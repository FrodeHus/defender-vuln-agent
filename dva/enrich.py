from __future__ import annotations
import os
import re
import json
import shlex
from dataclasses import asdict
from pathlib import Path
from dva.cache import IntelCache
from dva.config import Scoring, load_scoring
from dva.errors import DvaError
from dva.mcp_client import McpStdioClient
from dva.model import Asset, Product, EXPLOIT_RANK
from dva.rollup import build
from dva.run import Run, add_run_arg, resolve_run, cache_dir
from dva.scoring import CveIntel, product_score

CHUNK = 20


def _rank_key(r):
    # highest cvss, then strongest exploitability, then newest first_seen (ISO strings sort lexically)
    return (
        -r.cvss,
        -EXPLOIT_RANK.get(r.exploitability, 0),
        "" if r.first_seen is None else "".join(chr(0x10FFFF - ord(ch)) for ch in r.first_seen),
        r.id,
    )


def select_candidates(products: dict[str, Product], assets: dict[str, Asset], cache: IntelCache, cfg: Scoring, estate_size: int) -> list[str]:
    prelim = [(product_score(p, assets, {}, cfg, estate_size).score, p) for p in products.values()]
    prelim.sort(key=lambda x: (-x[0], x[1].key))
    out: list[str] = []
    seen: set[str] = set()
    for score, p in prelim:
        if score < cfg.enrich_threshold:
            break
        for r in sorted(p.cves.values(), key=_rank_key)[: cfg.enrich_top_per_product]:
            if r.id in seen or cache.get(r.id) is not None:
                continue
            seen.add(r.id)
            out.append(r.id)
            if len(out) >= cfg.enrich_max_cves:
                return out
    return out


def select_describe(products: dict[str, Product], assets: dict[str, Asset], cache: IntelCache, cfg: Scoring, estate_size: int, limit: int | None = None) -> list[str]:
    """The CVEs that drive each product that will be listed (its top enrich_top_per_product by CVSS, exploitability and
    recency), for lookup_cve descriptions and vendor advisories; skips ids already described."""
    prelim = sorted(products.values(), key=lambda p: (-product_score(p, assets, {}, cfg, estate_size).score, p.key))
    per_product = max(cfg.enrich_top_per_product, 1)
    window = max(cfg.top_n, 0) + 15
    limit = limit if limit is not None else window * per_product
    out: list[str] = []
    for p in prelim[:window]:
        for ref in sorted(p.cves.values(), key=_rank_key)[:per_product]:
            cached = cache.get(ref.id, stale_ok=True)  # descriptions never change: an expired entry that has one still counts
            if (cached is not None and cached.description) or ref.id in out:
                continue
            out.append(ref.id)
            if len(out) >= limit:
                return out
    return out


def _first(d: dict, *paths):
    for path in paths:
        cur = d
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                cur = None
                break
            cur = cur[part]
        if cur is not None:
            return cur
    return None


def _as_float(v) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _one(cve_id: str, d: dict) -> CveIntel:
    exploits = _first(d, "exploits") or []
    sources = _first(d, "exploit_sources") or [e.get("source") or e.get("name") for e in exploits if isinstance(e, dict)]
    desc = _first(d, "title") or (_first(d, "description") or "")[:120] or None
    return CveIntel(
        cvss=_as_float(_first(d, "cvss_v3_score", "cvss_score", "cvss.base_score", "cvss")),
        epss=_as_float(_first(d, "epss_score", "epss.score")),
        epss_percentile=_as_float(_first(d, "epss_percentile", "epss.percentile")),
        kev=bool(_first(d, "in_kev", "kev.in_kev", "cisa_kev", "kev")),
        kev_added=_first(d, "kev.date_added", "date_added"),
        ransomware=bool(_first(d, "kev.known_ransomware_use", "known_ransomware_use")),
        exploit_public=bool(_first(d, "exploit_available", "has_exploit", "poc_available") or exploits),
        exploit_sources=[s for s in sources if s],
        title=desc,
        cwe=_first(d, "cwe", "cwe_id"),
    )


def parse_store(payload: dict | list) -> dict[str, CveIntel]:
    if not isinstance(payload, (dict, list)):
        raise DvaError("unrecognized CVE server result shape")
    entries = payload
    if isinstance(payload, dict):
        entries = payload.get("results") or payload.get("cves") or payload.get("data") or payload
    out: dict[str, CveIntel] = {}
    if isinstance(entries, dict):
        for k, v in entries.items():
            if k.upper().startswith("CVE-") and isinstance(v, dict):
                out[k.upper()] = _one(k.upper(), v)
        if not out and (payload.get("cve_id") or payload.get("id")):
            cid = (payload.get("cve_id") or payload.get("id")).upper()
            out[cid] = _one(cid, payload)
        return out
    for e in entries or []:
        if isinstance(e, dict):
            cid = (e.get("cve_id") or e.get("id") or e.get("cve") or "").upper()
            if cid.startswith("CVE-"):
                out[cid] = _one(cid, e)
    return out


_CVE = r"(CVE-\d{4}-\d{4,})"
_RE_TRIAGE = re.compile(r"=== CVE Triage: " + _CVE + r" ===")
_RE_LOOKUP = re.compile(r"^=== " + _CVE + r" ===\s*$", re.M)
_RE_COMPARE_ROW = re.compile(r"^\s*\d+\s+" + _CVE + r"\s+([\d.]+)\s+(\w+)\s+(Yes|No)\s+([\d.]+)", re.M | re.I)
_RE_EPSS_LINE = re.compile(_CVE + r"\s+([\d.]+)%.*?Percentile:\s*([\d.]+)th", re.I)
_RE_KEV_SENTENCE = re.compile(_CVE + r" is (NOT )?in the CISA KEV", re.I)
_RE_POC_HEADER = re.compile(r"PoC Intelligence:\s*" + _CVE)
_RE_EXPLOIT_AVAIL = re.compile(r"=== Exploit Availability: " + _CVE + r" ===")
_RE_ADV_BLOCK = re.compile(r"^=== Vendor Advisories: " + _CVE + r" ===\s*\n(.*?)(?=^===|\Z)", re.M | re.S)
_RE_ADV_SECTION = re.compile(r"^(.+?)\s{2,}\(\d+ entr(?:y|ies)\):\s*$", re.M)
_RE_ADV_ENTRY = re.compile(r"^\s*\[([^\]]*)\]\s*(.*)$")
_RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_MATURITY_MAP = {
    "PUBLIC_EXPLOIT": 1.0,
    "WEAPONIZED": 1.0,
    "HIGH": 1.0,
    "MEDIUM": 0.85,
    "LOW": 0.7,
    "POC": 0.7,
    "NONE": 0.0,
}


def _maturity_from_label(label: str | None) -> float | None:
    if not label:
        return None
    return _MATURITY_MAP.get(label.upper())


def _advisory_url(source: str, cid: str, entry_id: str | None) -> str | None:
    s = source.strip().lower()
    if "red hat" in s:
        return f"https://access.redhat.com/errata/{entry_id}" if entry_id else None
    if "msrc" in s or "microsoft" in s:
        return f"https://msrc.microsoft.com/update-guide/vulnerability/{cid}"
    if "ubuntu" in s:
        return f"https://ubuntu.com/security/{cid}"
    return None


def _parse_advisories(cid: str, block: str, limit: int = 5) -> list[dict]:
    out: list[dict] = []
    sections = list(_RE_ADV_SECTION.finditer(block))
    for i, sm in enumerate(sections):
        source = sm.group(1).strip()
        start = sm.end()
        end = sections[i + 1].start() if i + 1 < len(sections) else len(block)
        for line in block[start:end].splitlines():
            if not line.strip():
                continue
            em = _RE_ADV_ENTRY.match(line)
            if not em:
                continue
            severity = em.group(1).strip()
            rest = em.group(2).strip()
            parts = re.split(r"\s{2,}", rest) if rest else []
            label = id_ = date = None
            if parts and _RE_DATE.match(parts[-1]):
                date = parts[-1]
                rest_parts = parts[:-1]
                if rest_parts:
                    id_ = rest_parts[-1]
                    if len(rest_parts) > 1:
                        label = " ".join(rest_parts[:-1])
            elif parts:
                label = " ".join(parts)
            out.append({
                "source": source,
                "severity": severity,
                "label": label,
                "id": id_,
                "date": date,
                "url": _advisory_url(source, cid, id_),
            })
            if len(out) >= limit:
                return out
    return out


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _merge_intel(cur: CveIntel | None, new: CveIntel) -> CveIntel:
    if cur is None:
        return new
    for f in ("cvss", "epss", "epss_percentile", "kev_added", "title", "cwe", "description", "vector"):
        if getattr(cur, f) is None and getattr(new, f) is not None:
            setattr(cur, f, getattr(new, f))
    cur.kev = cur.kev or new.kev
    cur.ransomware = cur.ransomware or new.ransomware
    cur.exploit_public = cur.exploit_public or new.exploit_public
    if new.exploit_maturity is not None:
        cur.exploit_maturity = new.exploit_maturity if cur.exploit_maturity is None else max(cur.exploit_maturity, new.exploit_maturity)
    for src in new.exploit_sources:
        if src not in cur.exploit_sources:
            cur.exploit_sources.append(src)
    for adv in new.advisories:
        aid = adv.get("id")
        if aid and any(a.get("id") == aid for a in cur.advisories):
            continue
        if not aid and adv in cur.advisories:
            continue
        cur.advisories.append(adv)
    return cur


STABLE_FIELDS = ("cvss", "vector", "description", "title", "cwe", "kev_added")


def _refresh_intel(stale: CveIntel | None, new: CveIntel) -> CveIntel:
    """Merge a freshly fetched result over an expired cache entry: the new EPSS/KEV/PoC signals win outright,
    while fields that never change (and were maybe fetched by a different tool) fill in when the new result lacks them."""
    if stale is None:
        return new
    for f in STABLE_FIELDS:
        if getattr(new, f) is None and getattr(stale, f) is not None:
            setattr(new, f, getattr(stale, f))
    if not new.advisories and stale.advisories:
        new.advisories = list(stale.advisories)
    return new


def _parse_triage_block(cid: str, block: str) -> CveIntel:
    intel = CveIntel()
    m = re.search(r"^\s*CVSS:\s+([\d.]+)", block, re.M)
    intel.cvss = _f(m.group(1)) if m else None
    mv = re.search(r"^\s*Vector:\s+(CVSS:\S+)", block, re.M)
    intel.vector = mv.group(1) if mv else None
    m = re.search(r"^\s*EPSS:\s+([\d.]+)%\s*\(percentile\s+([\d.]+)th", block, re.M)
    if m:
        intel.epss = _f(m.group(1)) / 100.0 if _f(m.group(1)) is not None else None
        intel.epss_percentile = _f(m.group(2)) / 100.0 if _f(m.group(2)) is not None else None
    m = re.search(r"^\s*KEV:\s+(YES|NO)(.*)$", block, re.M | re.I)
    if m:
        intel.kev = m.group(1).upper() == "YES"
        rest = m.group(2)
        da = re.search(r"added\s+(\d{4}-\d{2}-\d{2})", rest)
        if da:
            intel.kev_added = da.group(1)
        if re.search(r"ransomware:\s*Known", rest, re.I):
            intel.ransomware = True
    m = re.search(r"^\s*PoC:\s+(\w+)(?:.*?—\s*(\d+)\s+public source)?", block, re.M)
    if m:
        label = m.group(1)
        n = int(m.group(2)) if m.group(2) else 0
        intel.exploit_public = label.upper() != "NONE" or n > 0
        if intel.exploit_public:
            intel.exploit_sources.append("poc")
        maturity = _maturity_from_label(label)
        if n >= 5:
            maturity = max(maturity or 0.0, 0.85)
        intel.exploit_maturity = maturity
    return intel


def parse_text(text: str) -> dict[str, CveIntel]:
    """Parse the cve-mcp server's formatted text output (triage_cve, compare_cves, get_epss_score,
    lookup_cve, check_kev, check_poc_exists). Several tool outputs may be concatenated in one file."""
    out: dict[str, CveIntel] = {}

    def add(cid, intel):
        cid = cid.upper()
        out[cid] = _merge_intel(out.get(cid), intel)

    # triage_cve blocks
    parts = _RE_TRIAGE.split(text)
    for i in range(1, len(parts), 2):
        add(parts[i], _parse_triage_block(parts[i], parts[i + 1]))
    # lookup_cve blocks ("=== CVE-x ===" not preceded by "CVE Triage:")
    for m in _RE_LOOKUP.finditer(text):
        cid, block = m.group(1), text[m.end(): m.end() + 4000]
        intel = CveIntel()
        k = re.search(r"^CISA KEV:\s+(YES|NO)", block, re.M | re.I)
        intel.kev = bool(k and k.group(1).upper() == "YES")
        sc = re.search(r"^Score:\s+([\d.]+)", block, re.M)
        intel.cvss = _f(sc.group(1)) if sc else None
        cw = re.search(r"^Weaknesses:\s*(CWE-\d+)", block, re.M)
        intel.cwe = cw.group(1) if cw else None
        vv = re.search(r"^Vector:\s+(CVSS:\S+)", block, re.M)
        intel.vector = vv.group(1) if vv else None
        d = re.search(r"^Description:\s*\n(.+?)(?:\n\s*\n(?:[A-Z][A-Za-z ]+:|===)|\Z)", block, re.M | re.S)
        if d:
            full = re.sub(r"\s+", " ", d.group(1)).strip()
            intel.description = full[:600]
            intel.title = full[:120]
        add(cid, intel)
    # compare_cves table rows
    for m in _RE_COMPARE_ROW.finditer(text):
        intel = CveIntel(kev=m.group(4).lower() == "yes", epss=(_f(m.group(5)) or 0.0) / 100.0)
        add(m.group(1), intel)
    # get_epss_score lines
    for m in _RE_EPSS_LINE.finditer(text):
        add(m.group(1), CveIntel(epss=(_f(m.group(2)) or 0.0) / 100.0, epss_percentile=(_f(m.group(3)) or 0.0) / 100.0))
    # check_kev sentences
    for m in _RE_KEV_SENTENCE.finditer(text):
        block = text[m.end(): m.end() + 500]
        intel = CveIntel(kev=m.group(2) is None)
        da = re.search(r"Date Added:\s*(\d{4}-\d{2}-\d{2})", block)
        if da:
            intel.kev_added = da.group(1)
        if re.search(r"Ransomware Use:\s*Known", block, re.I):
            intel.ransomware = True
        add(m.group(1), intel)
    # check_poc_exists
    for m in _RE_POC_HEADER.finditer(text):
        block = text[m.end(): m.end() + 2000]
        c = re.search(r"Confidence:\s*(\w+)", block)
        has = bool(c and c.group(1).upper() != "NONE")
        intel = CveIntel(exploit_public=has, exploit_sources=["poc"] if has else [])
        if c:
            intel.exploit_maturity = _maturity_from_label(c.group(1))
        add(m.group(1), intel)
    # check_exploit_availability
    for m in _RE_EXPLOIT_AVAIL.finditer(text):
        block = text[m.end(): m.end() + 500]
        n = re.search(r"Public PoCs found:\s*(\d+)", block)
        if n:
            count = int(n.group(1))
            intel = CveIntel(exploit_public=count > 0)
            if count > 0:
                intel.exploit_maturity = 0.7
            add(m.group(1), intel)
    # get_vendor_advisory blocks
    for m in _RE_ADV_BLOCK.finditer(text):
        cid, block = m.group(1), m.group(2)
        add(cid, CveIntel(advisories=_parse_advisories(cid, block)))
    return out


def parse_file(path: Path) -> dict[str, CveIntel]:
    """Parse a stored CVE-server result: JSON (legacy/tool-agnostic) or the server's formatted text."""
    raw = path.read_text(encoding="utf-8")
    stripped = raw.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return parse_store(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise DvaError(f"store file is not valid JSON: {path}: {exc}")
    parsed = parse_text(raw)
    if not parsed:
        raise DvaError(f"no CVE data recognized in {path}; expected cve-mcp tool output (triage_cve, compare_cves, get_epss_score, lookup_cve, check_kev, check_poc_exists) or JSON")
    return parsed


def write_enrichment(run: Run, cache: IntelCache, ids: list[str]) -> dict:
    fresh = cache.all_fresh(ids)
    doc = {"cves": {k: asdict(v) for k, v in fresh.items()}, "missing": sorted(set(ids) - set(fresh))}
    run.write_json("enrichment.json", doc)
    return doc


def default_server_command() -> list[str]:
    """The CVE server to talk to: $DVA_CVE_MCP (a shell-style command line), else this checkout's scripts/cve-mcp.sh
    (under $DVA_HOME when the plugin was installed elsewhere)."""
    override = os.environ.get("DVA_CVE_MCP")
    if override:
        return shlex.split(override)
    home = Path(os.environ.get("DVA_HOME") or Path(__file__).resolve().parent.parent)
    return [str(home / "scripts" / "cve-mcp.sh")]


def register(sub) -> None:
    p = sub.add_parser("enrich", help="Select CVEs for enrichment and fetch or store CVE server results")
    add_run_arg(p)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="print the CVE ids to look up (for calling the server by hand)")
    g.add_argument("--fetch", action="store_true", help="select the CVE ids, call the CVE server for each and store the results")
    g.add_argument("--store", nargs="+", metavar="FILE", help="one or more saved cve-mcp tool outputs (text or JSON)")
    p.add_argument("--server", metavar="CMD", help="CVE server command line for --fetch (default: $DVA_CVE_MCP or scripts/cve-mcp.sh)")
    p.set_defaults(func=_run)


def _select(run: Run, cache: IntelCache, cfg: Scoring, products, assets, estate: int) -> tuple[list[str], list[str]]:
    ids = select_candidates(products, assets, cache, cfg, estate)
    run.write_json("enrich-candidates.json", ids)
    describe = select_describe(products, assets, cache, cfg, estate)
    run.write_json("enrich-describe.json", describe)
    return ids, describe


def _store(run: Run, cache: IntelCache, files: list[Path]) -> None:
    parsed: dict[str, CveIntel] = {}
    for path in files:
        if not path.exists():
            raise DvaError(f"store file not found: {path}")
        for cid, intel in parse_file(path).items():
            parsed[cid] = _merge_intel(parsed.get(cid), intel)
    for cid, intel in parsed.items():
        fresh = cache.get(cid)
        cache.put(cid, _merge_intel(fresh, intel) if fresh is not None else _refresh_intel(cache.get(cid, stale_ok=True), intel))
    wanted = run.read_json("enrich-candidates.json") if run.path("enrich-candidates.json").exists() else list(parsed)
    doc = write_enrichment(run, cache, wanted)
    print(f"stored {len(parsed)}, missing {len(doc['missing'])}")
    run.summary(f"Enrichment stored: {len(parsed)} CVEs; enrichment.json now has {len(doc['cves'])} CVEs, {len(doc['missing'])} still missing.")


def fetch(run: Run, ids: list[str], describe: list[str], server: list[str]) -> tuple[list[Path], int]:
    """Call the CVE server for every selected id, saving each text result under the run directory exactly as the
    agent used to (cve-triage-<id>.txt, cve-lookup-<id>.txt, cve-advisory-<id>.txt). A failed call is a warning."""
    calls = [("triage_cve", cid, {"cve_id": cid, "depth": "standard"}, "triage") for cid in ids]
    for cid in describe:
        calls.append(("lookup_cve", cid, {"cve_id": cid}, "lookup"))
        calls.append(("get_vendor_advisory", cid, {"cve_id": cid}, "advisory"))
    files: list[Path] = []
    failed = 0
    if not calls:
        return files, failed
    with McpStdioClient(server) as client:
        for tool, cid, args, kind in calls:
            try:
                text = client.call_tool(tool, args)
            except DvaError as e:
                failed += 1; print(f"warning: {tool} {cid}: {e}")
                continue
            path = run.path(f"cve-{kind}-{cid}.txt")
            path.write_text(text, encoding="utf-8")
            files.append(path)
    return files, failed


def _run(args) -> int:
    run, cfg = resolve_run(args), load_scoring()
    cache = IntelCache(cache_dir() / "cve", cfg.cache_ttl_days)
    products, assets = build(run)
    estate = len(run.read_json("machines.json")) if run.path("machines.json").exists() else len(assets)
    if args.list:
        ids, describe = _select(run, cache, cfg, products, assets, estate)
        for n in range(0, len(ids), CHUNK):
            print(json.dumps({"chunk": n // CHUNK + 1, "cve_ids": ids[n:n + CHUNK]}))
        if describe:
            print(json.dumps({"describe": describe}))
        run.summary(f"Enrichment candidates: {len(ids)} CVEs in {(len(ids) + CHUNK - 1) // CHUNK} chunks (cached ones excluded); {len(describe)} CVEs need a description for the risk summaries.")
        return 0
    if args.fetch:
        ids, describe = _select(run, cache, cfg, products, assets, estate)
        server = shlex.split(args.server) if args.server else default_server_command()
        files, failed = fetch(run, ids, describe, server)
        print(f"fetched {len(files)} results, {failed} failed")
        run.summary(f"Enrichment fetched: {len(ids)} CVEs triaged and {len(describe)} described through the CVE server; {failed} call(s) failed.")
        if files:
            _store(run, cache, files)
        else:
            doc = write_enrichment(run, cache, ids)
            print(f"stored 0, missing {len(doc['missing'])}")
        return 0
    _store(run, cache, [Path(raw) for raw in args.store])
    return 0
