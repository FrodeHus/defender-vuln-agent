from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path
from dva.cache import IntelCache
from dva.config import Scoring, load_scoring
from dva.errors import DvaError
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
        if score < cfg.report_threshold:
            break
        for r in sorted(p.cves.values(), key=_rank_key)[: cfg.enrich_top_per_product]:
            if r.id in seen or cache.get(r.id) is not None:
                continue
            seen.add(r.id)
            out.append(r.id)
            if len(out) >= cfg.enrich_max_cves:
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


def _one(cve_id: str, d: dict) -> CveIntel:
    exploits = _first(d, "exploits") or []
    sources = _first(d, "exploit_sources") or [e.get("source") or e.get("name") for e in exploits if isinstance(e, dict)]
    desc = _first(d, "title") or (_first(d, "description") or "")[:120] or None
    return CveIntel(
        cvss=_first(d, "cvss_v3_score", "cvss_score", "cvss.base_score", "cvss"),
        epss=_first(d, "epss_score", "epss.score"),
        epss_percentile=_first(d, "epss_percentile", "epss.percentile"),
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


def write_enrichment(run: Run, cache: IntelCache, ids: list[str]) -> dict:
    fresh = cache.all_fresh(ids)
    doc = {"cves": {k: asdict(v) for k, v in fresh.items()}, "missing": sorted(set(ids) - set(fresh))}
    run.write_json("enrichment.json", doc)
    return doc


def register(sub) -> None:
    p = sub.add_parser("enrich", help="Select CVEs for enrichment and store CVE server results")
    add_run_arg(p)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true")
    g.add_argument("--store")
    p.set_defaults(func=_run)


def _run(args) -> int:
    run, cfg = resolve_run(args), load_scoring()
    cache = IntelCache(cache_dir() / "cve", cfg.cache_ttl_days)
    products, assets = build(run)
    estate = len(run.read_json("machines.json")) if run.path("machines.json").exists() else len(assets)
    if args.list:
        ids = select_candidates(products, assets, cache, cfg, estate)
        run.write_json("enrich-candidates.json", ids)
        for n in range(0, len(ids), CHUNK):
            print(json.dumps({"chunk": n // CHUNK + 1, "cve_ids": ids[n:n + CHUNK]}))
        run.summary(f"Enrichment candidates: {len(ids)} CVEs in {(len(ids) + CHUNK - 1) // CHUNK} chunks (cached ones excluded).")
        return 0
    path = Path(args.store)
    if not path.exists():
        raise DvaError(f"store file not found: {path}")
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise DvaError(f"store file is not valid JSON: {path}: {exc}")
    parsed = parse_store(payload)
    for cid, intel in parsed.items():
        cache.put(cid, intel)
    wanted = run.read_json("enrich-candidates.json") if run.path("enrich-candidates.json").exists() else list(parsed)
    doc = write_enrichment(run, cache, wanted)
    print(f"stored {len(parsed)}, missing {len(doc['missing'])}")
    run.summary(f"Enrichment stored: {len(parsed)} CVEs; enrichment.json now has {len(doc['cves'])} CVEs, {len(doc['missing'])} still missing.")
    return 0
