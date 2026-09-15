"""CISA Known Exploited Vulnerabilities catalogue, matched against every CVE in the estate.

The catalogue is one public JSON file (about 1,400 entries, no key needed). Fetching it sends nothing
about the tenant; it is cached per tenant at ``<DVA_CACHE_DIR>/kev.json`` and refreshed by
``dva enrich --fetch`` (or ``dva kev``) when older than ``TTL_HOURS``. ``apply`` folds it into the
intel dict scoring uses, so KEV and ransomware flags cover all CVEs, not only the triaged ones.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dva.errors import DvaError
from dva.scoring import CveIntel

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TTL_HOURS = 24


def cache_path() -> Path:
    from dva.run import cache_dir
    return cache_dir() / "kev.json"


def parse(doc: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for v in doc.get("vulnerabilities") or []:
        cid = (v.get("cveID") or "").upper()
        if cid:
            out[cid] = {"date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                        "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                        "name": v.get("vulnerabilityName")}
    return out


def _enabled() -> bool:
    from dva.config import load_sources
    try:
        return bool(load_sources().kev)
    except Exception:
        return True


def refresh(fixture: Path | None = None, url: str | None = None) -> dict[str, dict]:
    """Download the catalogue (or read ``fixture``), write the cache, return the parsed entries."""
    source = os.environ.get("DVA_KEV_URL")
    if fixture is None and source and not source.startswith(("http://", "https://")):
        fixture = Path(source)  # a local copy of the catalogue (tests, air-gapped mirrors)
    if fixture is not None:
        try:
            doc = json.loads(Path(fixture).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DvaError(f"cannot read KEV fixture {fixture}: {exc}")
    else:
        import requests
        try:
            r = requests.get(url or source or KEV_URL, timeout=60)
            r.raise_for_status()
            doc = r.json()
        except (requests.RequestException, ValueError) as exc:
            raise DvaError(f"cannot download the CISA KEV catalogue: {exc}")
    cat = parse(doc)
    if not cat:
        raise DvaError("KEV catalogue is empty or not in CISA's format")
    p = cache_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    p.write_text(json.dumps({"fetched_at": datetime.now(timezone.utc).isoformat(), "released": doc.get("dateReleased"), "entries": cat}))
    return cat


def _read() -> dict | None:
    p = cache_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load() -> dict[str, dict]:
    """The cached catalogue, any age; empty when none is cached or ``sources.yaml`` has ``kev: false``."""
    if not _enabled():
        return {}
    doc = _read()
    return (doc or {}).get("entries") or {}


def age_hours() -> float | None:
    doc = _read()
    if not doc or not doc.get("fetched_at"):
        return None
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(doc["fetched_at"])).total_seconds() / 3600
    except ValueError:
        return None


def released() -> str | None:
    doc = _read()
    return (doc or {}).get("released")


def ensure_fresh() -> None:
    """Refresh when enabled and the cache is missing or older than ``TTL_HOURS``; a failed download keeps
    whatever is cached and prints a warning, so an offline run still scores."""
    if not _enabled():
        return
    age = age_hours()
    if age is not None and age < TTL_HOURS:
        return
    try:
        refresh()
    except DvaError as exc:
        print(f"warning: {exc}; " + ("using the cached catalogue" if age is not None else "KEV flags will be missing"))


def apply(intel: dict[str, CveIntel], catalog: dict[str, dict], ids) -> int:
    """Mark every id in ``ids`` that the catalogue lists, creating an intel entry when triage never ran."""
    n = 0
    for cid in ids:
        entry = catalog.get(cid.upper())
        if not entry:
            continue
        it = intel.get(cid)
        if it is None:
            it = intel[cid] = CveIntel()
        it.kev = True
        it.kev_added = it.kev_added or entry.get("date_added")
        it.ransomware = it.ransomware or bool(entry.get("ransomware"))
        n += 1
    return n


def register(sub) -> None:
    from dva.run import add_run_arg
    p = sub.add_parser("kev", help="Download (or load from --fixture) the CISA KEV catalogue and cache it for scoring")
    p.add_argument("--fixture", help="a saved copy of the catalogue JSON instead of downloading it")
    add_run_arg(p)
    p.set_defaults(func=_run)


def _run(args) -> int:
    from dva.run import Run, resolve_run
    cat = refresh(fixture=Path(args.fixture) if args.fixture else None)
    line = f"KEV catalogue: {len(cat)} entries (released {(released() or '?')[:10]})"
    try:
        run = resolve_run(args)
    except DvaError:
        print(line)
        return 0
    ids = {v["cve_id"].upper() for v in run.read_jsonl("vulns.jsonl")} if run.path("vulns.jsonl").exists() else set()
    hits = sum(1 for cid in ids if cid in cat)
    run.set_source("kev", "ok", count=hits)
    run.summary(f"{line}; {hits} CVE{'s' if hits != 1 else ''} in this estate {'are' if hits != 1 else 'is'} listed.")
    return 0
