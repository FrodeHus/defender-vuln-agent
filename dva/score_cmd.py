from __future__ import annotations
import os
from datetime import datetime, timezone
from dva.cache import IntelCache
from dva.config import Scoring, load_scoring
from dva.errors import DvaError
from dva.rollup import build, display_name, display_vendor
from dva.run import Run, add_run_arg, resolve_run, cache_dir
from dva.scoring import product_score, reason_for


def _breakdown(assets, cfg: Scoring) -> str:
    parts = []
    inet = sum(1 for a in assets if a.internet_facing)
    if inet: parts.append(f"{inet} internet-facing")
    for tag in cfg.criticality_tags:
        n = sum(1 for a in assets if any(t.lower() == tag.lower() for t in a.tags))
        if n: parts.append(f"{n} {tag}")
    hv = sum(1 for a in assets if (a.device_value or "").lower() == "high")
    if hv: parts.append(f"{hv} High value")
    return " · ".join(parts) if parts else "No exposure signals"


def compute(run: Run, cfg: Scoring, cache: IntelCache) -> dict:
    products, assets = build(run)
    estate = len(assets) if run.path("machines.json").exists() else sum(1 for a in assets.values() if a.kind == "device")
    all_ids = {cid for p in products.values() for cid in p.cves}
    intel = cache.all_fresh(all_ids)
    scored = sorted((product_score(p, assets, intel, cfg, estate) for p in products.values()), key=lambda s: (-s.score, s.product.name))
    rows = []
    # Always list at least the top_n products so a small or clean estate still gets a ranked view;
    # report_threshold decides how many of them count as "needing action".
    listed = [s for s in scored if s.score >= cfg.report_threshold]
    if len(listed) < cfg.top_n:
        listed = scored[: cfg.top_n]
    action_count = sum(1 for s in scored if s.score >= cfg.report_threshold)
    for i, sp in enumerate(listed):
        p = sp.product
        pa = [assets.get(a) for a in p.asset_ids if a in assets]
        rows.append({
            "rank": i + 1, "key": p.key, "vendor": display_vendor(p), "product": display_name(p), "score": sp.score, "label": sp.label,
            "counts": sp.counts, "flags": sp.flags, "reason": reason_for(sp),
            "remediation": p.remediation or (f"Update to {p.recommended_version}" if p.recommended_version else "Update to a fixed version; see vendor advisory."),
            "remediation_type": p.remediation_type, "recommended_version": p.recommended_version, "versions": p.versions,
            "driving_cves": [{"id": r.id, "severity": r.severity, "cvss": (intel[r.id].cvss if r.id in intel and intel[r.id].cvss is not None else r.cvss),
                              "epss": intel[r.id].epss if r.id in intel else None, "kev": bool(r.id in intel and intel[r.id].kev),
                              "poc": bool((r.id in intel and intel[r.id].exploit_public) or r.exploitability != "NoExploit"),
                              "title": intel[r.id].title if r.id in intel else None} for r, _ in sp.driving],
            "assets": {"count": len(p.asset_ids), "breakdown": _breakdown(pa, cfg), "top": [{"name": a.name, "why": why} for a, _, why in sp.top_assets]},
            "all_cves": sorted(p.cves), "all_assets": sorted(a.name for a in pa),
            "partial_intel": any(r.id not in intel for r, _ in sp.driving),
        })
    exposure = run.read_json("exposure.json") if run.path("exposure.json").exists() else {}
    prev = Run.latest(run.dir.parent, before=run.id)
    prev_doc = None
    if prev and prev.path("findings.json").exists():
        try:
            prev_doc = prev.read_json("findings.json")
        except DvaError as exc:
            run.log(f"ignoring previous run {prev.id}: {exc}")
            prev = None
    top_now = [r["key"] for r in rows[: cfg.top_n]]
    top_prev = [r["key"] for r in (prev_doc or {}).get("products", [])[: cfg.top_n]]
    kev_prev = {r["key"] for r in (prev_doc or {}).get("products", []) if r.get("flags", {}).get("kev")}
    kev_ids = {cid for cid, it in intel.items() if it.kev and cid in all_ids}
    inet_risk = {a.id for p in products.values() for a in (assets.get(x) for x in p.asset_ids) if a and a.internet_facing and any(r.severity == "Critical" for r in p.cves.values())}
    return {
        "run": run.manifest,
        "summary": {"devices": estate, "products_total": len(products), "products_action": action_count, "kev_cves": len(kev_ids),
                    "internet_facing_at_risk": len(inet_risk), "exposure_score": exposure.get("score"),
                    "previous_exposure_score": (prev_doc or {}).get("summary", {}).get("exposure_score"),
                    "generated_at": datetime.now(timezone.utc).isoformat(), "tenant": os.environ.get("DVA_TENANT_NAME", os.environ.get("DVA_TENANT_ID", "unknown"))},
        "products": rows,
        "diff_from_previous": {"previous_run_id": prev.id if prev_doc else None,
                               "entered_top10": [k for k in top_now if k not in top_prev], "left_top10": [k for k in top_prev if k not in top_now],
                               "new_kev": [r["key"] for r in rows if r["flags"]["kev"] and r["key"] not in kev_prev]},
    }


def register(sub) -> None:
    p = sub.add_parser("score", help="Roll up, score and write findings.json"); add_run_arg(p); p.set_defaults(func=_run)


def _run(args) -> int:
    run, cfg = resolve_run(args), load_scoring()
    doc = compute(run, cfg, IntelCache(cache_dir() / "cve", cfg.cache_ttl_days))
    run.write_json("findings.json", doc)
    top = ", ".join(f"{r['product']} ({r['score']})" for r in doc["products"][:3])
    run.summary(f"Scored {doc['summary']['products_total']} products; {doc['summary']['products_action']} need action; top: {top}.")
    return 0
