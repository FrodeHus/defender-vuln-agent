from __future__ import annotations
import os
from datetime import date, datetime, timedelta, timezone
from dva.cache import IntelCache
from dva.config import Scoring, load_scoring
from dva import exceptions as exceptions_mod
from dva.errors import DvaError
from dva.model import product_key
from dva.rollup import build, display_name, display_vendor
from dva.run import Run, add_run_arg, resolve_run, cache_dir
from dva.scoring import product_score, reason_for


def _risk(sp, intel, pa, cfg: Scoring, product_name: str) -> str:
    from dva.summary import risk_summary
    if not sp.driving:
        return f"No open CVEs are recorded for {product_name}."
    r = sp.driving[0][0]
    it = intel.get(r.id)
    cve = {"id": r.id, "severity": r.severity, "cvss": (it.cvss if it and it.cvss is not None else r.cvss),
           "epss": it.epss if it else None, "kev": bool(it and it.kev), "poc": bool((it and it.exploit_public) or r.exploitability != "NoExploit")}
    return risk_summary(product_name, cve, it.description if it else None, it.vector if it else None, len(sp.product.asset_ids),
                        sum(1 for a in pa if a.internet_facing),
                        sum(1 for a in pa if any(t.lower() == pat.lower() for t in a.tags for pat in cfg.criticality_tags)),
                        sum(1 for a in pa if (a.device_value or "").lower() == "high"))


def age_days(first_seen: str | None, now: datetime) -> int | None:
    if not first_seen:
        return None
    s = first_seen.strip()
    dt = None
    try:
        dt = datetime.fromisoformat(s.replace(" ", "T"))
    except ValueError:
        try:
            dt = datetime.fromisoformat(s[:10])
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


def _sla(p, cfg: Scoring, now: datetime) -> dict:
    ages = []
    overdue_cves = 0
    overdue_by_days = 0
    for ref in p.cves.values():
        age = age_days(ref.first_seen, now)
        if age is None:
            continue
        ages.append(age)
        threshold = cfg.sla_days.get(ref.severity.lower())
        if threshold is not None and age > threshold:
            overdue_cves += 1
            overdue_by_days = max(overdue_by_days, age - threshold)
    return {"oldest_days": max(ages) if ages else None, "overdue_cves": overdue_cves, "overdue_by_days": overdue_by_days}


def _fixes(p, total: int) -> list[dict]:
    ranked = sorted(p.fixes.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return [{"update": u, "cves": len(ids), "share": round(len(ids) / total, 2) if total else 0.0} for u, ids in ranked[:5]]


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


def previous_runs(run: Run, n: int) -> list[Run]:
    """Up to `n` previous runs in the same runs dir (ids < run.id) that have a readable findings.json,
    newest first. Corrupt manifests/findings are skipped with a log line rather than aborting the search."""
    runs_dir = run.dir.parent
    if not runs_dir.exists() or n <= 0:
        return []
    candidates = sorted(p.name for p in runs_dir.iterdir() if p.is_dir() and (p / "manifest.json").exists())
    candidates = [rid for rid in candidates if rid < run.id]
    result: list[Run] = []
    for rid in reversed(candidates):
        if len(result) >= n:
            break
        d = runs_dir / rid
        if not (d / "findings.json").exists():
            continue
        try:
            r = Run(d)
            r.read_json("findings.json")
        except DvaError as exc:
            run.log(f"ignoring previous run {rid}: {exc}")
            continue
        result.append(r)
    return result


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _all_previous_runs(run: Run) -> list[Run]:
    """Every previous run (ids < run.id) in the same runs dir with a readable findings.json, newest
    first, unlike `previous_runs` which is capped by count. Corrupt manifests/findings are skipped."""
    runs_dir = run.dir.parent
    if not runs_dir.exists():
        return []
    candidates = sorted(p.name for p in runs_dir.iterdir() if p.is_dir() and (p / "manifest.json").exists())
    candidates = [rid for rid in candidates if rid < run.id]
    result: list[Run] = []
    for rid in reversed(candidates):
        d = runs_dir / rid
        if not (d / "findings.json").exists():
            continue
        try:
            r = Run(d)
            r.read_json("findings.json")
        except DvaError as exc:
            run.log(f"ignoring previous run {rid} for score trend: {exc}")
            continue
        result.append(r)
    return result


def score_trend(run: Run, current_row: dict, store=None, days: int = 365, now: datetime | None = None) -> list[dict]:
    """[{run_id, generated_at, exposure_score, secure_score}] over the last `days` days, oldest first,
    including the current run. Uses the store's recorded runs when it has any history, else scans
    previous runs' findings.json files by summary.generated_at."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    def in_window(generated_at):
        dt = _parse_iso(generated_at)
        return dt is not None and dt >= cutoff

    if store is not None:
        prev = [r for r in store.recent_runs(100000) if r["run_id"] != run.id]
        if prev:
            rows = [{"run_id": r["run_id"], "generated_at": r.get("generated_at"),
                     "exposure_score": r.get("exposure_score"), "secure_score": r.get("secure_score")}
                    for r in prev if in_window(r.get("generated_at"))]
            rows.append(current_row)
            return rows
    rows = []
    for r in reversed(_all_previous_runs(run)):
        try:
            doc_p = r.read_json("findings.json")
        except DvaError as exc:
            run.log(f"ignoring previous run {r.id} for score trend: {exc}")
            continue
        s = doc_p.get("summary", {})
        if not in_window(s.get("generated_at")):
            continue
        rows.append({"run_id": r.id, "generated_at": s.get("generated_at"),
                     "exposure_score": s.get("exposure_score"), "secure_score": s.get("secure_score")})
    rows.append(current_row)
    return rows


def _patched_7d(run: Run) -> dict[str, dict]:
    """Per-product recently-patched CVE counts from vuln-changes.jsonl: {key: {critical, high, cves}}."""
    if not run.path("vuln-changes.jsonl").exists():
        return {}
    out: dict[str, dict] = {}
    for row in run.read_jsonl("vuln-changes.jsonl"):
        if row.get("status") != "Fixed":
            continue
        key = product_key(row.get("vendor"), row.get("product"))
        d = out.setdefault(key, {"critical": 0, "high": 0, "cves": []})
        sev = (row.get("severity") or "").lower()
        if sev == "critical":
            d["critical"] += 1
            if row.get("cve_id") and len(d["cves"]) < 5:
                d["cves"].append(row["cve_id"])
        elif sev == "high":
            d["high"] += 1
    return out


def _cve_counts_by_severity(rows: list[dict]) -> dict[str, int]:
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        c = r.get("counts") or {}
        for k in totals:
            totals[k] += c.get(k, 0)
    return totals


def _trend_from_store(store, run: Run, cfg: Scoring, current_row: dict) -> list[dict] | None:
    """Trend rows built from the store's recorded runs, oldest first, or None when the store
    has no rows yet (caller should fall back to the file scan)."""
    prev = [r for r in store.recent_runs(cfg.trend_runs) if r["run_id"] != run.id]
    if not prev:
        return None
    rows = [{
        "run_id": r["run_id"], "generated_at": r.get("generated_at"), "exposure_score": r.get("exposure_score"),
        "products_action": r.get("products_action"), "kev_cves": r.get("kev_cves"), "sla_breaches": r.get("sla_breaches"),
        "cves_by_severity": r.get("cves_by_severity") or {"critical": 0, "high": 0, "medium": 0, "low": 0},
    } for r in prev[-cfg.trend_runs:]]
    rows.append(current_row)
    return rows


def _trend(run: Run, prevs: list[Run], current_row: dict) -> list[dict]:
    rows = []
    for r in reversed(prevs):  # oldest first
        try:
            doc_p = r.read_json("findings.json")
        except DvaError as exc:
            run.log(f"ignoring previous run {r.id}: {exc}")
            continue
        s = doc_p.get("summary", {})
        rows.append({
            "run_id": r.id, "generated_at": s.get("generated_at"), "exposure_score": s.get("exposure_score"),
            "products_action": s.get("products_action"), "kev_cves": s.get("kev_cves"), "sla_breaches": s.get("sla_breaches"),
            "cves_by_severity": _cve_counts_by_severity(doc_p.get("products", [])),
        })
    rows.append(current_row)
    return rows


def _new_and_fixed_cves(rows: list[dict], products: dict, prev_doc: dict | None) -> tuple[dict[str, int], dict[str, int]]:
    current_pairs = {(r["key"], cve) for r in rows for cve in r.get("all_cves", [])}
    prev_products = (prev_doc or {}).get("products", [])
    previous_pairs = {(pr["key"], cve) for pr in prev_products for cve in pr.get("all_cves", [])}
    prev_severity: dict[tuple[str, str], str] = {}
    for pr in prev_products:
        for dc in pr.get("driving_cves") or []:
            prev_severity[(pr["key"], dc["id"])] = dc.get("severity")

    def _bucket(pairs, sev_lookup) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for key, cve in pairs:
            sev = (sev_lookup(key, cve) or "unknown").lower()
            if sev not in out:
                sev = "unknown"
            out[sev] += 1
        return out

    def _current_sev(key, cve) -> str | None:
        p = products.get(key)
        ref = p.cves.get(cve) if p else None
        return ref.severity if ref else None

    def _prev_sev(key, cve) -> str | None:
        return prev_severity.get((key, cve))

    new_pairs = current_pairs - previous_pairs
    fixed_pairs = previous_pairs - current_pairs
    return _bucket(new_pairs, _current_sev), _bucket(fixed_pairs, _prev_sev)


def _posture(run: Run) -> dict:
    cert_rows = run.read_json("hunt-certificates.json").get("results", []) if run.path("hunt-certificates.json").exists() else []
    cfg_rows = run.read_json("hunt-config-findings.json").get("results", []) if run.path("hunt-config-findings.json").exists() else []
    certificates_expiring = [{
        "thumbprint": r.get("Thumbprint"), "name": r.get("FriendlyName"), "issued_to": r.get("IssuedTo"),
        "expires": r.get("Exp"), "devices": r.get("Devices"),
    } for r in cert_rows]
    config_findings = []
    config_by_impact = {"high": 0, "medium": 0, "low": 0}
    for r in cfg_rows:
        try:
            impact_n = float(r.get("ConfigurationImpact"))
        except (TypeError, ValueError):
            impact_n = 0.0
        bucket = "high" if impact_n >= 7 else "medium" if impact_n >= 4 else "low"
        config_by_impact[bucket] += 1
        config_findings.append({
            "id": r.get("ConfigurationId"), "category": r.get("ConfigurationCategory"),
            "subcategory": r.get("ConfigurationSubcategory"), "impact": r.get("ConfigurationImpact"), "devices": r.get("Devices"),
        })
    return {"certificates_expiring": certificates_expiring, "config_findings": config_findings, "config_by_impact": config_by_impact}


def compute(run: Run, cfg: Scoring, cache: IntelCache, tenant_name: str | None = None, now: datetime | None = None, store=None) -> dict:
    now = now or datetime.now(timezone.utc)
    products, assets = build(run)
    from dva.evidence import summarize as _summarize_paths
    ev = run.read_json("hunt-evidence.json").get("results", []) if run.path("hunt-evidence.json").exists() else []
    paths_by_key = _summarize_paths(ev)
    estate = len(assets) if run.path("machines.json").exists() else sum(1 for a in assets.values() if a.kind == "device")
    all_ids = {cid for p in products.values() for cid in p.cves}
    intel = cache.all_fresh(all_ids)
    exc_items = exceptions_mod.load(exceptions_mod.path_for_current())
    active_exceptions, expired_exceptions = exceptions_mod.split(exc_items, date.today())
    listed_products, dropped_exceptions = exceptions_mod.apply(products, active_exceptions)
    sla_by_key = {key: _sla(p, cfg, now) for key, p in listed_products.items()}
    scored = sorted((product_score(p, assets, intel, cfg, estate, overdue=sla_by_key[p.key]["overdue_cves"] > 0) for p in listed_products.values()), key=lambda s: (-s.score, s.product.name))
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
        top = sp.driving[0][0] if sp.driving else None
        rows.append({
            "rank": i + 1, "key": p.key, "vendor": display_vendor(p), "product": display_name(p), "score": sp.score, "label": sp.label,
            "counts": sp.counts, "flags": sp.flags, "reason": reason_for(sp),
            "remediation": p.remediation or (f"Update to {p.recommended_version}" if p.recommended_version else "Update to a fixed version; see vendor advisory."),
            "remediation_type": p.remediation_type, "recommended_version": p.recommended_version, "versions": p.versions,
            "sla": sla_by_key[p.key], "eos": p.eos, "fixes": _fixes(p, len(p.cves)),
            "driving_cves": [{"id": r.id, "severity": r.severity, "cvss": (intel[r.id].cvss if r.id in intel and intel[r.id].cvss is not None else r.cvss),
                              "epss": intel[r.id].epss if r.id in intel else None, "kev": bool(r.id in intel and intel[r.id].kev),
                              "poc": bool((r.id in intel and intel[r.id].exploit_public) or r.exploitability != "NoExploit"),
                              "title": intel[r.id].title if r.id in intel else None} for r, _ in sp.driving],
            "assets": {"count": len(p.asset_ids), "breakdown": _breakdown(pa, cfg), "top": [{"name": a.name, "why": why} for a, _, why in sp.top_assets]},
            "advisories": intel[top.id].advisories[:5] if top is not None and top.id in intel else [],
            "risk_summary": _risk(sp, intel, pa, cfg, display_name(p)),
            "paths": paths_by_key.get(p.key, []),
            "all_cves": sorted(p.cves), "all_assets": sorted(a.name for a in pa),
            "partial_intel": any(r.id not in intel for r, _ in sp.driving),
        })
    patched_by_key = _patched_7d(run)
    for row in rows:
        row["patched_7d"] = patched_by_key.get(row["key"])
    patched_7d_critical = sum(v["critical"] for v in patched_by_key.values())
    expired_product_keys = {i.product for i in expired_exceptions if i.product}
    expired_cve_ids = {i.cve for i in expired_exceptions if i.cve}
    for row in rows:
        row["flags"]["exception_expired"] = row["key"] in expired_product_keys or bool(expired_cve_ids & set(row["all_cves"]))
    accepted_active = []
    for key, item in dropped_exceptions.items():
        p = products[key]
        sp = product_score(p, assets, intel, cfg, estate)
        accepted_active.append({
            "key": key, "product": display_name(p), "vendor": display_vendor(p),
            "reason": item.reason, "until": item.until, "owner": item.owner, "would_be_score": sp.score,
        })
    accepted_active.sort(key=lambda x: x["key"])
    accepted_expired = []
    for item in expired_exceptions:
        if item.product:
            key = item.product
            p = products.get(key)
            name = display_name(p) if p else key
        else:
            key = item.cve
            name = next((display_name(p2) for p2 in products.values() if item.cve in p2.cves), key)
        accepted_expired.append({"key": key, "product": name, "reason": item.reason, "until": item.until, "owner": item.owner})
    accepted_expired.sort(key=lambda x: x["key"])
    exposure = run.read_json("exposure.json") if run.path("exposure.json").exists() else {}
    prevs = previous_runs(run, cfg.trend_runs)
    prev = prevs[0] if prevs else None
    prev_doc = prev.read_json("findings.json") if prev else None
    top_now = [r["key"] for r in rows[: cfg.top_n]]
    top_prev = [r["key"] for r in (prev_doc or {}).get("products", [])[: cfg.top_n]]
    kev_prev = {r["key"] for r in (prev_doc or {}).get("products", []) if r.get("flags", {}).get("kev")}
    kev_ids = {cid for cid, it in intel.items() if it.kev and cid in all_ids}
    inet_risk = {a.id for p in products.values() for a in (assets.get(x) for x in p.asset_ids) if a and a.internet_facing and any(r.severity == "Critical" for r in p.cves.values())}
    generated_at = datetime.now(timezone.utc).isoformat()
    exposure_score = round(exposure["score"], 2) if isinstance(exposure.get("score"), (int, float)) else None
    secure_score = round(exposure["secure_score"], 2) if isinstance(exposure.get("secure_score"), (int, float)) else None
    sla_breaches = sum(1 for v in sla_by_key.values() if v["overdue_cves"] > 0)
    current_trend_row = {
        "run_id": run.id, "generated_at": generated_at, "exposure_score": exposure_score,
        "products_action": action_count, "kev_cves": len(kev_ids), "sla_breaches": sla_breaches,
        "cves_by_severity": _cve_counts_by_severity(rows),
    }
    current_score_row = {"run_id": run.id, "generated_at": generated_at, "exposure_score": exposure_score, "secure_score": secure_score}
    new_cves, fixed_cves = _new_and_fixed_cves(rows, products, prev_doc)
    return {
        "run": run.manifest,
        "summary": {"devices": estate, "products_total": len(products), "products_action": action_count, "kev_cves": len(kev_ids),
                    "internet_facing_at_risk": len(inet_risk),
                    "sla_breaches": sla_breaches,
                    "overdue_cves_total": sum(v["overdue_cves"] for v in sla_by_key.values()),
                    "eos_products": sum(1 for p in listed_products.values() if p.eos is not None),
                    "exposure_score": exposure_score,
                    "secure_score": secure_score,
                    "patched_7d_critical": patched_7d_critical,
                    "previous_exposure_score": (prev_doc or {}).get("summary", {}).get("exposure_score"),
                    "generated_at": generated_at, "tenant": tenant_name or os.environ.get("DVA_TENANT_NAME") or os.environ.get("DVA_TENANT") or os.environ.get("DVA_TENANT_ID", "unknown")},
        "products": rows,
        "diff_from_previous": {"previous_run_id": prev.id if prev_doc else None,
                               "entered_top10": [k for k in top_now if k not in top_prev], "left_top10": [k for k in top_prev if k not in top_now],
                               "new_kev": [r["key"] for r in rows if r["flags"]["kev"] and r["key"] not in kev_prev],
                               "new_cves": new_cves, "fixed_cves": fixed_cves},
        "accepted_risks": {"active": accepted_active, "expired": accepted_expired},
        "posture": _posture(run),
        "trend": (store and _trend_from_store(store, run, cfg, current_trend_row)) or _trend(run, prevs, current_trend_row),
        "score_trend": score_trend(run, current_score_row, store=store, now=now),
    }


def register(sub) -> None:
    p = sub.add_parser("score", help="Roll up, score and write findings.json"); add_run_arg(p); p.set_defaults(func=_run)


def _run(args) -> int:
    run, cfg = resolve_run(args), load_scoring()
    from dva.tenantinfo import resolve_display_name
    from dva.hunting import GRAPH_BASE
    from dva.auth import GRAPH_SCOPE
    from dva.mde import make_client
    from dva.store import open_store
    tenant_name = resolve_display_name(cache_dir(), client_factory=lambda: make_client(GRAPH_SCOPE, GRAPH_BASE), log=run.log)
    store = open_store()
    doc = compute(run, cfg, IntelCache(cache_dir() / "cve", cfg.cache_ttl_days), tenant_name=tenant_name, store=store)
    run.write_json("findings.json", doc)
    run_summary = dict(doc["summary"])
    run_summary["cves_by_severity"] = doc["trend"][-1]["cves_by_severity"] if doc["trend"] else {}
    store.record_run(run.id, tenant_name, run_summary, doc["products"])
    top = ", ".join(f"{r['product']} ({r['score']})" for r in doc["products"][:3])
    run.summary(f"Scored {doc['summary']['products_total']} products; {doc['summary']['products_action']} need action; top: {top}.")
    return 0
