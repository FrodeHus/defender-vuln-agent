"""The few lines the agent needs for its reply, so it never reads report.md (about 3.5K tokens) into its context."""
from __future__ import annotations

import re


def _names(rows: list[dict], keys: list[str]) -> str:
    by_key = {r["key"]: r["product"] for r in rows}
    return ", ".join(by_key.get(k, k) for k in keys) or "none"


def _first_sentence(text: str) -> str:
    """The head of the risk summary: the driving CVE with its threat signals, up to the first sentence end."""
    m = re.match(r"(.+?[.!?])(\s|$)", text.strip())
    return m.group(1) if m else text.strip()


def render(doc: dict, suggestions: list[dict] | None, run_dir: str) -> str:
    s, d, rows = doc["summary"], doc.get("diff_from_previous") or {}, doc["products"]
    out = [f"Tenant: {s.get('tenant', 'tenant')} · run {doc['run'].get('run_id')} · {run_dir}", "Top products:"]
    for r in rows[:3]:
        out.append(f"  {r['rank']}. {r['product']} ({r['vendor']}) {r['score']} {r['label']} — {r['reason']}")
        if r.get("risk_summary"):
            out.append(f"     Risk: {_first_sentence(r['risk_summary'])}")
    out.append(f"Needing action: {s['products_action']} of {s['products_total']} products across {s['devices']} devices; "
               f"{s['kev_cves']} KEV-listed CVEs; {s['internet_facing_at_risk']} internet-facing devices with a critical CVE")
    breaches = [r for r in rows if (r.get("sla") or {}).get("overdue_cves")]
    out.append(f"SLA breaches: {s.get('sla_breaches', 0)} product(s)" + (": " + ", ".join(f"{r['product']} (overdue by {r['sla']['overdue_by_days']} days)" for r in breaches) if breaches else ""))
    eos = [r["product"] for r in rows if r.get("eos")]
    out.append(f"End of support: {s.get('eos_products', 0)} product(s)" + (": " + ", ".join(eos) if eos else ""))
    stale = doc.get("long_standing") or []
    if stale:
        out.append(f"Long-standing (>{s.get('long_standing_days', 90)} days): {len(stale)} product(s): "
                   + ", ".join(f"{r['product']} ({r['cves_over_threshold']} CVEs, oldest {r['oldest_days']} days)" for r in stale[:5])
                   + (f", +{len(stale) - 5} more" if len(stale) > 5 else ""))
    out.append(f"Patched in the last 7 days: {s.get('patched_7d_critical', 0)} critical CVEs")
    if s.get("exposure_score") is not None:
        out.append(f"Exposure score: {s['exposure_score']}"
                   + (f" (previous {s['previous_exposure_score']})" if s.get("previous_exposure_score") is not None else "")
                   + (f"; secure score {s['secure_score']}" if s.get("secure_score") is not None else ""))
    if d.get("previous_run_id"):
        out.append(f"Since run {d['previous_run_id']}: entered top 10: {_names(rows, d.get('entered_top10') or [])}; "
                   f"left: {_names(rows, d.get('left_top10') or [])}; newly KEV-listed: {_names(rows, d.get('new_kev') or [])}")
    bad = [(name, st) for name, st in sorted((doc["run"].get("sources") or {}).items()) if st.get("status") != "ok"]
    if bad:
        out.append("Sources not ok: " + "; ".join(f"{name} {st.get('status')}" + (f" ({st['error']})" if st.get("error") else f" ({st['count']} records)" if st.get("count") is not None else "") for name, st in bad))
    else:
        out.append("Sources: all ok")
    ar = doc.get("accepted_risks") or {}
    out.append(f"Accepted risks: {len(ar.get('active') or [])} active, {len(ar.get('expired') or [])} expired")
    if suggestions is None:
        out.append("Exception suggestions: none (run dva exception suggest first)")
    elif not suggestions:
        out.append("Exception suggestions: none")
    else:
        out.append(f"Exception suggestions: {len(suggestions)} — " + "; ".join(
            f"{x.get('product') or x.get('cve')}: {', '.join(x.get('reasons') or [])} (until {x.get('suggested_until')})" for x in suggestions))
    return "\n".join(out) + "\n"
