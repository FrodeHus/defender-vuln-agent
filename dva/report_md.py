from __future__ import annotations

METHOD = ("Each product's score (0 to 100) combines threat signals for its CVEs (CVSS, EPSS, CISA KEV listing, public exploit "
          "availability), the context of the affected assets (internet exposure, Defender exposure level, device value, criticality "
          "tags) and the number of affected devices. Findings are grouped by software product so one row maps to one patch action; "
          "only the three CVEs contributing most to a product's score and its most critical assets are shown. Weights live in scoring.yaml.")


def _flags(r: dict) -> str:
    f = r["flags"]; return ", ".join(x for x, on in [("KEV", f["kev"]), ("exploit", f["exploit"]), ("internet-facing", f["internet_facing"])] if on) or "-"


def _row(r: dict) -> str:
    c = r["counts"]
    return f"| {r['rank']} | {r['product']} | {r['vendor']} | {r['score']} {r['label']} | {r['assets']['count']} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {_flags(r)} |"


def render(doc: dict) -> str:
    s, d, rows = doc["summary"], doc["diff_from_previous"], doc["products"]
    top, rest = rows[:10], rows[10:]
    out = [f"# Vulnerability assessment — {s.get('tenant', 'tenant')}", "",
           f"Run {doc['run'].get('run_id')} · generated {s.get('generated_at')} · previous run {d.get('previous_run_id') or 'none'}", "",
           "## Executive summary", ""]
    emergencies = [r for r in top if r["flags"]["kev"] and r["flags"]["internet_facing"]]
    out.append(f"{s['products_action']} of {s['products_total']} software products across {s['devices']} devices need action. "
               f"{len(emergencies)} of the top 10 carry KEV-listed CVEs on internet-facing hosts and should be treated as emergency changes. "
               f"{s['kev_cves']} KEV-listed CVEs are present; {s['internet_facing_at_risk']} internet-facing devices have at least one critical CVE."
               + (f" Exposure score is {s['exposure_score']}." if s.get("exposure_score") is not None else ""))
    if d.get("previous_run_id"):
        by_key = {r["key"]: r["product"] for r in rows}
        entered = ", ".join(by_key.get(k, k) for k in d["entered_top10"]) or "none"
        out += ["", f"Since run {d['previous_run_id']}: entered the top 10: {entered}; left the top 10: {', '.join(d['left_top10']) or 'none'}; "
                    f"newly KEV-listed products: {', '.join(by_key.get(k, k) for k in d['new_kev']) or 'none'}."
                    + (f" Exposure score moved from {s['previous_exposure_score']} to {s['exposure_score']}." if s.get("previous_exposure_score") is not None and s.get("exposure_score") is not None else "")]
    out += ["", "## Top 10 products to patch", "", "| # | Product | Vendor | Score | Devices | Crit | High | Med | Low | Flags |", "|---|---|---|---|---|---|---|---|---|---|"]
    out += [_row(r) for r in top]
    for r in top:
        out += ["", f"### {r['rank']}. {r['product']} ({r['vendor']}) — {r['score']} {r['label']}", "", f"Why: {r['reason']}", "", f"Risk: {r.get('risk_summary', '')}", "", f"Remediation: {r['remediation']}", "",
                f"Driving vulnerabilities ({sum(r['counts'].values())} open CVEs in total" + (", partial intel" if r.get("partial_intel") else "") + "):"]
        for c in r["driving_cves"]:
            bits = [c["id"], f"CVSS {c['cvss']}"] + ([f"EPSS {c['epss']}"] if c.get("epss") is not None else []) + (["KEV"] if c["kev"] else []) + (["Exploit"] if c["poc"] else []) + ([c["title"]] if c.get("title") else [])
            out.append("- " + " · ".join(str(b) for b in bits))
        a = r["assets"]
        out += ["", f"Affected assets ({a['count']}): {a['breakdown']}"] + [f"- {x['name']} — {x['why']}" for x in a["top"]]
        more = a["count"] - len(a["top"])
        if more > 0:
            out.append(f"+ {more} more in findings.json")
        paths = r.get("paths") or []
        if paths:
            out += ["", f"<details><summary>Installation paths ({len(paths)})</summary>", ""]
            out += [f"- `{x['path']}` — {x['devices']} device{'s' if x['devices'] != 1 else ''}" + (" (registry)" if x.get("kind") == "registry" else "") for x in paths]
            out += ["", "</details>"]
    if rest:
        out += ["", "## All prioritized products", "", "| # | Product | Vendor | Score | Devices | Crit | High | Med | Low | Flags |", "|---|---|---|---|---|---|---|---|---|---|"] + [_row(r) for r in rest]
    out += ["", "## Method", "", METHOD, "", "## Sources", ""]
    for name, st in sorted(doc["run"].get("sources", {}).items()):
        out.append(f"- {name}: {st.get('status')}" + (f" ({st.get('count')} records)" if st.get("count") is not None else "") + (f" — {st.get('error')}" if st.get("error") else ""))
    return "\n".join(out) + "\n"
