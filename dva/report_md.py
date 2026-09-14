from __future__ import annotations

METHOD = ("Each product's score (0 to 100) combines threat signals for its CVEs (CVSS, EPSS, CISA KEV listing, known ransomware use, "
          "public exploit availability and exploit maturity), the context of the affected assets (internet exposure, Defender exposure "
          "level, device value, criticality tags, privileged-user sign-ins, cloud attack-path membership and applied mitigations) and "
          "the number of affected devices. A product with at least one CVE past its SLA deadline gets its score multiplied up (the SLA "
          "overdue multiplier in scoring.yaml). Findings are grouped by software product so one row maps to one patch action; only the "
          "three CVEs contributing most to a product's score and its most critical assets are shown. Weights live in scoring.yaml.")


def _flags(r: dict) -> str:
    f = r["flags"]
    bits = [x for x, on in [("KEV", f["kev"]), ("exploit", f["exploit"]), ("internet-facing", f["internet_facing"])] if on]
    sla = r.get("sla") or {}
    if sla.get("overdue_cves"):
        bits.append(f"Overdue by {sla['overdue_by_days']} days")
    if r.get("eos"):
        bits.append("End of support")
    return ", ".join(bits) or "-"


def _row(r: dict) -> str:
    c = r["counts"]
    return f"| {r['rank']} | {r['product']} | {r['vendor']} | {r['score']} {r['label']} | {r['assets']['count']} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {_flags(r)} |"


def _advisories(advisories: list[dict]) -> list[str]:
    out = []
    for adv in advisories:
        id_ = adv.get("id") or "advisory"
        bits = adv.get("source") or "-"
        if adv.get("label"):
            bits += f", {adv['label']}"
        if adv.get("date"):
            bits += f" ({adv['date']})"
        if adv.get("url"):
            out.append(f"- [{id_}]({adv['url']}) — {bits}")
        else:
            out.append(f"- {id_} — {bits}")
    return out


def _fmt_severity_counts(d: dict) -> str:
    return ", ".join(f"{d.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "unknown") if d.get(s, 0))


def _score_trend_line(doc: dict) -> str | None:
    st = doc.get("score_trend") or []
    exp = [r["exposure_score"] for r in st if r.get("exposure_score") is not None]
    sec = [r["secure_score"] for r in st if r.get("secure_score") is not None]
    if not exp and not sec:
        return None
    parts = []
    if exp:
        parts.append(f"exposure score {min(exp)}/{max(exp)}/{exp[-1]} (min/max/now)")
    if sec:
        parts.append(f"secure score {min(sec)}/{max(sec)}/{sec[-1]} (min/max/now)")
    return "Score trend (12 months): " + "; ".join(parts) + "."


def _trend_section(doc: dict) -> list[str]:
    trend = doc.get("trend") or []
    if len(trend) < 2:
        return []
    out = ["", "## Trend", "",
           "| Run | Generated | Exposure score | Products needing action | KEV CVEs | SLA breaches | Critical | High | Medium | Low |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for t in trend:
        c = t.get("cves_by_severity") or {}
        exposure = t.get("exposure_score")
        out.append(f"| {t.get('run_id')} | {t.get('generated_at')} | {exposure if exposure is not None else '-'} | "
                    f"{t.get('products_action')} | {t.get('kev_cves')} | {t.get('sla_breaches')} | "
                    f"{c.get('critical', 0)} | {c.get('high', 0)} | {c.get('medium', 0)} | {c.get('low', 0)} |")
    d = doc.get("diff_from_previous") or {}
    nc, fc = d.get("new_cves") or {}, d.get("fixed_cves") or {}
    bits = []
    if any(nc.values()):
        bits.append(f"New: {_fmt_severity_counts(nc)}")
    if any(fc.values()):
        bits.append(f"Fixed: {_fmt_severity_counts(fc)}")
    if bits:
        out += ["", " · ".join(bits) + " since the previous run."]
    score_line = _score_trend_line(doc)
    if score_line:
        out += ["", score_line]
    return out


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
    out += _trend_section(doc)
    out += ["", "## Top 10 products to patch", "", "| # | Product | Vendor | Score | Devices | Crit | High | Med | Low | Flags |", "|---|---|---|---|---|---|---|---|---|---|"]
    out += [_row(r) for r in top]
    for r in top:
        total_cves = sum(r["counts"].values())
        out += ["", f"### {r['rank']}. {r['product']} ({r['vendor']}) — {r['score']} {r['label']}", "", f"Why: {r['reason']}", "", f"Risk: {r.get('risk_summary', '')}", "", f"Remediation: {r['remediation']}"]
        advisories = r.get("advisories") or []
        if advisories:
            out += ["", "Vendor advisories:"] + _advisories(advisories)
        fixes = r.get("fixes") or []
        if fixes:
            top_fix = fixes[0]
            out += ["", f"Upgrading to {top_fix['update']} fixes {top_fix['cves']} of {total_cves} CVEs."]
        patched = r.get("patched_7d")
        if patched and (patched.get("critical") or patched.get("high")):
            out += ["", f"Patched in the last 7 days: {patched.get('critical', 0)} critical, {patched.get('high', 0)} high."]
        out += ["",
                f"Driving vulnerabilities ({total_cves} open CVEs in total" + (", partial intel" if r.get("partial_intel") else "") + "):"]
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
    ar = doc.get("accepted_risks") or {}
    active, expired = ar.get("active") or [], ar.get("expired") or []
    if active or expired:
        out += ["", "## Accepted risks", ""]
        if active:
            out += ["| Product | Vendor | Reason | Until | Owner | Would-be score |", "|---|---|---|---|---|---|"]
            out += [f"| {a['product']} | {a['vendor']} | {a['reason']} | {a['until']} | {a.get('owner') or '-'} | {a['would_be_score']} |" for a in active]
        if expired:
            if active:
                out.append("")
            out.append("Expired (back in the ranking; flagged `Exception expired`):")
            out += [f"- {e['product']} (until {e['until']}, owner {e.get('owner') or '-'}): {e['reason']}" for e in expired]
    posture = doc.get("posture") or {}
    certs, findings, by_impact = posture.get("certificates_expiring") or [], posture.get("config_findings") or [], posture.get("config_by_impact") or {}
    if certs or findings:
        out += ["", "## Posture", ""]
        if certs:
            out += ["### Certificates expiring within 30 days", "", "| Thumbprint | Name | Issued to | Expires | Devices |", "|---|---|---|---|---|"]
            out += [f"| {c.get('thumbprint') or '-'} | {c.get('name') or '-'} | {c.get('issued_to') or '-'} | {c.get('expires') or '-'} | {c.get('devices', 0)} |" for c in certs]
        if findings:
            if certs:
                out.append("")
            out += ["### Non-compliant configurations", "",
                    f"By impact: {by_impact.get('high', 0)} high, {by_impact.get('medium', 0)} medium, {by_impact.get('low', 0)} low", "",
                    "| Configuration | Category | Subcategory | Impact | Devices |", "|---|---|---|---|---|"]
            out += [f"| {f.get('id') or '-'} | {f.get('category') or '-'} | {f.get('subcategory') or '-'} | {f.get('impact', '-')} | {f.get('devices', 0)} |" for f in findings]
    out += ["", "## Method", "", METHOD, "", "## Sources", ""]
    for name, st in sorted(doc["run"].get("sources", {}).items()):
        out.append(f"- {name}: {st.get('status')}" + (f" ({st.get('count')} records)" if st.get("count") is not None else "") + (f" — {st.get('error')}" if st.get("error") else ""))
    return "\n".join(out) + "\n"
