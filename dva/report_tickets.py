"""Ticket export: one ticket per listed product, ready to hand to a ticketing system.

Excepted products never appear in doc["products"] (compute() already drops them), so nothing
extra needs filtering here.
"""
from __future__ import annotations
import json

_PRIORITY = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}


def _description(r: dict) -> str:
    lines = [r.get("risk_summary") or "", "", f"**Remediation:** {r.get('remediation') or ''}"]
    fixes = r.get("fixes") or []
    if fixes:
        top_fix = fixes[0]
        total = sum((r.get("counts") or {}).values())
        lines += ["", f"Upgrading to {top_fix['update']} fixes {top_fix['cves']} of {total} CVEs."]
    driving = r.get("driving_cves") or []
    if driving:
        lines += ["", "**Driving CVEs:**"]
        for c in driving:
            bits = [c["id"], f"CVSS {c['cvss']}"]
            if c.get("epss") is not None:
                bits.append(f"EPSS {c['epss']}")
            if c.get("kev"):
                bits.append("KEV")
            if c.get("poc"):
                bits.append("Exploit")
            if c.get("title"):
                bits.append(c["title"])
            lines.append("- " + " · ".join(str(b) for b in bits))
    top_assets = (r.get("assets") or {}).get("top") or []
    if top_assets:
        lines += ["", "**Top assets:**"]
        lines += [f"- {x['name']} — {x['why']}" for x in top_assets]
    paths = r.get("paths") or []
    if paths:
        lines += ["", "**Paths:**"]
        lines += [f"- `{x['path']}` — {x['devices']} devices" for x in paths]
    return "\n".join(lines)


def _ticket(doc: dict, r: dict) -> dict:
    label = r.get("label") or "Low"
    flags = r.get("flags") or {}
    labels = ["vuln", label.lower()]
    if flags.get("kev"):
        labels.append("kev")
    if flags.get("internet_facing"):
        labels.append("internet-facing")
    n = (r.get("assets") or {}).get("count", 0)
    return {
        "key": r["key"],
        "title": f"Patch {r['product']} ({r['vendor']}): {label}, {n} devices",
        "priority": _PRIORITY.get(label, 4),
        "labels": labels,
        "description": _description(r),
        "product": r["product"],
        "tenant": (doc.get("summary") or {}).get("tenant"),
        "run_id": (doc.get("run") or {}).get("run_id"),
    }


def render(doc: dict) -> str:
    tickets = [_ticket(doc, r) for r in doc.get("products") or []]
    return json.dumps(tickets, indent=2, sort_keys=True)
