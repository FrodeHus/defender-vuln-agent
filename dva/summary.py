"""Plain-language risk summary per product, built from the CVE that drives its score."""
from __future__ import annotations

import re

_IMPACTS: list[tuple[str, str, str]] = [
    # (regex over description, what an attacker could do, the risk noun used in the closing sentence)
    (r"remote code execution|execute arbitrary code|arbitrary code execution|run arbitrary code|command injection|deserializ", "run their own code on the affected device and take control of it", "full compromise"),
    (r"authentication bypass|bypass(es|ing)? authentication|unauthenticated access|without authentication", "get in without valid credentials", "unauthorized access"),
    (r"privilege escalation|elevation of privilege|elevate privileges|escalate privileges|gain (?:system|root|administrator)", "turn a foothold into administrator-level control", "privilege escalation"),
    (r"sql injection", "read or change the application's database", "data theft or tampering"),
    (r"cross-site scripting|\bxss\b", "run scripts in users' browsers", "account or session hijacking"),
    (r"path traversal|directory traversal|arbitrary file (?:read|write)", "read or write files outside the application's directory", "file exposure or tampering"),
    (r"information disclosure|read (?:arbitrary )?memory|memory contents|leak|exposure of sensitive|disclose", "read data they are not supposed to see", "data exposure"),
    (r"denial of service|\bdos\b|crash|unavailable|resource exhaustion", "crash the service or make it unavailable", "service outage"),
    (r"use[- ]after[- ]free|buffer overflow|out[- ]of[- ]bounds|heap overflow|type confusion|integer overflow|memory corruption", "corrupt memory and most likely run their own code on the device", "full compromise"),
]


def _impact(description: str | None, vector: str | None) -> tuple[str, str]:
    text = (description or "").lower()
    for pattern, what, noun in _IMPACTS:
        if re.search(pattern, text):
            return what, noun
    v = vector or ""
    if "C:H" in v and "I:H" in v:
        return "fully compromise the affected device", "full compromise"
    if "C:H" in v:
        return "read sensitive data from the affected device", "data exposure"
    if "I:H" in v:
        return "tamper with data or configuration on the affected device", "tampering"
    if "A:H" in v:
        return "make the affected service unavailable", "service outage"
    return "exploit the flaw against the affected device", "compromise"


def _exposure(vector: str | None) -> str:
    v = vector or ""
    bits = []
    if "AV:N" in v:
        bits.append("over the network")
    elif "AV:A" in v:
        bits.append("from the same network segment")
    elif "AV:L" in v:
        bits.append("with local access to the device")
    elif "AV:P" in v:
        bits.append("with physical access")
    if "PR:N" in v:
        bits.append("without any credentials")
    if "UI:R" in v:
        bits.append("if a user opens a crafted file or link")
    return " ".join(bits)


def _first_sentence(description: str | None, limit: int = 220) -> str | None:
    if not description:
        return None
    text = re.sub(r"\s+", " ", description).strip()
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    s = m.group(1) if m else text
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s


def risk_summary(product: str, cve: dict, description: str | None, vector: str | None,
                 device_count: int, internet_facing: int, critical_tags: int, high_value: int) -> str:
    """cve: {id, severity, cvss, epss, kev, poc}. Returns 2 to 4 plain-language sentences."""
    what, noun = _impact(description, vector)
    how = _exposure(vector)
    sev = (cve.get("severity") or "").lower()
    head = f"The most critical issue is {cve['id']}" + (f" ({sev}, CVSS {cve['cvss']})" if cve.get("cvss") is not None else "")
    signals = []
    if cve.get("kev"):
        signals.append("it is in CISA's Known Exploited Vulnerabilities catalog, so it is being used in real attacks")
    if cve.get("poc"):
        signals.append("public exploit code is available")
    if cve.get("epss") is not None and cve["epss"] >= 0.1:
        signals.append(f"EPSS puts the chance of exploitation in the next 30 days at {round(cve['epss'] * 100)}%")
    if signals:
        head += ": " + "; ".join(signals)
    head += "."
    desc = _first_sentence(description)
    parts = [head]
    if desc:
        parts.append(desc)
    parts.append(f"An attacker could {what}" + (f" {how}" if how else "") + ".")
    scope = f"{device_count} device{'s' if device_count != 1 else ''} run{'s' if device_count == 1 else ''} {product}"
    extras = []
    if internet_facing:
        extras.append(f"{internet_facing} of them internet-facing")
    if critical_tags:
        extras.append(f"{critical_tags} tagged as critical")
    if high_value:
        extras.append(f"{high_value} marked high value")
    if extras:
        scope += ", " + " and ".join(extras)
    parts.append(f"{scope}; leaving it unpatched risks {noun}" + (" on systems reachable from the internet." if internet_facing else "."))
    return " ".join(parts)
