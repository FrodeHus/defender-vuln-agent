"""Installation-path evidence from DeviceTvmSoftwareEvidenceBeta, generalized across devices.

Defender records, per device and software, the disk and registry paths that prove the product is
installed. Paths differ per device (user profiles, custom drives, versioned folders), so they are
generalized before grouping: profile and program folders become placeholders, the drive letter is
dropped, version-like and GUID/SID segments are collapsed. The product-specific tail survives, so
identical installations on many devices fold into one line with a device count.
"""
from __future__ import annotations

import re
from collections import defaultdict

from dva.model import product_key

_WIN_PREFIXES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\", re.I), r"%LOCALAPPDATA%\\"),
    (re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\roaming\\", re.I), r"%APPDATA%\\"),
    (re.compile(r"^[a-z]:\\users\\[^\\]+\\", re.I), r"%USERPROFILE%\\"),
    (re.compile(r"^[a-z]:\\program files \(x86\)\\", re.I), r"%ProgramFiles(x86)%\\"),
    (re.compile(r"^[a-z]:\\program files\\", re.I), r"%ProgramFiles%\\"),
    (re.compile(r"^[a-z]:\\programdata\\", re.I), r"%ProgramData%\\"),
    (re.compile(r"^[a-z]:\\windows\\", re.I), r"%WINDIR%\\"),
    (re.compile(r"^[a-z]:\\", re.I), r"<drive>:\\"),
]
_POSIX_PREFIXES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^/(?:home|Users)/[^/]+/"), "~/"),
]
_REGISTRY: list[tuple[re.Pattern, str]] = [
    (re.compile(r"HKEY_USERS\\S-1-5-21-[\d-]+", re.I), r"HKEY_USERS\\<sid>"),
    (re.compile(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", re.I), "{<guid>}"),
]
_VERSION_SEG = re.compile(r"^(?:v|jre|jdk|version)?\d+(?:[._-]\d+){1,}[a-z0-9_-]*$", re.I)


def generalize(path: str) -> str:
    p = path.strip()
    if not p:
        return p
    if p.upper().startswith("HKEY_"):
        for rx, repl in _REGISTRY:
            p = rx.sub(repl, p)
        return p
    for rx, repl in _WIN_PREFIXES:
        if rx.search(p):
            p = rx.sub(repl, p, count=1)
            break
    else:
        for rx, repl in _POSIX_PREFIXES:
            if rx.search(p):
                p = rx.sub(repl, p, count=1)
                break
    sep = "\\" if "\\" in p else "/"
    parts = p.split(sep)
    parts = [("<version>" if i > 0 and _VERSION_SEG.match(seg) else seg) for i, seg in enumerate(parts)]
    return sep.join(parts)


def _kql_list(values) -> str:
    return ", ".join('"' + v.replace('"', '\\"') + '"' for v in sorted(set(values)))


def build_query(pairs: list[tuple[str, str]], top: int = 5000) -> str:
    """KQL for the disk and registry evidence of the given (vendor, name) pairs, one row per path."""
    vendors = _kql_list(v for v, _ in pairs if v)
    names = _kql_list(n for _, n in pairs if n)
    return (
        "DeviceTvmSoftwareEvidenceBeta\n"
        f"| where SoftwareVendor in~ ({vendors}) and SoftwareName in~ ({names})\n"
        "| project DeviceId, SoftwareVendor, SoftwareName, DiskPaths, RegistryPaths\n"
        "| mv-expand Disk = DiskPaths to typeof(string), Registry = RegistryPaths to typeof(string)\n"
        "| extend Path = coalesce(Disk, Registry), Kind = iff(isnotempty(Disk), \"disk\", \"registry\")\n"
        "| where isnotempty(Path)\n"
        "| summarize Devices = dcount(DeviceId) by SoftwareVendor, SoftwareName, Kind, Path\n"
        "| order by Devices desc\n"
        f"| take {top}"
    )


def summarize(rows: list[dict], limit: int = 10) -> dict[str, list[dict]]:
    """Group evidence rows by product key and generalized path: {key: [{path, kind, devices}, ...]}."""
    acc: dict[str, dict[tuple[str, str], int]] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        path = r.get("Path") or ""
        if not path:
            continue
        key = product_key(r.get("SoftwareVendor"), r.get("SoftwareName"))
        kind = (r.get("Kind") or ("registry" if path.upper().startswith("HKEY_") else "disk")).lower()
        acc[key][(kind, generalize(path))] += int(r.get("Devices") or 1)
    out: dict[str, list[dict]] = {}
    for key, paths in acc.items():
        ordered = sorted(paths.items(), key=lambda kv: (kv[0][0] != "disk", -kv[1], kv[0][1]))
        out[key] = [{"path": p, "kind": k, "devices": n} for (k, p), n in ordered[:limit]]
    return out


def listed_pairs(run, cfg) -> list[tuple[str, str]]:
    """(vendor, name) of the products the report will list, by preliminary score, for scoping the query."""
    from dva.rollup import build
    from dva.scoring import product_score
    products, assets = build(run)
    ranked = sorted(products.values(), key=lambda p: (-product_score(p, assets, {}, cfg, len(assets)).score, p.key))
    return [(p.vendor, p.name) for p in ranked[: cfg.top_n + 15] if p.vendor != "defender-for-cloud"]
