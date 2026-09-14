from __future__ import annotations
from dva.model import Asset, CveRef, Product, product_key, EXPLOIT_RANK
from dva.run import Run


def _hunt(run: Run, name: str) -> list[dict]:
    p = run.path(f"hunt-{name}.json")
    if not p.exists():
        return []
    return run.read_json(f"hunt-{name}.json").get("results", [])


def _split_tags(s) -> list[str]:
    return [t.strip() for t in (s or "").split(",") if t.strip()]


def build(run: Run) -> tuple[dict[str, Product], dict[str, Asset]]:
    assets: dict[str, Asset] = {}
    for m in run.read_json("machines.json"):
        assets[m["id"]] = Asset(
            id=m["id"], name=m.get("name") or m["id"],
            internet_facing=bool(m.get("is_internet_facing")),
            exposure_level=m.get("exposure_level"), device_value=m.get("device_value"),
            tags=list(m.get("tags") or []), group=m.get("group"),
        )
    for row in _hunt(run, "device-tags"):
        a = assets.setdefault(row["DeviceId"], Asset(id=row["DeviceId"], name=row.get("DeviceName") or row["DeviceId"]))
        a.exposure_level = a.exposure_level or row.get("ExposureLevel")
        a.device_value = a.device_value or row.get("AssetValue")
        for t in _split_tags(row.get("DeviceManualTags")) + _split_tags(row.get("DeviceDynamicTags")):
            if t not in a.tags:
                a.tags.append(t)
        if row.get("IsInternetFacing"):
            a.internet_facing = True
    for row in _hunt(run, "internet-facing"):
        a = assets.setdefault(row["DeviceId"], Asset(id=row["DeviceId"], name=row.get("DeviceName") or row["DeviceId"]))
        a.internet_facing = True

    exploited = {r["CveId"] for r in _hunt(run, "exploited-cves")}
    recs = {}
    if run.path("recommendations.json").exists():
        for r in run.read_json("recommendations.json"):
            recs[product_key(r.get("vendor"), r.get("product"))] = r

    version_devices: dict[str, dict[str, set[str]]] = {}
    products: dict[str, Product] = {}
    for v in run.read_jsonl("vulns.jsonl"):
        key = product_key(v.get("vendor"), v.get("product"))
        p = products.get(key)
        if p is None:
            rec = recs.get(key)
            p = products[key] = Product(
                key=key, vendor=v.get("vendor") or "unknown", name=v.get("product") or "unknown",
                remediation=rec.get("name") if rec else None,
                remediation_type=rec.get("remediation_type") if rec else None,
                recommended_version=rec.get("recommended_version") if rec else None,
            )
        p.asset_ids.add(v["device_id"])
        if v.get("version"):
            version_devices.setdefault(key, {}).setdefault(v["version"], set()).add(v["device_id"])
        expl = v.get("exploitability") or "NoExploit"
        if v["cve_id"] in exploited and EXPLOIT_RANK.get(expl, 0) < 1:
            expl = "ExploitIsPublic"
        cur = p.cves.get(v["cve_id"])
        ref = CveRef(id=v["cve_id"], severity=v.get("severity") or "Low", cvss=float(v.get("cvss") or 0.0),
                     exploitability=expl, first_seen=v.get("first_seen"))
        if cur is None or EXPLOIT_RANK[ref.exploitability] > EXPLOIT_RANK[cur.exploitability] or ref.cvss > cur.cvss:
            p.cves[v["cve_id"]] = ref
        if v["device_id"] not in assets:
            assets[v["device_id"]] = Asset(id=v["device_id"], name=v.get("device_name") or v["device_id"], group=v.get("group"))

    for key, versions in version_devices.items():
        products[key].versions = {ver: len(devices) for ver, devices in versions.items()}

    return products, assets


def display_name(p: Product) -> str:
    return " ".join(w.upper() if w.lower() in {"dc", "ems", "ssh", "sql", "vpn"} else w.capitalize() for w in p.name.replace("_", " ").split())


def display_vendor(p: Product) -> str:
    return p.vendor.replace("_", " ").title()
