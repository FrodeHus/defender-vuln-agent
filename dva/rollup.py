from __future__ import annotations
import json
from dva.model import Asset, CveRef, Product, product_key, EXPLOIT_RANK, SEVERITIES
from dva.run import Run

SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # Low=0 ... Critical=3
_EOS_IGNORE = {"", "None", "NotApplicable"}


def _hunt(run: Run, name: str) -> list[dict]:
    p = run.path(f"hunt-{name}.json")
    if not p.exists():
        return []
    return run.read_json(f"hunt-{name}.json").get("results", [])


def _split_tags(s) -> list[str]:
    if not s:
        return []
    if isinstance(s, str):
        try:
            parsed = json.loads(s)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return [t.strip() for t in parsed if isinstance(t, str) and t.strip()]
        return [t.strip() for t in s.split(",") if t.strip()]
    if isinstance(s, list):
        return [t.strip() for t in s if isinstance(t, str) and t.strip()]
    return []


def _norm_exploitability(e) -> str:
    return e if e in EXPLOIT_RANK else "NoExploit"


def _norm_cvss(c) -> float:
    try:
        return float(c)
    except (TypeError, ValueError):
        return 0.0


def _merge_cve_ref(cur: CveRef | None, new: CveRef) -> CveRef:
    if cur is None:
        return new
    exploitability = new.exploitability if EXPLOIT_RANK[new.exploitability] > EXPLOIT_RANK[cur.exploitability] else cur.exploitability
    cvss = max(new.cvss, cur.cvss)
    severity = new.severity if SEVERITY_RANK.get(new.severity, 0) > SEVERITY_RANK.get(cur.severity, 0) else cur.severity
    first_seens = [fs for fs in (new.first_seen, cur.first_seen) if fs]
    first_seen = min(first_seens) if first_seens else None
    return CveRef(id=cur.id, severity=severity, cvss=cvss, exploitability=exploitability, first_seen=first_seen)


def build(run: Run) -> tuple[dict[str, Product], dict[str, Asset]]:
    assets: dict[str, Asset] = {}
    azure_id_map: dict[str, str] = {}  # lower(azure_resource_id) -> asset id
    name_label_map: dict[str, str] = {}  # lower(first label of asset name) -> asset id
    machines = run.read_json("machines.json") if run.path("machines.json").exists() else []
    for m in machines:
        assets[m["id"]] = Asset(
            id=m["id"], name=m.get("name") or m["id"],
            internet_facing=bool(m.get("is_internet_facing")),
            exposure_level=m.get("exposure_level"), device_value=m.get("device_value"),
            tags=list(m.get("tags") or []), group=m.get("group"),
        )
        if m.get("azure_resource_id"):
            azure_id_map[m["azure_resource_id"].lower()] = m["id"]
        else:
            # hostname-label fallback only applies to MDE assets with no azure_resource_id to match against
            label = (m.get("name") or m["id"]).split(".")[0].strip().lower()
            if label:
                name_label_map.setdefault(label, m["id"])
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
    for row in _hunt(run, "privileged-logons"):
        a = assets.setdefault(row["DeviceId"], Asset(id=row["DeviceId"], name=row.get("DeviceName") or row["DeviceId"]))
        a.privileged_user = True
    for row in _hunt(run, "mitigations"):
        a = assets.setdefault(row["DeviceId"], Asset(id=row["DeviceId"], name=row.get("DeviceName") or row["DeviceId"]))
        compliant, total = row.get("Compliant") or 0, row.get("Total") or 0
        a.mitigations = compliant if compliant == total else 0

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
        expl = _norm_exploitability(v.get("exploitability") or "NoExploit")
        if v["cve_id"] in exploited and EXPLOIT_RANK[expl] < EXPLOIT_RANK["ExploitIsPublic"]:
            expl = "ExploitIsPublic"
        cur = p.cves.get(v["cve_id"])
        new_ref = CveRef(id=v["cve_id"], severity=v.get("severity") or "Low", cvss=_norm_cvss(v.get("cvss")),
                          exploitability=expl, first_seen=v.get("first_seen"))
        p.cves[v["cve_id"]] = _merge_cve_ref(cur, new_ref)
        if v.get("security_update"):
            p.fixes.setdefault(v["security_update"], set()).add(v["cve_id"])
        if v["device_id"] not in assets:
            assets[v["device_id"]] = Asset(id=v["device_id"], name=v.get("device_name") or v["device_id"], group=v.get("group"))

    for key, versions in version_devices.items():
        products[key].versions = {ver: len(devices) for ver, devices in versions.items()}

    for row in _hunt(run, "product-versions"):
        status = row.get("EndOfSupportStatus")
        if status in _EOS_IGNORE or status is None:
            continue
        key = product_key(row.get("SoftwareVendor"), row.get("SoftwareName"))
        p = products.get(key)
        if p is None:
            continue
        if p.eos is None:
            p.eos = {"status": status, "date": row.get("EndOfSupportDate") or None, "versions": []}
        version = row.get("SoftwareVersion")
        if version and version not in p.eos["versions"]:
            p.eos["versions"].append(version)

    if run.path("cloud-vulns.jsonl").exists():
        _merge_cloud(run, products, assets, azure_id_map, name_label_map, exploited)

    return products, assets


def _merge_cloud(run: Run, products: dict[str, Product], assets: dict[str, Asset],
                  azure_id_map: dict[str, str], name_label_map: dict[str, str], exploited: set[str]) -> None:
    image_version_images: dict[str, dict[str, set[str]]] = {}
    for row in run.read_jsonl("cloud-vulns.jsonl"):
        resource_id = row.get("resource_id") or ""
        repo = row.get("image_repo")
        dup_asset_id = azure_id_map.get(resource_id.lower())
        if dup_asset_id is None and not repo:
            # hostname-label fallback: server rows only, and only when the resource-id match found nothing
            last_seg = resource_id.rstrip("/").split("/")[-1].strip().lower()
            dup_asset_id = name_label_map.get(last_seg) if last_seg else None
        if dup_asset_id is not None:
            continue  # duplicate of an MDE asset; skip

        expl = "ExploitIsPublic" if row.get("cve_id") in exploited else "NoExploit"

        if repo:
            digest = row.get("image_digest") or ""
            short_digest = digest[:12]
            host, _, path = repo.partition("/")
            key = product_key(host, path)
            p = products.get(key)
            if p is None:
                p = products[key] = Product(key=key, vendor=host, name=path or repo)
            image_name = f"{repo}@{short_digest}"
            if image_name not in assets:
                assets[image_name] = Asset(id=image_name, name=image_name, kind="image")
            p.asset_ids.add(image_name)
            image_version_images.setdefault(key, {}).setdefault(short_digest, set()).add(image_name)
            if row.get("cve_id"):
                cur = p.cves.get(row["cve_id"])
                new_ref = CveRef(id=row["cve_id"], severity=row.get("severity") or "Low", cvss=_norm_cvss(row.get("cvss")),
                                  exploitability=expl, first_seen=None)
                p.cves[row["cve_id"]] = _merge_cve_ref(cur, new_ref)
        else:
            if resource_id and resource_id not in assets:
                assets[resource_id] = Asset(id=resource_id, name=row.get("display_name") or resource_id, kind="device")
            if resource_id and row.get("cve_id"):
                # grouped by finding name (not installed software: Defender for Cloud server findings carry no vendor/product)
                key = product_key("defender-for-cloud", row.get("display_name") or row["cve_id"])
                p = products.get(key)
                if p is None:
                    p = products[key] = Product(key=key, vendor="defender-for-cloud", name=row.get("display_name") or row["cve_id"])
                p.asset_ids.add(resource_id)
                cur = p.cves.get(row["cve_id"])
                new_ref = CveRef(id=row["cve_id"], severity=row.get("severity") or "Low", cvss=_norm_cvss(row.get("cvss")),
                                  exploitability=expl, first_seen=None)
                p.cves[row["cve_id"]] = _merge_cve_ref(cur, new_ref)

    for key, versions in image_version_images.items():
        products[key].versions.update({ver: len(images) for ver, images in versions.items()})


def display_name(p: Product) -> str:
    return " ".join(w.upper() if w.lower() in {"dc", "ems", "ssh", "sql", "vpn"} else w.capitalize() for w in p.name.replace("_", " ").split())


def display_vendor(p: Product) -> str:
    return p.vendor.replace("_", " ").title()
