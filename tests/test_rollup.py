from dva.run import Run
from dva.rollup import build, display_name
from dva.model import product_key


def seed(tmp_path):
    run = Run.create(tmp_path)
    run.write_json("machines.json", [
        {"id": "m1", "name": "vpn-gw-01", "exposure_level": "High", "device_value": "High", "tags": ["Tier0"], "group": "Perimeter", "is_internet_facing": None, "azure_resource_id": None},
        {"id": "m2", "name": "ws-114", "exposure_level": "Medium", "device_value": "Normal", "tags": [], "group": "Workstations", "is_internet_facing": None, "azure_resource_id": None},
    ])
    run.write_jsonl("vulns.jsonl", [
        {"device_id": "m1", "device_name": "vpn-gw-01", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.1", "cve_id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "exploitability": "ExploitIsInKit", "first_seen": "2026-09-08", "recommendation_ref": "va-_-ivanti-_-connect_secure"},
        {"device_id": "m1", "device_name": "vpn-gw-01", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.1", "cve_id": "CVE-2025-46512", "severity": "High", "cvss": 8.2, "exploitability": "NoExploit", "first_seen": "2026-06-01", "recommendation_ref": "va-_-ivanti-_-connect_secure"},
        {"device_id": "m2", "device_name": "ws-114", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.0", "cve_id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "exploitability": "ExploitIsInKit", "first_seen": "2026-09-09", "recommendation_ref": "va-_-ivanti-_-connect_secure"},
        {"device_id": "m2", "device_name": "ws-114", "vendor": "adobe", "product": "acrobat_reader_dc", "version": "24.0", "cve_id": "CVE-2026-24433", "severity": "Critical", "cvss": 8.6, "exploitability": "NoExploit", "first_seen": "2026-09-01", "recommendation_ref": "va-_-adobe-_-acrobat_reader_dc"},
    ])
    run.write_json("recommendations.json", [{"id": "va-_-ivanti-_-connect_secure", "vendor": "ivanti", "product": "connect_secure", "name": "Update Ivanti Connect Secure to 22.7R2.5", "recommended_version": "22.7R2.5", "remediation_type": "Update"}])
    run.write_json("hunt-internet-facing.json", {"results": [{"DeviceId": "m1", "PublicIP": "1.2.3.4"}]})
    run.write_json("hunt-device-tags.json", {"results": [{"DeviceId": "m2", "DeviceManualTags": "[\"Prod\",\"Finance\"]", "DeviceDynamicTags": "", "ExposureLevel": "Medium", "AssetValue": "Normal"}]})
    run.write_json("hunt-exploited-cves.json", {"results": [{"CveId": "CVE-2025-46512"}]})
    return run


def test_products_and_assets(tmp_path):
    products, assets = build(seed(tmp_path))
    ics = products[product_key("ivanti", "connect_secure")]
    assert set(ics.cves) == {"CVE-2026-21887", "CVE-2025-46512"} and ics.asset_ids == {"m1", "m2"}
    assert ics.versions == {"22.7R2.1": 1, "22.7R2.0": 1}
    assert ics.recommended_version == "22.7R2.5" and ics.remediation.startswith("Update Ivanti")
    assert ics.cves["CVE-2025-46512"].exploitability == "ExploitIsPublic"  # upgraded from hunting KB
    assert display_name(ics) == "Connect Secure"
    assert assets["m1"].internet_facing is True and assets["m1"].tags == ["Tier0"]
    assert assets["m2"].internet_facing is False and sorted(assets["m2"].tags) == ["Finance", "Prod"]
    adobe = products[product_key("adobe", "acrobat_reader_dc")]
    assert adobe.remediation is None and adobe.asset_ids == {"m2"}


def test_split_tags_json_array_and_comma_fallback():
    from dva.rollup import _split_tags

    assert _split_tags('["Tier0","Prod"]') == ["Tier0", "Prod"]
    assert _split_tags("Prod,Finance") == ["Prod", "Finance"]
    assert _split_tags("") == []
    assert _split_tags(None) == []


def test_cve_ref_merges_strongest_fields_across_rows(tmp_path):
    run = Run.create(tmp_path)
    run.write_json("machines.json", [
        {"id": "m1", "name": "vpn-gw-01", "exposure_level": "High", "device_value": "High", "tags": [], "group": None, "is_internet_facing": None, "azure_resource_id": None},
        {"id": "m2", "name": "ws-114", "exposure_level": "Medium", "device_value": "Normal", "tags": [], "group": None, "is_internet_facing": None, "azure_resource_id": None},
    ])
    run.write_jsonl("vulns.jsonl", [
        {"device_id": "m1", "device_name": "vpn-gw-01", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.1", "cve_id": "CVE-2026-21887", "severity": "High", "cvss": 5.0, "exploitability": "ExploitIsInKit", "first_seen": "2026-06-01", "recommendation_ref": None},
        {"device_id": "m2", "device_name": "ws-114", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.1", "cve_id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "exploitability": "NoExploit", "first_seen": "2026-01-01", "recommendation_ref": None},
    ])
    run.write_json("recommendations.json", [])
    products, _ = build(run)
    ref = products[product_key("ivanti", "connect_secure")].cves["CVE-2026-21887"]
    assert ref.exploitability == "ExploitIsInKit"
    assert ref.cvss == 9.8
    assert ref.severity == "Critical"
    assert ref.first_seen == "2026-01-01"


def test_build_tolerates_unknown_exploitability_and_non_numeric_cvss(tmp_path):
    run = Run.create(tmp_path)
    run.write_json("machines.json", [
        {"id": "m1", "name": "vpn-gw-01", "exposure_level": "High", "device_value": "High", "tags": [], "group": None, "is_internet_facing": None, "azure_resource_id": None},
    ])
    run.write_jsonl("vulns.jsonl", [
        {"device_id": "m1", "device_name": "vpn-gw-01", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.1", "cve_id": "CVE-2026-99999", "severity": "Low", "cvss": "N/A", "exploitability": "Weird", "first_seen": "2026-06-01", "recommendation_ref": None},
    ])
    run.write_json("recommendations.json", [])
    products, _ = build(run)
    ref = products[product_key("ivanti", "connect_secure")].cves["CVE-2026-99999"]
    assert ref.exploitability == "NoExploit"
    assert ref.cvss == 0.0
