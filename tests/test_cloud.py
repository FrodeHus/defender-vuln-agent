from dva.cloud import collect_vulns, ARM_BASE, RG_PATH
from dva.http import Client
from dva.run import Run
from dva.rollup import build
from dva.model import Asset
from tests.fakes import FakeSession, FakeResponse, FakeTokens

ROW_VM = {"id": "/subscriptions/s1/.../assessments/k1/subassessments/x", "subscriptionId": "s1", "resourceGroup": "rg", "assessmentKey": "k1", "cveId": "CVE-2026-21335", "displayName": "Win32k EoP", "severity": "High", "resourceId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vpn-gw-01", "assessedType": "ServerVulnerability", "cvss": 8.8, "patchable": True, "repo": "", "digest": ""}
ROW_IMG = {"id": "/subscriptions/s1/.../assessments/k2/subassessments/y", "subscriptionId": "s1", "resourceGroup": "rg", "assessmentKey": "k2", "cveId": "CVE-2026-1097", "displayName": "nginx QUIC overflow", "severity": "Critical", "resourceId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/prodacr", "assessedType": "AzureContainerRegistryVulnerability", "cvss": 9.1, "patchable": True, "repo": "prodacr.azurecr.io/nginx", "digest": "sha256:abcdef1234567890"}


def test_paging_and_dedup(tmp_path):
    run = Run.create(tmp_path)
    run.write_json("machines.json", [{"id": "m1", "name": "vpn-gw-01.corp.example", "exposure_level": "High", "device_value": "High", "tags": [], "group": "g", "is_internet_facing": True, "azure_resource_id": ROW_VM["resourceId"]}])
    run.write_jsonl("vulns.jsonl", [])
    run.write_json("hunt-exploited-cves.json", {"results": [{"CveId": "CVE-2026-1097"}]})
    s = FakeSession({f"POST {ARM_BASE}{RG_PATH}": [FakeResponse(200, {"data": [ROW_VM], "count": 1, "$skipToken": "t1"}), FakeResponse(200, {"data": [ROW_IMG], "count": 1})]})
    c = Client(FakeTokens(), "s", base_url=ARM_BASE, session=s, sleep=lambda x: None)
    assert collect_vulns(c, run, ["s1"]) == 2
    assert s.calls[1][2]["json"]["options"]["$skipToken"] == "t1"
    rows = list(run.read_jsonl("cloud-vulns.jsonl"))
    assert rows[0]["cve_id"] == "CVE-2026-21335" and rows[1]["image_repo"] == "prodacr.azurecr.io/nginx"
    products, assets = build(run)
    assert "prodacr.azurecr.io/nginx" in products and assets["prodacr.azurecr.io/nginx@sha256:abcde"].kind == "image"
    assert not any(a.kind == "device" and a.id != "m1" for a in assets.values())  # VM row de-duplicated
    img_product = products["prodacr.azurecr.io/nginx"]
    assert img_product.cves["CVE-2026-1097"].exploitability == "ExploitIsPublic"  # picked up from hunt-exploited-cves.json


def test_hostname_dedup_only_applies_without_azure_resource_id(tmp_path):
    # m1 has an azure_resource_id that does NOT match the cloud row's resourceId, but its hostname label
    # ("vpn-gw-01") does match the cloud VM's resource name. The resource-id match stays authoritative for
    # any MDE asset that has one, so this must NOT be treated as a duplicate.
    run = Run.create(tmp_path)
    run.write_json("machines.json", [{"id": "m1", "name": "vpn-gw-01.corp.example", "exposure_level": "High", "device_value": "High", "tags": [], "group": "g", "is_internet_facing": True, "azure_resource_id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/unrelated-vm"}])
    run.write_jsonl("vulns.jsonl", [])
    run.write_jsonl("cloud-vulns.jsonl", [{
        "resource_id": ROW_VM["resourceId"], "resource_type": "ServerVulnerability", "subscription": "s1",
        "resource_group": "rg", "cve_id": "CVE-2026-21335", "severity": "High", "cvss": 8.8, "patchable": True,
        "image_repo": None, "image_digest": None, "display_name": "Win32k EoP", "assessment_key": "k1", "duplicate_of": None,
    }])
    products, assets = build(run)
    assert ROW_VM["resourceId"] in assets and assets[ROW_VM["resourceId"]].kind == "device"


def test_surviving_server_row_becomes_scored_product(tmp_path):
    run = Run.create(tmp_path)
    run.write_json("machines.json", [])
    run.write_jsonl("vulns.jsonl", [])
    run.write_jsonl("cloud-vulns.jsonl", [{
        "resource_id": ROW_VM["resourceId"], "resource_type": "ServerVulnerability", "subscription": "s1",
        "resource_group": "rg", "cve_id": "CVE-2026-21335", "severity": "High", "cvss": 8.8, "patchable": True,
        "image_repo": None, "image_digest": None, "display_name": "Win32k EoP", "assessment_key": "k1", "duplicate_of": None,
    }])
    products, assets = build(run)
    matches = [p for p in products.values() if "CVE-2026-21335" in p.cves]
    assert len(matches) == 1
    p = matches[0]
    assert ROW_VM["resourceId"] in p.asset_ids
    assert p.cves["CVE-2026-21335"].severity == "High"
