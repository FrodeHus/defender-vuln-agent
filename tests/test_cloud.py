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
    s = FakeSession({f"POST {ARM_BASE}{RG_PATH}": [FakeResponse(200, {"data": [ROW_VM], "count": 1, "$skipToken": "t1"}), FakeResponse(200, {"data": [ROW_IMG], "count": 1})]})
    c = Client(FakeTokens(), "s", base_url=ARM_BASE, session=s, sleep=lambda x: None)
    assert collect_vulns(c, run, ["s1"]) == 2
    assert s.calls[1][2]["json"]["options"]["$skipToken"] == "t1"
    rows = list(run.read_jsonl("cloud-vulns.jsonl"))
    assert rows[0]["cve_id"] == "CVE-2026-21335" and rows[1]["image_repo"] == "prodacr.azurecr.io/nginx"
    products, assets = build(run)
    assert "prodacr.azurecr.io/nginx" in products and assets["prodacr.azurecr.io/nginx@sha256:abcde"].kind == "image"
    assert not any(a.kind == "device" and a.id != "m1" for a in assets.values())  # VM row de-duplicated
