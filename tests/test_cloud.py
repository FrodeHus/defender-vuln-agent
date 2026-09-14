from dva.cloud import collect_vulns, collect_attack_paths, ARM_BASE, RG_PATH
from dva.http import Client
from dva.run import Run
from dva.rollup import build
from dva.model import Asset
from dva.config import load_scoring
from dva.scoring import asset_signals
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


ROW_PATH_1 = {
    "id": "/subscriptions/s1/providers/Microsoft.Security/attackPaths/p1",
    "subscriptionId": "s1",
    "displayName": "Internet exposed VM leads to key vault",
    "riskCategories": ["Lateral Movement"],
    "entities": '[{"id":"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vpn-gw-01"},{"id":"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"}]',
}
ROW_PATH_2 = {
    "id": "/subscriptions/s1/providers/Microsoft.Security/attackPaths/p2",
    "subscriptionId": "s1",
    "displayName": "Storage account exposed to internet",
    "riskCategories": ["Exposure"],
    "entities": '[{"id":"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1"}]',
}


def test_attack_paths_paging(tmp_path):
    run = Run.create(tmp_path)
    s = FakeSession({f"POST {ARM_BASE}{RG_PATH}": [
        FakeResponse(200, {"data": [ROW_PATH_1], "count": 1, "$skipToken": "t1"}),
        FakeResponse(200, {"data": [ROW_PATH_2], "count": 1}),
    ]})
    c = Client(FakeTokens(), "s", base_url=ARM_BASE, session=s, sleep=lambda x: None)
    assert collect_attack_paths(c, run, ["s1"]) == 2
    assert s.calls[1][2]["json"]["options"]["$skipToken"] == "t1"
    rows = run.read_json("cloud-attackpaths.json")
    assert rows[0]["id"] == ROW_PATH_1["id"]
    assert rows[0]["display_name"] == "Internet exposed VM leads to key vault"
    assert rows[0]["subscription"] == "s1"
    assert rows[0]["risk_categories"] == ["Lateral Movement"]
    assert "vpn-gw-01" in rows[0]["entities"]
    assert rows[1]["display_name"] == "Storage account exposed to internet"


def test_rollup_marks_asset_on_attack_path_case_insensitive(tmp_path):
    run = Run.create(tmp_path)
    resource_id = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vpn-gw-01"
    run.write_json("machines.json", [{
        "id": "m1", "name": "vpn-gw-01.corp.example", "tags": [], "group": "g",
        "azure_resource_id": resource_id.upper(),
    }])
    run.write_jsonl("vulns.jsonl", [])
    run.write_json("cloud-attackpaths.json", [
        {"id": "p1", "subscription": "s1", "display_name": "Internet exposed VM leads to key vault",
         "risk_categories": ["Lateral Movement"], "entities": f'[{{"id":"{resource_id}"}}]'},
    ])
    products, assets = build(run)
    a = assets["m1"]
    assert a.attack_paths == ["Internet exposed VM leads to key vault"]


def test_rollup_asset_on_multiple_attack_paths_and_scoring_bonus(tmp_path):
    run = Run.create(tmp_path)
    resource_id = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vpn-gw-01"
    run.write_json("machines.json", [{
        "id": "m1", "name": "vpn-gw-01.corp.example", "tags": [], "group": "g",
        "azure_resource_id": resource_id,
    }])
    run.write_jsonl("vulns.jsonl", [])
    run.write_json("cloud-attackpaths.json", [
        {"id": "p1", "subscription": "s1", "display_name": "Internet exposed VM leads to key vault",
         "risk_categories": ["Lateral Movement"], "entities": f'[{{"id":"{resource_id}"}}]'},
        {"id": "p2", "subscription": "s1", "display_name": "Second hop path",
         "risk_categories": ["Exposure"], "entities": f'[{{"id":"{resource_id}"}}]'},
    ])
    products, assets = build(run)
    a = assets["m1"]
    assert a.attack_paths == ["Internet exposed VM leads to key vault", "Second hop path"]

    cfg = load_scoring()
    sig = asset_signals(a, cfg)
    texts = [t for t, _ in sig]
    assert "On attack path: Internet exposed VM leads to key vault (+1 more)" in texts
    assert (cfg.asset_bonus["attack_path"] in [v for _, v in sig])
