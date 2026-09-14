import json
from pathlib import Path
import pytest
from dva.mde import collect_machines, collect_vulns, collect_recommendations, collect_score, collect_changes, MDE_BASE
from dva.errors import DvaError
from dva.http import Client
from dva.run import Run
from tests.fakes import FakeSession, FakeResponse, FakeTokens

FX = Path(__file__).parent / "fixtures" / "mde"
def load(n): return json.loads((FX / n).read_text())

def client(routes):
    return Client(FakeTokens(), "s", base_url=MDE_BASE, session=FakeSession(routes), sleep=lambda s: None)

def test_machines_paged_and_normalized(tmp_path):
    run = Run.create(tmp_path)
    c = client({f"GET {MDE_BASE}/machines": [FakeResponse(200, load("machines_p1.json")), FakeResponse(200, load("machines_p2.json"))]})
    assert collect_machines(c, run) == 3
    m = {x["id"]: x for x in run.read_json("machines.json")}
    assert m["m1"]["azure_resource_id"].endswith("/vpn-gw-01")
    assert m["m3"]["tags"] == ["Tier0", "Prod"] and m["m3"]["device_value"] == "High"
    assert m["m2"]["azure_resource_id"] is None
    assert run.manifest["sources"]["mde.machines"]["status"] == "ok"
    assert c.session.calls[0][2]["params"] == {"$top": 10000}

def test_vulns_skip_null_cve_and_write_jsonl(tmp_path):
    run = Run.create(tmp_path)
    c = client({f"GET {MDE_BASE}/machines/SoftwareVulnerabilitiesByMachine": [FakeResponse(200, load("vulns_p1.json"))]})
    assert collect_vulns(c, run) == 4
    rows = list(run.read_jsonl("vulns.jsonl"))
    assert rows[0]["cve_id"] == "CVE-2026-21887" and rows[0]["cvss"] == 9.8 and rows[0]["exploitability"] == "ExploitIsInKit"
    assert all(r["cve_id"] for r in rows)

def test_recommendations_and_score(tmp_path):
    run = Run.create(tmp_path)
    c = client({
        f"GET {MDE_BASE}/recommendations": [FakeResponse(200, load("recommendations.json"))],
        f"GET {MDE_BASE}/exposureScore": [FakeResponse(200, load("exposure.json"))],
        f"GET {MDE_BASE}/exposureScore/ByMachineGroups": [FakeResponse(200, {"value": [{"rbacGroupName": "Servers", "score": 61.0}]})],
        f"GET {MDE_BASE}/configurationScore": [FakeResponse(200, {"score": 72.34})],
    })
    assert collect_recommendations(c, run) == 2
    rec = run.read_json("recommendations.json")[0]
    assert rec["recommended_version"] == "22.7R2.5" and rec["remediation_type"] == "Update"
    collect_score(c, run)
    assert run.read_json("exposure.json") == {"score": 54.2, "by_group": {"Servers": 61.0}, "secure_score": 72.34}

def test_failed_source_marks_manifest(tmp_path):
    run = Run.create(tmp_path)
    c = client({f"GET {MDE_BASE}/recommendations": [FakeResponse(403, {"error": {"message": "denied"}})]})
    with pytest.raises(DvaError):
        collect_recommendations(c, run)
    assert run.manifest["sources"]["mde.recommendations"]["status"] == "failed"

def test_vulns_write_is_atomic_on_page_failure(tmp_path):
    run = Run.create(tmp_path)
    page1 = {
        "value": [load("vulns_p1.json")["value"][0]],
        "@odata.nextLink": f"{MDE_BASE}/machines/SoftwareVulnerabilitiesByMachine?$skiptoken=p2",
    }
    s = FakeSession({
        f"GET {MDE_BASE}/machines/SoftwareVulnerabilitiesByMachine": [
            FakeResponse(200, page1), FakeResponse(503, {"error": {"message": "boom"}}),
        ],
    })
    c = Client(FakeTokens(), "s", base_url=MDE_BASE, session=s, sleep=lambda s: None, max_attempts=1)
    with pytest.raises(DvaError):
        collect_vulns(c, run)
    assert not run.path("vulns.jsonl").exists()
    assert not run.path("vulns.jsonl.tmp").exists()
    assert run.manifest["sources"]["mde.vulns"]["status"] == "failed"

def test_mde_all_fixture_end_to_end(tmp_path):
    from dva.__main__ import main
    run = Run.create(tmp_path)
    rc = main(["mde", "all", "--fixture", str(FX / "all.json"), "--run", str(run.dir)])
    assert rc == 0
    assert len(run.read_json("machines.json")) == 3
    assert len(list(run.read_jsonl("vulns.jsonl"))) == 4
    assert len(run.read_json("recommendations.json")) == 2
    assert run.read_json("exposure.json")["score"] == 54.2
    assert run.read_json("exposure.json")["secure_score"] == 72.34
    assert len(list(run.read_jsonl("vuln-changes.jsonl"))) == 1


def test_exposure_score_rounded_to_two_decimals(tmp_path):
    run = Run.create(tmp_path)
    c = client({
        f"GET {MDE_BASE}/exposureScore": [FakeResponse(200, {"score": 31.59096493849269})],
        f"GET {MDE_BASE}/exposureScore/ByMachineGroups": [FakeResponse(200, {"value": [{"rbacGroupName": "Servers", "score": 61.0049}]})],
        f"GET {MDE_BASE}/configurationScore": [FakeResponse(200, {"score": 40.005})],
    })
    collect_score(c, run)
    assert run.read_json("exposure.json") == {"score": 31.59, "by_group": {"Servers": 61.0}, "secure_score": 40.01}


def test_changes_sinceTime_and_normalized_rows_skip_null_cve(tmp_path):
    run = Run.create(tmp_path)
    c = client({f"GET {MDE_BASE}/machines/SoftwareVulnerabilityChangesByMachine": [FakeResponse(200, {
        "value": [
            {"deviceId": "m1", "softwareVendor": "ivanti", "softwareName": "connect_secure", "softwareVersion": "22.7R2.5",
             "cveId": "CVE-2026-21887", "vulnerabilitySeverityLevel": "Critical", "status": "Fixed", "eventTimestamp": "2026-09-13T00:00:00Z"},
            {"deviceId": "m2", "softwareVendor": "adobe", "softwareName": "acrobat_reader_dc", "softwareVersion": "24.002.20000",
             "cveId": None, "status": "New", "eventTimestamp": "2026-09-12T00:00:00Z"},
        ]
    })]})
    n = collect_changes(c, run, since_days=7)
    assert n == 1
    rows = list(run.read_jsonl("vuln-changes.jsonl"))
    assert rows[0] == {"device_id": "m1", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.5",
                        "cve_id": "CVE-2026-21887", "severity": "Critical", "status": "Fixed", "event_time": "2026-09-13T00:00:00Z"}
    method, url, kwargs = c.session.calls[0]
    assert kwargs["params"]["pageSize"] == 50000
    assert kwargs["params"]["sinceTime"].endswith("Z")
    assert run.manifest["sources"]["mde.changes"]["status"] == "ok"


def test_changes_rejects_since_days_over_14(tmp_path):
    run = Run.create(tmp_path)
    c = client({})
    with pytest.raises(DvaError):
        collect_changes(c, run, since_days=15)
