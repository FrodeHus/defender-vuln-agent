import json
from pathlib import Path
import pytest
from dva.mde import collect_machines, collect_vulns, collect_recommendations, collect_score, MDE_BASE
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
    })
    assert collect_recommendations(c, run) == 2
    rec = run.read_json("recommendations.json")[0]
    assert rec["recommended_version"] == "22.7R2.5" and rec["remediation_type"] == "Update"
    collect_score(c, run)
    assert run.read_json("exposure.json") == {"score": 54.2, "by_group": {"Servers": 61.0}}

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
