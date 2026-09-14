import pytest
from dva.hunting import run_query, run_named, load_query, GRAPH_BASE, ROW_CAP, check_kql_is_readonly
from dva.http import Client
from dva.run import Run
from dva.errors import DvaError
from tests.fakes import FakeSession, FakeResponse, FakeTokens

URL = f"POST {GRAPH_BASE}/security/runHuntingQuery"

def client(resp):
    return Client(FakeTokens(), "s", base_url=GRAPH_BASE, session=FakeSession({URL: [resp]}), sleep=lambda s: None)

def test_named_query_loads():
    assert "IsInternetFacing == true" in load_query("internet-facing")


def test_new_named_queries_load():
    assert "IdentityInfo" in load_query("privileged-logons") and "CriticalityLevel <= 1" in load_query("privileged-logons")
    assert "__CONFIG_IDS__" in load_query("mitigations")
    assert "DeviceTvmSecureConfigurationAssessmentKB" in load_query("mitigation-catalog")
    assert "DeviceTvmCertificateInfo" in load_query("certificates")
    assert "IssuedTo = tostring(IssuedTo)" in load_query("certificates")
    assert "IsCompliant == false" in load_query("config-findings")


def test_run_named_mitigations_skips_when_no_config(tmp_path, monkeypatch):
    from dva.config import Scoring, load_scoring

    base = load_scoring()
    empty_cfg = Scoring(**{**base.__dict__, "mitigation_configs": []})
    monkeypatch.setattr("dva.config.load_scoring", lambda *a, **k: empty_cfg)
    run = Run.create(tmp_path)
    c = client(FakeResponse(200, {"schema": [], "results": []}))
    assert run_named(c, run, ["mitigations"]) == 0
    assert c.session.calls == []
    assert run.read_json("hunt-mitigations.json") == {"schema": [], "results": [], "capped": False}
    assert run.manifest["sources"]["hunting.mitigations"]["status"] == "ok"


def test_run_named_mitigations_renders_configured_ids(tmp_path, monkeypatch):
    from dva.config import Scoring, load_scoring

    base = load_scoring()
    cfg = Scoring(**{**base.__dict__, "mitigation_configs": ["scid-1", "scid-2"]})
    monkeypatch.setattr("dva.config.load_scoring", lambda *a, **k: cfg)
    run = Run.create(tmp_path)
    c = client(FakeResponse(200, {"schema": [], "results": [{"DeviceId": "m1", "Compliant": 2, "Total": 2}]}))
    assert run_named(c, run, ["mitigations"]) == 0
    body = c.session.calls[0][2]["json"]["Query"]
    assert '"scid-1"' in body and '"scid-2"' in body
    assert run.read_json("hunt-mitigations.json")["results"][0]["DeviceId"] == "m1"
    assert run.manifest["sources"]["hunting.mitigations"]["status"] == "ok"

def test_run_query_writes_results_and_body(tmp_path):
    run = Run.create(tmp_path)
    c = client(FakeResponse(200, {"schema": [{"name": "DeviceId", "type": "String"}], "results": [{"DeviceId": "m1"}]}))
    out = run_query(c, run, "internet-facing", load_query("internet-facing"))
    assert out["results"] == [{"DeviceId": "m1"}] and out["capped"] is False
    assert run.read_json("hunt-internet-facing.json")["results"][0]["DeviceId"] == "m1"
    body = c.session.calls[0][2]["json"]
    assert body["Query"].startswith("DeviceInfo") and body["Query"].endswith("| take 10000") and body["Timespan"] == "P7D"
    assert run.manifest["sources"]["hunting.internet-facing"]["status"] == "ok"

def test_row_cap_marks_partial(tmp_path):
    run = Run.create(tmp_path)
    c = client(FakeResponse(200, {"schema": [], "results": [{"i": n} for n in range(ROW_CAP)]}))
    out = run_query(c, run, "big", "DeviceInfo")
    assert out["capped"] is True
    assert run.manifest["sources"]["hunting.big"]["status"] == "partial"

def test_query_ending_in_existing_take_is_not_rewrapped(tmp_path):
    run = Run.create(tmp_path)
    c = client(FakeResponse(200, {"schema": [], "results": [{"i": 1}]}))
    out = run_query(c, run, "small", "DeviceInfo | take 5")
    body = c.session.calls[0][2]["json"]
    assert body["Query"] == "DeviceInfo | take 5"
    assert out["capped"] is False


def test_readonly_guard():
    with pytest.raises(DvaError):
        check_kql_is_readonly(".create table X")
    check_kql_is_readonly("DeviceInfo | take 1")

def test_run_named_records_failed_source_for_unknown_query(tmp_path):
    run = Run.create(tmp_path)
    c = client(FakeResponse(200, {"schema": [], "results": [{"DeviceId": "m1"}]}))
    failures = run_named(c, run, ["internet-facing", "no-such-query"])
    assert failures == 1
    assert run.read_json("hunt-internet-facing.json")
    assert run.manifest["sources"]["hunting.no-such-query"]["status"] == "failed"
