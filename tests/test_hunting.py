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
