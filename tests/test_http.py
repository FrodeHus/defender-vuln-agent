import pytest
import requests
from dva.http import Client
from dva.errors import DvaError
from tests.fakes import FakeSession, FakeResponse, FakeTokens


def test_get_json_sets_bearer():
    s = FakeSession({"GET https://h/api/x": [FakeResponse(200, {"a": 1})]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s)
    assert c.get_json("/x") == {"a": 1}
    assert s.calls[0][2]["params"] is None


def test_retries_on_429_with_retry_after():
    slept = []
    s = FakeSession({"GET https://h/api/x": [FakeResponse(429, {}, {"Retry-After": "2"}), FakeResponse(200, {"ok": True})]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s, sleep=slept.append)
    assert c.get_json("/x") == {"ok": True}
    assert slept == [2.0]


def test_gives_up_after_max_attempts():
    s = FakeSession({"GET https://h/api/x": [FakeResponse(503, {})]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s, sleep=lambda s: None, max_attempts=3)
    with pytest.raises(DvaError, match="503"):
        c.get_json("/x")


def test_4xx_is_not_retried():
    s = FakeSession({"GET https://h/api/x": [FakeResponse(403, {"error": {"message": "nope"}})]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s)
    with pytest.raises(DvaError, match="403"):
        c.get_json("/x")
    assert len(s.calls) == 1


def test_paged_follows_next_link():
    s = FakeSession({
        "GET https://h/api/items": [FakeResponse(200, {"value": [1, 2], "@odata.nextLink": "https://h/api/items?$skiptoken=abc"}), FakeResponse(200, {"value": [3]})],
    })
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s)
    assert list(c.paged("/items")) == [1, 2, 3]
    assert "$skiptoken=abc" in s.calls[1][1]


def test_retries_on_network_exception():
    slept = []
    s = FakeSession({"GET https://h/api/x": [requests.ConnectionError("connection failed"), FakeResponse(200, {"ok": True})]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s, sleep=slept.append)
    assert c.get_json("/x") == {"ok": True}
    assert len(slept) == 1


def test_network_exception_exhausts_retries():
    s = FakeSession({"GET https://h/api/x": [requests.ConnectionError("connection failed")]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s, sleep=lambda s: None, max_attempts=3)
    with pytest.raises(DvaError, match="failed after 3 attempts"):
        c.get_json("/x")


def test_non_json_body_raises_dva_error():
    s = FakeSession({"GET https://h/api/x": [FakeResponse(200, None, json_error=ValueError("not json"), text="<html>")]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s)
    with pytest.raises(DvaError, match="non-JSON body.*<html>"):
        c.get_json("/x")


def test_http_date_retry_after():
    slept = []
    s = FakeSession({"GET https://h/api/x": [FakeResponse(429, {}, {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}), FakeResponse(200, {"ok": True})]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s, sleep=slept.append)
    assert c.get_json("/x") == {"ok": True}
    assert slept[0] == 0.0 or slept[0] < 0.1


def test_network_exception_then_http_error_shows_real_error():
    s = FakeSession({"GET https://h/api/x": [requests.ConnectionError("connection failed"), FakeResponse(403, {"error": {"message": "denied"}})]})
    c = Client(FakeTokens(), "scope", base_url="https://h/api", session=s, sleep=lambda s: None)
    with pytest.raises(DvaError) as exc_info:
        c.get_json("/x")
    msg = str(exc_info.value)
    assert "403" in msg
    assert "denied" in msg
    assert "failed after" not in msg
