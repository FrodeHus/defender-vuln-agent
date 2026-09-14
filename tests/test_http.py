import pytest
from dva.http import Client
from dva.errors import DvaError
from tests.fakes import FakeSession, FakeResponse, FakeTokens


def mk(routes, **kw):
    return Client(FakeTokens(), "scope", base_url="https://h/api", session=FakeSession(routes), sleep=lambda s: None, **kw)


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
