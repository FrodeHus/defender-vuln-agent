import os, json
import pytest
from dva.auth import TokenProvider, MDE_SCOPE
from dva.errors import DvaError

class FakeApp:
    def __init__(self):
        self.calls = 0
    def acquire_token_for_client(self, scopes):
        self.calls += 1
        return {"access_token": f"tok-{scopes[0]}-{self.calls}", "expires_in": 3600}

def test_token_is_cached_per_scope(tmp_path):
    app = FakeApp()
    tp = TokenProvider("t", "c", secret="s", cache_path=tmp_path / "tokens.json", app_factory=lambda: app)
    assert tp.token(MDE_SCOPE) == f"tok-{MDE_SCOPE}-1"
    assert tp.token(MDE_SCOPE) == f"tok-{MDE_SCOPE}-1"
    assert app.calls == 1
    assert json.loads((tmp_path / "tokens.json").read_text())[MDE_SCOPE]["access_token"].startswith("tok-")

def test_error_surface(tmp_path):
    class Bad:
        def acquire_token_for_client(self, scopes):
            return {"error": "invalid_client", "error_description": "bad secret"}
    tp = TokenProvider("t", "c", secret="s", cache_path=tmp_path / "t.json", app_factory=Bad)
    with pytest.raises(DvaError, match="invalid_client"):
        tp.token(MDE_SCOPE)

def test_from_env_requires_vars(monkeypatch, tmp_path):
    for k in ["DVA_TENANT_ID", "DVA_CLIENT_ID", "DVA_CLIENT_SECRET", "DVA_CLIENT_CERT_PATH"]:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(DvaError, match="DVA_TENANT_ID"):
        TokenProvider.from_env(tmp_path)
