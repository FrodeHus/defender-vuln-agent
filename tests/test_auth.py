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

def test_cache_with_list_shape(tmp_path):
    cache_file = tmp_path / "tokens.json"
    cache_file.write_text("[]")
    app = FakeApp()
    tp = TokenProvider("t", "c", secret="s", cache_path=cache_file, app_factory=lambda: app)
    assert tp.token(MDE_SCOPE) == f"tok-{MDE_SCOPE}-1"

def test_cache_with_missing_expires_at(tmp_path):
    cache_file = tmp_path / "tokens.json"
    cache_file.write_text(json.dumps({MDE_SCOPE: {"access_token": "old-token"}}))
    app = FakeApp()
    tp = TokenProvider("t", "c", secret="s", cache_path=cache_file, app_factory=lambda: app)
    assert tp.token(MDE_SCOPE) == f"tok-{MDE_SCOPE}-1"
    assert app.calls == 1

def test_cache_unreadable_path(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / "tokens.json"
    cache_file.write_text("{}")
    os.chmod(cache_file, 0o000)
    try:
        app = FakeApp()
        tp = TokenProvider("t", "c", secret="s", cache_path=cache_file, app_factory=lambda: app)
        assert tp._mem == {}
    finally:
        os.chmod(cache_file, 0o644)

def test_cert_auth_path(tmp_path, monkeypatch):
    monkeypatch.setenv("DVA_TENANT_ID", "t")
    monkeypatch.setenv("DVA_CLIENT_ID", "c")
    monkeypatch.setenv("DVA_CLIENT_CERT_PATH", "/path/to/cert")
    monkeypatch.setenv("DVA_CLIENT_CERT_THUMBPRINT", "thumbprint123")

    calls = []
    class FakeMsalApp:
        def __init__(self, client_id, authority, client_credential):
            calls.append({"client_id": client_id, "authority": authority, "client_credential": client_credential})
        def acquire_token_for_client(self, scopes):
            return {"access_token": "token", "expires_in": 3600}

    monkeypatch.setattr("msal.ConfidentialClientApplication", FakeMsalApp)

    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("cert-content")
    monkeypatch.setenv("DVA_CLIENT_CERT_PATH", str(cert_file))

    tp = TokenProvider.from_env(tmp_path)
    tp.token(MDE_SCOPE)

    assert len(calls) == 1
    call = calls[0]
    assert call["client_id"] == "c"
    assert call["authority"] == "https://login.microsoftonline.com/t"
    assert call["client_credential"]["private_key"] == "cert-content"
    assert call["client_credential"]["thumbprint"] == "thumbprint123"

def test_cert_auth_requires_thumbprint(monkeypatch, tmp_path):
    monkeypatch.setenv("DVA_TENANT_ID", "t")
    monkeypatch.setenv("DVA_CLIENT_ID", "c")
    monkeypatch.setenv("DVA_CLIENT_CERT_PATH", "/path/to/cert")
    monkeypatch.delenv("DVA_CLIENT_CERT_THUMBPRINT", raising=False)

    with pytest.raises(DvaError, match="DVA_CLIENT_CERT_THUMBPRINT is required"):
        TokenProvider.from_env(tmp_path)
