from __future__ import annotations
import json, os, time
from pathlib import Path
from typing import Callable
from dva.errors import DvaError

MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"
_SKEW = 300  # refresh tokens 5 minutes before expiry


class TokenProvider:
    def __init__(self, tenant_id: str, client_id: str, secret: str | None = None,
                 cert_path: str | None = None, cache_path: Path | None = None,
                 app_factory: Callable | None = None):
        self.tenant_id, self.client_id = tenant_id, client_id
        self.secret, self.cert_path = secret, cert_path
        self.cache_path = cache_path
        self._app_factory = app_factory or self._msal_app
        self._app = None
        self._mem: dict[str, dict] = self._load_disk()

    @classmethod
    def from_env(cls, cache_dir: Path) -> "TokenProvider":
        tenant, client = os.environ.get("DVA_TENANT_ID"), os.environ.get("DVA_CLIENT_ID")
        secret, cert = os.environ.get("DVA_CLIENT_SECRET"), os.environ.get("DVA_CLIENT_CERT_PATH")
        missing = [k for k, v in [("DVA_TENANT_ID", tenant), ("DVA_CLIENT_ID", client)] if not v]
        if not secret and not cert:
            missing.append("DVA_CLIENT_SECRET or DVA_CLIENT_CERT_PATH")
        if missing:
            raise DvaError("missing environment: " + ", ".join(missing))
        return cls(tenant, client, secret=secret, cert_path=cert, cache_path=cache_dir / "tokens.json")

    def _msal_app(self):
        import msal
        if self.cert_path:
            cred = {"private_key": Path(self.cert_path).read_text(), "thumbprint": os.environ.get("DVA_CLIENT_CERT_THUMBPRINT", "")}
        else:
            cred = self.secret
        return msal.ConfidentialClientApplication(
            self.client_id, authority=f"https://login.microsoftonline.com/{self.tenant_id}", client_credential=cred)

    def token(self, scope: str) -> str:
        entry = self._mem.get(scope)
        if entry and entry["expires_at"] - _SKEW > time.time():
            return entry["access_token"]
        if self._app is None:
            self._app = self._app_factory()
        result = self._app.acquire_token_for_client(scopes=[scope])
        if "access_token" not in result:
            raise DvaError(f"token request for {scope} failed: {result.get('error')}: {result.get('error_description')}")
        self._mem[scope] = {"access_token": result["access_token"], "expires_at": time.time() + int(result.get("expires_in", 3600))}
        self._save_disk()
        return result["access_token"]

    def _load_disk(self) -> dict:
        if self.cache_path and self.cache_path.exists():
            try:
                return json.loads(self.cache_path.read_text())
            except json.JSONDecodeError:
                return {}
        return {}

    def _save_disk(self) -> None:
        if not self.cache_path:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self._mem))
        os.chmod(self.cache_path, 0o600)
