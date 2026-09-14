# Defender Vulnerability Assessment Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Claude Code agent plus a `dva` Python package that pulls Defender inventory and vulnerability data to files, enriches only the top CVEs per software product through the cve-mcp-server, scores products, and renders Markdown, HTML and JSON reports.

**Architecture:** Every `python -m dva <command>` reads or writes files under `runs/<run id>/` and prints a short summary; the agent orchestrates commands and calls the CVE MCP tools for the small candidate list that `dva enrich --list` prints. Collectors (`mde.py`, `hunting.py`) share one HTTP client with retry and OData paging and one MSAL token provider. `scoring.py` rolls findings up to products and computes scores from `config/scoring.yaml`; three renderers read only `findings.json`.

**Tech Stack:** Python 3.11+, `msal`, `requests`, `pyyaml`, `pytest`; no other runtime dependencies. Claude Code agent + skills; `cve-mcp-server` over stdio.

**Spec:** `docs/superpowers/specs/2026-09-14-defender-vuln-agent-design.md`

## Global Constraints

- Python 3.11 or newer; dependencies limited to `msal`, `requests`, `pyyaml` (runtime) and `pytest` (dev).
- Read-only: no command may issue anything other than GET to MDE/ARM or POST to `/security/runHuntingQuery` and Resource Graph query endpoints.
- Raw records go to files under `runs/<id>/`; stdout carries one-paragraph summaries only. Never print raw records.
- Every command exits non-zero with a single-line reason on stderr on failure; details to `runs/<id>/log.txt`.
- Env vars: `DVA_TENANT_ID`, `DVA_CLIENT_ID`, `DVA_CLIENT_SECRET` or `DVA_CLIENT_CERT_PATH`; optional `DVA_RUNS_DIR` (default `runs/`), `DVA_CACHE_DIR` (default `.cache/`).
- Scopes: `https://api.securitycenter.microsoft.com/.default`, `https://graph.microsoft.com/.default`, `https://management.azure.com/.default`.
- MDE base URL `https://api.securitycenter.microsoft.com/api`. Hunting endpoint `https://graph.microsoft.com/v1.0/security/runHuntingQuery`. Hunting cap 10,000 rows.
- Enrichment: `enrich_top_per_product` default 3, `enrich_max_cves` default 200, `report_threshold` default 40, cache TTL 7 days, chunk size 20 (the CVE server's `bulk_cve_lookup` limit).
- Score bands: Critical ≥ 80, High ≥ 60, Medium ≥ 40, else Low. Top 10 by score is the prioritized list.
- No tests hit live APIs. Golden files regenerate with `DVA_UPDATE_GOLDEN=1 pytest`.
- Commit after every task with a conventional message.

---

## File map

| File | Responsibility |
|---|---|
| `pyproject.toml` | package metadata, deps, pytest config |
| `dva/__init__.py` | version string |
| `dva/__main__.py` | argparse CLI dispatch to command functions |
| `dva/errors.py` | `DvaError` (exit with one-line reason) |
| `dva/config.py` | load `config/scoring.yaml` and `config/sources.yaml` into dataclasses |
| `dva/auth.py` | `TokenProvider` (MSAL client credentials, disk cache) |
| `dva/http.py` | `Client` (GET/POST JSON, retry, Retry-After, OData paging) |
| `dva/run.py` | `Run` (directory, manifest, log, summary print, previous run lookup) |
| `dva/mde.py` | collectors: machines, vulns, recommendations, score |
| `dva/hunting.py` | `run_query`, named query loader, row-cap detection |
| `dva/queries/*.kql` | named hunting queries |
| `dva/doctor.py` | permission checks table |
| `dva/model.py` | `Device`, `Finding`, `CveIntel`, `Product`, `Asset` dataclasses |
| `dva/rollup.py` | build products and assets from run files |
| `dva/scoring.py` | threat score, asset multiplier, product score, labels, reason text |
| `dva/cache.py` | TTL JSON cache for CVE intel |
| `dva/enrich.py` | candidate selection (`--list`) and `--store` merge |
| `dva/score_cmd.py` | `findings.json` writer including diff from previous run |
| `dva/report_md.py`, `dva/report_html.py`, `dva/report_json.py` | renderers |
| `dva/report_template.html` | HTML skeleton with `__FINDINGS_JSON__` placeholder |
| `config/scoring.yaml`, `config/sources.yaml` | tunables |
| `setup/create-app.sh`, `setup/permissions.md` | app registration |
| `.claude/agents/vuln-assessor.md`, `.claude/skills/*/SKILL.md`, `.mcp.json` | agent surface |
| `tests/` | unit tests, fixtures, golden files |

---

### Task 1: Project scaffold and CLI skeleton

**Files:**
- Create: `pyproject.toml`, `dva/__init__.py`, `dva/__main__.py`, `dva/errors.py`, `tests/__init__.py`, `tests/test_cli.py`, `README.md`

**Interfaces:**
- Produces: `dva.errors.DvaError(message)`; `dva.__main__.main(argv) -> int` which dispatches subcommands and converts `DvaError` into a one-line stderr message and exit code 1. Later tasks register commands by adding `register_<name>(subparsers)` functions in their modules and listing them in `COMMAND_MODULES` in `__main__.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import subprocess, sys

def test_help_lists_commands():
    out = subprocess.run([sys.executable, "-m", "dva", "--help"], capture_output=True, text=True)
    assert out.returncode == 0
    assert "doctor" in out.stdout

def test_unknown_command_fails_cleanly():
    out = subprocess.run([sys.executable, "-m", "dva", "nope"], capture_output=True, text=True)
    assert out.returncode != 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL (module `dva` not found).

- [ ] **Step 3: Write the scaffold**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "defender-vuln-agent"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["msal>=1.28", "requests>=2.31", "pyyaml>=6"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.setuptools.packages.find]
include = ["dva*"]

[tool.setuptools.package-data]
dva = ["queries/*.kql", "report_template.html"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

```python
# dva/__init__.py
__version__ = "0.1.0"
```

```python
# dva/errors.py
class DvaError(Exception):
    """Raised for any user-facing failure. The CLI prints str(exc) on one line and exits 1."""
```

```python
# dva/__main__.py
from __future__ import annotations
import argparse
import importlib
import sys
from dva.errors import DvaError

# Each module exposes register(subparsers) and its command functions set parser.set_defaults(func=...)
COMMAND_MODULES = ["dva.doctor", "dva.run", "dva.mde", "dva.hunting", "dva.enrich", "dva.score_cmd", "dva.report_cmd"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dva", description="Defender vulnerability assessment helper")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in COMMAND_MODULES:
        try:
            mod = importlib.import_module(name)
        except ModuleNotFoundError:
            continue  # allows the CLI to work before every module exists
        mod.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except DvaError as exc:
        print(f"dva: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

Also create a placeholder `dva/doctor.py` so `--help` lists `doctor` (Task 8 replaces the body):

```python
# dva/doctor.py
def register(sub):
    p = sub.add_parser("doctor", help="Check credentials and permissions")
    p.set_defaults(func=run)

def run(args) -> int:
    from dva.errors import DvaError
    raise DvaError("doctor not implemented yet")
```

`README.md`: two paragraphs, what the tool does and `pip install -e ".[dev]"`, `pytest`, `python -m dva --help`.

- [ ] **Step 4: Install and run tests**

Run: `python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]" && pytest tests/test_cli.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml dva tests README.md
git commit -m "feat: scaffold dva package and CLI"
```

---

### Task 2: Configuration loading

**Files:**
- Create: `config/scoring.yaml`, `config/sources.yaml`, `dva/config.py`, `tests/test_config.py`

**Interfaces:**
- Produces: `dva.config.load_scoring(path=None) -> Scoring` and `load_sources(path=None) -> Sources`. `Scoring` fields: `threat_weights: dict[str,float]` (keys `cvss`, `epss`, `kev`, `exploit`), `asset_bonus: dict[str,float]` (keys `internet_facing`, `exposure_high`, `exposure_medium`, `device_value_high`, `criticality_tag`, `public_lb`), `asset_cap: float`, `criticality_tags: list[str]`, `enrich_top_per_product: int`, `enrich_max_cves: int`, `report_threshold: int`, `top_n: int`, `cache_ttl_days: int`, `bands: dict[str,int]`. `Sources` fields: `mde: bool`, `hunting: bool`, `cloud: bool`, `subscriptions: list[str]`, `hunting_queries: list[str]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
from dva.config import load_scoring, load_sources

def test_scoring_defaults():
    s = load_scoring()
    assert s.threat_weights == {"cvss": 0.35, "epss": 0.25, "kev": 0.25, "exploit": 0.15}
    assert s.enrich_top_per_product == 3
    assert s.enrich_max_cves == 200
    assert s.report_threshold == 40
    assert s.bands == {"critical": 80, "high": 60, "medium": 40}
    assert "Tier0" in s.criticality_tags

def test_sources_defaults():
    src = load_sources()
    assert src.mde and src.hunting and not src.cloud
    assert "internet-facing" in src.hunting_queries
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -v` → FAIL (no module).

- [ ] **Step 3: Write config files and loader**

```yaml
# config/scoring.yaml
threat_weights: { cvss: 0.35, epss: 0.25, kev: 0.25, exploit: 0.15 }
asset_bonus:
  internet_facing: 0.6
  exposure_high: 0.4
  exposure_medium: 0.2
  device_value_high: 0.4
  criticality_tag: 0.5
  public_lb: 0.6
asset_cap: 2.5
criticality_tags: [Tier0, Prod, DMZ]
enrich_top_per_product: 3
enrich_max_cves: 200
report_threshold: 40
top_n: 10
cache_ttl_days: 7
bands: { critical: 80, high: 60, medium: 40 }
```

```yaml
# config/sources.yaml
mde: true
hunting: true
cloud: false
subscriptions: []
hunting_queries: [internet-facing, exploited-cves, device-tags, vuln-counts-by-device, product-versions]
```

```python
# dva/config.py
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"


@dataclass
class Scoring:
    threat_weights: dict[str, float]
    asset_bonus: dict[str, float]
    asset_cap: float
    criticality_tags: list[str]
    enrich_top_per_product: int
    enrich_max_cves: int
    report_threshold: int
    top_n: int
    cache_ttl_days: int
    bands: dict[str, int]


@dataclass
class Sources:
    mde: bool = True
    hunting: bool = True
    cloud: bool = False
    subscriptions: list[str] = field(default_factory=list)
    hunting_queries: list[str] = field(default_factory=list)


def _read(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_scoring(path: Path | None = None) -> Scoring:
    return Scoring(**_read(path or CONFIG_DIR / "scoring.yaml"))


def load_sources(path: Path | None = None) -> Sources:
    return Sources(**_read(path or CONFIG_DIR / "sources.yaml"))
```

- [ ] **Step 4: Run tests** → `pytest tests/test_config.py -v` → 2 passed.

- [ ] **Step 5: Commit**

```bash
git add config dva/config.py tests/test_config.py
git commit -m "feat: load scoring and sources configuration"
```

---

### Task 3: Token provider (MSAL client credentials)

**Files:**
- Create: `dva/auth.py`, `tests/test_auth.py`

**Interfaces:**
- Produces: `dva.auth.TokenProvider(tenant_id, client_id, secret=None, cert_path=None, cache_path=None, app_factory=None)` with `token(scope: str) -> str`; `TokenProvider.from_env(cache_dir: Path) -> TokenProvider` raising `DvaError` when env vars are missing. Scope constants `MDE_SCOPE`, `GRAPH_SCOPE`, `ARM_SCOPE`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_auth.py
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
```

- [ ] **Step 2: Run test to verify it fails** → `pytest tests/test_auth.py -v` → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/auth.py
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
```

- [ ] **Step 4: Run tests** → 3 passed.
- [ ] **Step 5: Commit** → `git add dva/auth.py tests/test_auth.py && git commit -m "feat: MSAL client-credentials token provider with disk cache"`

---

### Task 4: HTTP client with retry and OData paging

**Files:**
- Create: `dva/http.py`, `tests/test_http.py`, `tests/fakes.py`

**Interfaces:**
- Produces: `dva.http.Client(token_provider, scope, base_url="", session=None, sleep=time.sleep, max_attempts=5)` with `get_json(path, params=None) -> dict`, `post_json(path, body) -> dict`, `paged(path, params=None, value_key="value") -> Iterator[dict]` (follows `@odata.nextLink`). `session` must expose `request(method, url, headers=, params=, json=, timeout=) -> response` where response has `.status_code`, `.headers`, `.json()`, `.text`. `tests/fakes.py` provides `FakeSession(routes: dict[str, list[dict|Callable]])` returning canned responses in order per URL and `FakeTokens` returning `"tok"`.

- [ ] **Step 1: Write fakes and failing tests**

```python
# tests/fakes.py
from __future__ import annotations
import json
from urllib.parse import urlsplit, parse_qsl

class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}
    def json(self):
        return self._body
    @property
    def text(self):
        return json.dumps(self._body)

class FakeSession:
    """routes: {"GET https://host/path": [FakeResponse, ...]} consumed in order; last one repeats."""
    def __init__(self, routes: dict):
        self.routes = {k: list(v) for k, v in routes.items()}
        self.calls: list[tuple[str, str, dict]] = []
    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        base = url.split("?")[0]
        key = f"{method} {base}"
        self.calls.append((method, url, {"params": params, "json": json}))
        if key not in self.routes:
            raise AssertionError(f"unexpected request {key}")
        queue = self.routes[key]
        return queue.pop(0) if len(queue) > 1 else queue[0]

class FakeTokens:
    def token(self, scope):
        return "tok"
```

```python
# tests/test_http.py
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
```

- [ ] **Step 2: Run tests to verify they fail** → `pytest tests/test_http.py -v` → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/http.py
from __future__ import annotations
import time
from typing import Callable, Iterator
import requests
from dva.errors import DvaError

RETRY_STATUS = {429, 500, 502, 503, 504}


class Client:
    def __init__(self, tokens, scope: str, base_url: str = "", session=None,
                 sleep: Callable[[float], None] = time.sleep, max_attempts: int = 5, timeout: int = 120):
        self.tokens, self.scope, self.base_url = tokens, scope, base_url.rstrip("/")
        self.session = session or requests.Session()
        self.sleep, self.max_attempts, self.timeout = sleep, max_attempts, timeout

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    def _request(self, method: str, path: str, params=None, body=None) -> dict:
        url = self._url(path)
        last = None
        for attempt in range(1, self.max_attempts + 1):
            headers = {"Authorization": f"Bearer {self.tokens.token(self.scope)}", "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            resp = self.session.request(method, url, headers=headers, params=params, json=body, timeout=self.timeout)
            if resp.status_code < 300:
                return resp.json() if resp.text else {}
            last = resp
            if resp.status_code in RETRY_STATUS and attempt < self.max_attempts:
                retry_after = resp.headers.get("Retry-After")
                self.sleep(float(retry_after) if retry_after else min(60.0, 2.0 ** attempt))
                continue
            break
        detail = ""
        try:
            detail = (last.json().get("error") or {}).get("message", "") if last is not None else ""
        except Exception:
            detail = (last.text or "")[:200] if last is not None else ""
        raise DvaError(f"{method} {url} failed with HTTP {last.status_code}: {detail}")

    def get_json(self, path: str, params: dict | None = None) -> dict:
        return self._request("GET", path, params=params)

    def post_json(self, path: str, body: dict) -> dict:
        return self._request("POST", path, body=body)

    def paged(self, path: str, params: dict | None = None, value_key: str = "value") -> Iterator[dict]:
        page = self.get_json(path, params)
        while True:
            yield from page.get(value_key, [])
            nxt = page.get("@odata.nextLink")
            if not nxt:
                return
            page = self.get_json(nxt)
```

- [ ] **Step 4: Run tests** → 5 passed.
- [ ] **Step 5: Commit** → `git add dva/http.py tests/fakes.py tests/test_http.py && git commit -m "feat: HTTP client with retry, Retry-After and OData paging"`

---

### Task 5: Run directories, manifest, and logging

**Files:**
- Create: `dva/run.py`, `tests/test_run.py`

**Interfaces:**
- Produces: `dva.run.Run` with `Run.create(runs_dir) -> Run` (directory `runs/<YYYYMMDDTHHMMSSZ>`), `Run.open(path) -> Run`, `Run.latest(runs_dir, before: str | None = None) -> Run | None`, properties `dir: Path`, `id: str`, methods `path(name) -> Path`, `write_json(name, obj)`, `read_json(name) -> Any`, `write_jsonl(name, iterable) -> int`, `read_jsonl(name) -> Iterator[dict]`, `log(msg)`, `set_source(name, status, count=None, error=None)`, `manifest -> dict`, `summary(text)` (prints `text` and appends it to `summary.txt`). CLI: `dva run new [--runs-dir]` prints the directory; `dva run latest` prints the latest directory. Helper `resolve_run(args) -> Run` used by every later command: `--run <dir>` argument, else env `DVA_RUN`, else latest under `DVA_RUNS_DIR`/`runs`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_run.py
import json
from dva.run import Run

def test_create_and_manifest(tmp_path):
    r = Run.create(tmp_path)
    assert r.dir.exists() and r.manifest["run_id"] == r.id
    r.set_source("mde.machines", "ok", count=3)
    r.write_json("a.json", {"x": 1})
    n = r.write_jsonl("b.jsonl", [{"i": 1}, {"i": 2}])
    assert n == 2 and list(r.read_jsonl("b.jsonl")) == [{"i": 1}, {"i": 2}]
    m = json.loads((r.dir / "manifest.json").read_text())
    assert m["sources"]["mde.machines"] == {"status": "ok", "count": 3, "error": None}

def test_latest_and_previous(tmp_path):
    a = Run.create(tmp_path); b = Run.create(tmp_path) if False else None
    (tmp_path / "20260101T000000Z").mkdir(); (tmp_path / "20260101T000000Z" / "manifest.json").write_text('{"run_id": "20260101T000000Z", "sources": {}}')
    latest = Run.latest(tmp_path)
    assert latest.id == a.id  # a was created now, which sorts after 2026-01-01
    prev = Run.latest(tmp_path, before=a.id)
    assert prev.id == "20260101T000000Z"

def test_summary_prints_and_records(tmp_path, capsys):
    r = Run.create(tmp_path)
    r.summary("machines: 3 collected")
    assert "machines: 3" in capsys.readouterr().out
    assert "machines: 3" in (r.dir / "summary.txt").read_text()
```

- [ ] **Step 2: Run to verify fail** → `pytest tests/test_run.py -v` → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/run.py
from __future__ import annotations
import json, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from dva.errors import DvaError


class Run:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.id = self.dir.name
        self._manifest_path = self.dir / "manifest.json"
        self.manifest = json.loads(self._manifest_path.read_text()) if self._manifest_path.exists() else {
            "run_id": self.id, "started_at": datetime.now(timezone.utc).isoformat(), "sources": {}}

    @classmethod
    def create(cls, runs_dir: Path) -> "Run":
        rid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")[:-4] + "Z"  # YYYYMMDDTHHMMSSmmZ
        d = Path(runs_dir) / rid
        d.mkdir(parents=True, exist_ok=False)
        run = cls(d)
        run._save()
        return run

    @classmethod
    def open(cls, path: Path) -> "Run":
        p = Path(path)
        if not (p / "manifest.json").exists():
            raise DvaError(f"not a run directory: {p}")
        return cls(p)

    @classmethod
    def latest(cls, runs_dir: Path, before: str | None = None) -> "Run | None":
        runs_dir = Path(runs_dir)
        if not runs_dir.exists():
            return None
        ids = sorted(p.name for p in runs_dir.iterdir() if (p / "manifest.json").exists())
        if before:
            ids = [i for i in ids if i < before]
        return cls(runs_dir / ids[-1]) if ids else None

    def path(self, name: str) -> Path:
        return self.dir / name

    def write_json(self, name: str, obj: Any) -> None:
        self.path(name).write_text(json.dumps(obj, indent=2, default=str))

    def read_json(self, name: str) -> Any:
        p = self.path(name)
        if not p.exists():
            raise DvaError(f"missing {name} in run {self.id}; run the collector first")
        return json.loads(p.read_text())

    def write_jsonl(self, name: str, rows: Iterable[dict]) -> int:
        n = 0
        with open(self.path(name), "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, default=str) + "\n"); n += 1
        return n

    def read_jsonl(self, name: str) -> Iterator[dict]:
        p = self.path(name)
        if not p.exists():
            raise DvaError(f"missing {name} in run {self.id}; run the collector first")
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def log(self, msg: str) -> None:
        with open(self.path("log.txt"), "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now(timezone.utc).isoformat()} {msg}\n")

    def set_source(self, name: str, status: str, count: int | None = None, error: str | None = None) -> None:
        self.manifest["sources"][name] = {"status": status, "count": count, "error": error}
        self._save()

    def summary(self, text: str) -> None:
        print(text)
        with open(self.path("summary.txt"), "a", encoding="utf-8") as fh:
            fh.write(text + "\n")

    def _save(self) -> None:
        self._manifest_path.write_text(json.dumps(self.manifest, indent=2))


def runs_dir() -> Path:
    return Path(os.environ.get("DVA_RUNS_DIR", "runs"))


def cache_dir() -> Path:
    return Path(os.environ.get("DVA_CACHE_DIR", ".cache"))


def add_run_arg(parser) -> None:
    parser.add_argument("--run", help="run directory (default: $DVA_RUN or latest under runs/)")


def resolve_run(args) -> Run:
    target = getattr(args, "run", None) or os.environ.get("DVA_RUN")
    if target:
        return Run.open(Path(target))
    latest = Run.latest(runs_dir())
    if latest is None:
        raise DvaError("no run found; create one with `dva run new`")
    return latest


def register(sub) -> None:
    p = sub.add_parser("run", help="Manage run directories")
    s = p.add_subparsers(dest="run_cmd", required=True)
    n = s.add_parser("new"); n.set_defaults(func=_new)
    l = s.add_parser("latest"); l.set_defaults(func=_latest)


def _new(args) -> int:
    print(Run.create(runs_dir()).dir); return 0


def _latest(args) -> int:
    r = Run.latest(runs_dir())
    if r is None:
        raise DvaError("no runs yet")
    print(r.dir); return 0
```

- [ ] **Step 4: Run tests** → 3 passed. Also `python -m dva run new` prints a directory.
- [ ] **Step 5: Commit** → `git add dva/run.py tests/test_run.py && git commit -m "feat: run directories with manifest, logs and summaries"`

---

### Task 6: MDE collectors (machines, vulns, recommendations, score)

**Files:**
- Create: `dva/mde.py`, `tests/test_mde.py`, `tests/fixtures/mde/machines_p1.json`, `tests/fixtures/mde/machines_p2.json`, `tests/fixtures/mde/vulns_p1.json`, `tests/fixtures/mde/recommendations.json`, `tests/fixtures/mde/exposure.json`

**Interfaces:**
- Consumes: `Client`, `Run`, `TokenProvider.from_env`, `MDE_SCOPE`.
- Produces: `dva.mde.MDE_BASE = "https://api.securitycenter.microsoft.com/api"`; `collect_machines(client, run) -> int` writes `machines.json` (list of normalized dicts with keys `id, name, os_platform, os_version, health, exposure_level, device_value, tags, group, last_seen, aad_device_id, azure_resource_id, is_internet_facing`); `collect_vulns(client, run, page_size=50000) -> int` writes `vulns.jsonl` (keys `device_id, device_name, vendor, product, version, cve_id, severity, cvss, exploitability, first_seen, last_seen, recommendation_ref, security_update, group`), skipping rows with null `cveId`; `collect_recommendations(client, run) -> int` writes `recommendations.json` (keys `id, vendor, product, name, recommended_version, remediation_type, public_exploit, exposed_machines, total_machines, weaknesses`); `collect_score(client, run) -> None` writes `exposure.json` (`{"score": float, "by_group": {name: score}}`). `make_client(scope, base_url) -> Client` builds a client from env. CLI: `dva mde machines|vulns|recommendations|score|all [--run] [--fixture FILE]`. With `--fixture`, the collector reads a JSON file containing the canned API response(s) instead of calling the API (a list means pages).

- [ ] **Step 1: Write fixtures**

`tests/fixtures/mde/machines_p1.json`:
```json
{"value": [
  {"id": "m1", "computerDnsName": "vpn-gw-01.corp.example", "osPlatform": "Linux", "version": "22.04", "healthStatus": "Active",
   "exposureLevel": "High", "deviceValue": "High", "machineTags": ["Tier0"], "rbacGroupName": "Perimeter", "lastSeen": "2026-09-14T04:00:00Z",
   "aadDeviceId": null, "vmMetadata": {"resourceId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vpn-gw-01"}},
  {"id": "m2", "computerDnsName": "ws-finance-114.corp.example", "osPlatform": "Windows11", "version": "23H2", "healthStatus": "Active",
   "exposureLevel": "Medium", "deviceValue": "Normal", "machineTags": [], "rbacGroupName": "Workstations", "lastSeen": "2026-09-14T03:00:00Z", "aadDeviceId": "aad-2"}
 ], "@odata.nextLink": "https://api.securitycenter.microsoft.com/api/machines?$skiptoken=p2"}
```
`tests/fixtures/mde/machines_p2.json`:
```json
{"value": [
  {"id": "m3", "computerDnsName": "dc-01.corp.example", "osPlatform": "WindowsServer2019", "version": "1809", "healthStatus": "Active",
   "exposureLevel": "High", "deviceValue": "High", "machineTags": ["Tier0", "Prod"], "rbacGroupName": "Servers", "lastSeen": "2026-09-14T02:00:00Z"}
]}
```
`tests/fixtures/mde/vulns_p1.json` (one page, no nextLink; note the null-cve row that must be skipped):
```json
{"value": [
  {"deviceId": "m1", "deviceName": "vpn-gw-01.corp.example", "rbacGroupName": "Perimeter", "softwareVendor": "ivanti", "softwareName": "connect_secure", "softwareVersion": "22.7R2.1",
   "cveId": "CVE-2026-21887", "vulnerabilitySeverityLevel": "Critical", "cvssScore": 9.8, "exploitabilityLevel": "ExploitIsInKit", "firstSeenTimestamp": "2026-09-08 01:00:00", "lastSeenTimestamp": "2026-09-14 01:00:00",
   "recommendationReference": "va-_-ivanti-_-connect_secure", "recommendedSecurityUpdate": "22.7R2.5"},
  {"deviceId": "m1", "deviceName": "vpn-gw-01.corp.example", "rbacGroupName": "Perimeter", "softwareVendor": "ivanti", "softwareName": "connect_secure", "softwareVersion": "22.7R2.1",
   "cveId": "CVE-2025-46512", "vulnerabilitySeverityLevel": "High", "cvssScore": 8.2, "exploitabilityLevel": "ExploitIsPublic", "firstSeenTimestamp": "2026-06-01 01:00:00", "lastSeenTimestamp": "2026-09-14 01:00:00",
   "recommendationReference": "va-_-ivanti-_-connect_secure", "recommendedSecurityUpdate": "22.7R2.5"},
  {"deviceId": "m2", "deviceName": "ws-finance-114.corp.example", "rbacGroupName": "Workstations", "softwareVendor": "adobe", "softwareName": "acrobat_reader_dc", "softwareVersion": "24.002.20000",
   "cveId": "CVE-2026-24433", "vulnerabilitySeverityLevel": "Critical", "cvssScore": 8.6, "exploitabilityLevel": "NoExploit", "firstSeenTimestamp": "2026-09-01 01:00:00", "lastSeenTimestamp": "2026-09-14 01:00:00",
   "recommendationReference": "va-_-adobe-_-acrobat_reader_dc", "recommendedSecurityUpdate": "24.003.20112"},
  {"deviceId": "m3", "deviceName": "dc-01.corp.example", "rbacGroupName": "Servers", "softwareVendor": "microsoft", "softwareName": "windows_server_2019", "softwareVersion": "10.0.17763.6000",
   "cveId": "CVE-2026-21335", "vulnerabilitySeverityLevel": "Critical", "cvssScore": 8.8, "exploitabilityLevel": "ExploitIsVerified", "firstSeenTimestamp": "2026-09-10 01:00:00", "lastSeenTimestamp": "2026-09-14 01:00:00",
   "recommendationReference": "va-_-microsoft-_-windows_server_2019", "recommendedSecurityUpdate": "September 2026 Security Updates"},
  {"deviceId": "m3", "deviceName": "dc-01.corp.example", "rbacGroupName": "Servers", "softwareVendor": "microsoft", "softwareName": "edge", "softwareVersion": "128.0",
   "cveId": null, "vulnerabilitySeverityLevel": null, "cvssScore": null, "exploitabilityLevel": "NoExploit", "firstSeenTimestamp": "2026-09-10 01:00:00", "lastSeenTimestamp": "2026-09-14 01:00:00",
   "recommendationReference": "va-_-microsoft-_-edge"}
]}
```
`tests/fixtures/mde/recommendations.json`:
```json
{"value": [
  {"id": "va-_-ivanti-_-connect_secure", "productName": "connect_secure", "vendor": "ivanti", "recommendationName": "Update Ivanti Connect Secure to version 22.7R2.5", "recommendedVersion": "22.7R2.5", "remediationType": "Update", "publicExploit": true, "exposedMachinesCount": 6, "totalMachineCount": 6, "weaknesses": 26},
  {"id": "va-_-adobe-_-acrobat_reader_dc", "productName": "acrobat_reader_dc", "vendor": "adobe", "recommendationName": "Update Adobe Acrobat Reader DC", "recommendedVersion": "24.003.20112", "remediationType": "Update", "publicExploit": false, "exposedMachinesCount": 1140, "totalMachineCount": 1200, "weaknesses": 46}
]}
```
`tests/fixtures/mde/exposure.json`: `{"score": 54.2}` and the by-group fixture is inline in the test.

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_mde.py
import json
from pathlib import Path
from dva.mde import collect_machines, collect_vulns, collect_recommendations, collect_score, MDE_BASE
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
    import pytest
    from dva.errors import DvaError
    with pytest.raises(DvaError):
        collect_recommendations(c, run)
    assert run.manifest["sources"]["mde.recommendations"]["status"] == "failed"
```

- [ ] **Step 3: Run to verify fail** → `pytest tests/test_mde.py -v` → FAIL.

- [ ] **Step 4: Implement**

```python
# dva/mde.py
from __future__ import annotations
import json
from pathlib import Path
from dva.auth import TokenProvider, MDE_SCOPE
from dva.errors import DvaError
from dva.http import Client
from dva.run import Run, add_run_arg, resolve_run, cache_dir

MDE_BASE = "https://api.securitycenter.microsoft.com/api"


def make_client(scope: str = MDE_SCOPE, base_url: str = MDE_BASE) -> Client:
    return Client(TokenProvider.from_env(cache_dir()), scope, base_url=base_url)


def _guard(run: Run, source: str):
    """Context manager: marks the source failed in the manifest if the body raises."""
    class _G:
        def __enter__(self): return self
        def __exit__(self, et, ev, tb):
            if ev is not None:
                run.set_source(source, "failed", error=str(ev)); run.log(f"{source} failed: {ev}")
            return False
    return _G()


def _norm_machine(m: dict) -> dict:
    vm = m.get("vmMetadata") or {}
    return {
        "id": m["id"], "name": m.get("computerDnsName"), "os_platform": m.get("osPlatform"), "os_version": m.get("version"),
        "health": m.get("healthStatus"), "exposure_level": m.get("exposureLevel"), "device_value": m.get("deviceValue"),
        "tags": list(m.get("machineTags") or []), "group": m.get("rbacGroupName"), "last_seen": m.get("lastSeen"),
        "aad_device_id": m.get("aadDeviceId"), "azure_resource_id": vm.get("resourceId"), "is_internet_facing": m.get("isInternetFacing"),
    }


def _norm_vuln(v: dict) -> dict:
    return {
        "device_id": v["deviceId"], "device_name": v.get("deviceName"), "vendor": v.get("softwareVendor"), "product": v.get("softwareName"),
        "version": v.get("softwareVersion"), "cve_id": v["cveId"], "severity": v.get("vulnerabilitySeverityLevel"), "cvss": v.get("cvssScore"),
        "exploitability": v.get("exploitabilityLevel") or "NoExploit", "first_seen": v.get("firstSeenTimestamp"), "last_seen": v.get("lastSeenTimestamp"),
        "recommendation_ref": v.get("recommendationReference"), "security_update": v.get("recommendedSecurityUpdate"), "group": v.get("rbacGroupName"),
    }


def _norm_rec(r: dict) -> dict:
    return {
        "id": r["id"], "vendor": r.get("vendor"), "product": r.get("productName"), "name": r.get("recommendationName"),
        "recommended_version": r.get("recommendedVersion"), "remediation_type": r.get("remediationType"), "public_exploit": bool(r.get("publicExploit")),
        "exposed_machines": r.get("exposedMachinesCount"), "total_machines": r.get("totalMachineCount"), "weaknesses": r.get("weaknesses"),
    }


def collect_machines(client: Client, run: Run) -> int:
    with _guard(run, "mde.machines"):
        machines = [_norm_machine(m) for m in client.paged("/machines", {"$top": 10000})]
        run.write_json("machines.json", machines)
        run.set_source("mde.machines", "ok", count=len(machines))
        run.summary(f"MDE machines: {len(machines)} devices collected.")
        return len(machines)


def collect_vulns(client: Client, run: Run, page_size: int = 50000) -> int:
    with _guard(run, "mde.vulns"):
        rows = (_norm_vuln(v) for v in client.paged("/machines/SoftwareVulnerabilitiesByMachine", {"pageSize": page_size}) if v.get("cveId"))
        n = run.write_jsonl("vulns.jsonl", rows)
        run.set_source("mde.vulns", "ok", count=n)
        run.summary(f"MDE vulnerabilities: {n} device/software/CVE rows written to vulns.jsonl.")
        return n


def collect_recommendations(client: Client, run: Run) -> int:
    with _guard(run, "mde.recommendations"):
        recs = [_norm_rec(r) for r in client.paged("/recommendations")]
        run.write_json("recommendations.json", recs)
        run.set_source("mde.recommendations", "ok", count=len(recs))
        run.summary(f"MDE recommendations: {len(recs)} collected.")
        return len(recs)


def collect_score(client: Client, run: Run) -> None:
    with _guard(run, "mde.score"):
        score = client.get_json("/exposureScore").get("score")
        groups = {g.get("rbacGroupName"): g.get("score") for g in client.get_json("/exposureScore/ByMachineGroups").get("value", [])}
        run.write_json("exposure.json", {"score": score, "by_group": groups})
        run.set_source("mde.score", "ok", count=1)
        run.summary(f"MDE exposure score: {score}.")


class _FixtureSession:
    """Serves canned pages from a JSON file for --fixture runs (a list = pages, in order)."""
    def __init__(self, path: Path):
        data = json.loads(Path(path).read_text())
        self.pages = data if isinstance(data, list) else [data]
    def request(self, method, url, **kw):
        from tests.fakes import FakeResponse  # test helper is fine for offline mode
        return FakeResponse(200, self.pages.pop(0) if len(self.pages) > 1 else self.pages[0])


def _client_for(args) -> Client:
    if getattr(args, "fixture", None):
        from tests.fakes import FakeTokens
        return Client(FakeTokens(), MDE_SCOPE, base_url=MDE_BASE, session=_FixtureSession(args.fixture))
    return make_client()


def register(sub) -> None:
    p = sub.add_parser("mde", help="Collect from the Defender for Endpoint API")
    s = p.add_subparsers(dest="mde_cmd", required=True)
    for name, fn in [("machines", collect_machines), ("vulns", collect_vulns), ("recommendations", collect_recommendations), ("score", collect_score)]:
        q = s.add_parser(name); add_run_arg(q); q.add_argument("--fixture"); q.set_defaults(func=lambda a, fn=fn: fn(_client_for(a), resolve_run(a)) and 0)
    a = s.add_parser("all"); add_run_arg(a); a.add_argument("--fixture")
    def _all(args):
        run, c = resolve_run(args), _client_for(args)
        failures = 0
        for fn in (collect_machines, collect_vulns, collect_recommendations, collect_score):
            try: fn(c, run)
            except DvaError as e: failures += 1; print(f"warning: {e}")
        return 1 if failures == 4 else 0
    a.set_defaults(func=_all)
```

Note: `_guard` returns a small context manager so a failing collector records `failed` in the manifest and re-raises, which `mde all` catches per source (the spec: one source failing does not abort the run).

- [ ] **Step 5: Run tests** → `pytest tests/test_mde.py -v` → 4 passed.
- [ ] **Step 6: Commit** → `git add dva/mde.py tests/test_mde.py tests/fixtures/mde && git commit -m "feat: MDE collectors for machines, vulnerabilities, recommendations and score"`

---

### Task 7: Advanced Hunting client and query library

**Files:**
- Create: `dva/hunting.py`, `dva/queries/internet-facing.kql`, `dva/queries/exploited-cves.kql`, `dva/queries/device-tags.kql`, `dva/queries/vuln-counts-by-device.kql`, `dva/queries/product-versions.kql`, `tests/test_hunting.py`

**Interfaces:**
- Consumes: `Client`, `Run`, `GRAPH_SCOPE`.
- Produces: `dva.hunting.GRAPH_BASE = "https://graph.microsoft.com/v1.0"`, `ROW_CAP = 10000`, `load_query(name) -> str`, `run_query(client, run, name, kql, timespan="P7D") -> dict` posting `{"Query": kql, "Timespan": timespan}` to `/security/runHuntingQuery`, writing `hunt-<name>.json` as `{"schema": [...], "results": [...], "capped": bool}`, marking the source `hunting.<name>` `ok` or `partial` (when `len(results) >= ROW_CAP`). `run_named(client, run, names)`. CLI: `dva hunt <name>... [--run] [--fixture FILE]` and `dva hunt --kql "<text>" --name adhoc`. Ad hoc KQL is rejected with `DvaError` if it contains any of the tokens `.set`, `.create`, `.drop`, `.alter`, `.ingest`, `externaldata` (case-insensitive); it is read-only by API contract anyway, this is a guard against mistakes.

Named queries (each ends with `| take 10000`-style capping is NOT used; the API caps at 10k and we detect it):

`dva/queries/internet-facing.kql`:
```kusto
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, IsInternetFacing, PublicIP, ExposureLevel, AssetValue, DeviceManualTags, DeviceDynamicTags, MachineGroup, AzureResourceId, DeviceName) by DeviceId
| where IsInternetFacing == true
| project DeviceId, DeviceName, PublicIP, ExposureLevel, AssetValue, MachineGroup, AzureResourceId
```
`dva/queries/device-tags.kql`:
```kusto
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, DeviceName, ExposureLevel, AssetValue, DeviceManualTags, DeviceDynamicTags, MachineGroup, AzureResourceId, IsInternetFacing) by DeviceId
| project DeviceId, DeviceName, ExposureLevel, AssetValue, DeviceManualTags, DeviceDynamicTags, MachineGroup, AzureResourceId, IsInternetFacing
```
`dva/queries/exploited-cves.kql`:
```kusto
DeviceTvmSoftwareVulnerabilitiesKB
| where IsExploitAvailable == true
| project CveId, CvssScore, VulnerabilitySeverityLevel, PublishedDate, VulnerabilityDescription
```
`dva/queries/vuln-counts-by-device.kql`:
```kusto
DeviceTvmSoftwareVulnerabilities
| summarize Critical = countif(VulnerabilitySeverityLevel == "Critical"), High = countif(VulnerabilitySeverityLevel == "High"),
            Medium = countif(VulnerabilitySeverityLevel == "Medium"), Low = countif(VulnerabilitySeverityLevel == "Low") by DeviceId, DeviceName
```
`dva/queries/product-versions.kql`:
```kusto
DeviceTvmSoftwareInventory
| summarize Devices = dcount(DeviceId) by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus
| order by Devices desc
```

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_hunting.py
import pytest
from dva.hunting import run_query, load_query, GRAPH_BASE, ROW_CAP, check_kql_is_readonly
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
    assert body["Query"].startswith("DeviceInfo") and body["Timespan"] == "P7D"
    assert run.manifest["sources"]["hunting.internet-facing"]["status"] == "ok"

def test_row_cap_marks_partial(tmp_path):
    run = Run.create(tmp_path)
    c = client(FakeResponse(200, {"schema": [], "results": [{"i": n} for n in range(ROW_CAP)]}))
    out = run_query(c, run, "big", "DeviceInfo")
    assert out["capped"] is True
    assert run.manifest["sources"]["hunting.big"]["status"] == "partial"

def test_readonly_guard():
    with pytest.raises(DvaError):
        check_kql_is_readonly(".create table X")
    check_kql_is_readonly("DeviceInfo | take 1")
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/hunting.py
from __future__ import annotations
import re
from pathlib import Path
from dva.auth import GRAPH_SCOPE
from dva.errors import DvaError
from dva.http import Client
from dva.run import Run, add_run_arg, resolve_run

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
ROW_CAP = 10000
QUERY_DIR = Path(__file__).parent / "queries"
_FORBIDDEN = re.compile(r"(\.set\b|\.create\b|\.drop\b|\.alter\b|\.ingest\b|externaldata)", re.I)


def load_query(name: str) -> str:
    p = QUERY_DIR / f"{name}.kql"
    if not p.exists():
        raise DvaError(f"unknown hunting query '{name}'; available: {', '.join(sorted(q.stem for q in QUERY_DIR.glob('*.kql')))}")
    return p.read_text(encoding="utf-8")


def check_kql_is_readonly(kql: str) -> None:
    if _FORBIDDEN.search(kql):
        raise DvaError("KQL contains a management or ingestion command; only read-only queries are allowed")


def run_query(client: Client, run: Run, name: str, kql: str, timespan: str = "P7D") -> dict:
    check_kql_is_readonly(kql)
    source = f"hunting.{name}"
    try:
        resp = client.post_json("/security/runHuntingQuery", {"Query": kql, "Timespan": timespan})
    except DvaError as e:
        run.set_source(source, "failed", error=str(e)); run.log(f"{source} failed: {e}"); raise
    results = resp.get("results", [])
    capped = len(results) >= ROW_CAP
    out = {"schema": resp.get("schema", []), "results": results, "capped": capped}
    run.write_json(f"hunt-{name}.json", out)
    run.set_source(source, "partial" if capped else "ok", count=len(results), error="hit 10,000 row cap; narrow the query" if capped else None)
    run.summary(f"Hunting {name}: {len(results)} rows" + (" (CAPPED at 10,000; results are partial)" if capped else "") + ".")
    return out


def run_named(client: Client, run: Run, names: list[str]) -> int:
    failures = 0
    for n in names:
        try:
            run_query(client, run, n, load_query(n))
        except DvaError as e:
            failures += 1; print(f"warning: {e}")
    return failures


def _client(args) -> Client:
    if getattr(args, "fixture", None):
        from dva.mde import _FixtureSession
        from tests.fakes import FakeTokens
        return Client(FakeTokens(), GRAPH_SCOPE, base_url=GRAPH_BASE, session=_FixtureSession(args.fixture))
    from dva.mde import make_client
    return make_client(GRAPH_SCOPE, GRAPH_BASE)


def register(sub) -> None:
    p = sub.add_parser("hunt", help="Run Advanced Hunting queries")
    add_run_arg(p)
    p.add_argument("names", nargs="*", help="named queries from dva/queries")
    p.add_argument("--kql", help="ad hoc KQL (read-only)")
    p.add_argument("--name", default="adhoc", help="output name for --kql")
    p.add_argument("--timespan", default="P7D")
    p.add_argument("--fixture")
    def _run(args):
        run, c = resolve_run(args), _client(args)
        if args.kql:
            run_query(c, run, args.name, args.kql, args.timespan); return 0
        if not args.names:
            raise DvaError("give query names or --kql")
        return 1 if run_named(c, run, args.names) == len(args.names) else 0
    p.set_defaults(func=_run)
```

- [ ] **Step 4: Run tests** → 4 passed.
- [ ] **Step 5: Commit** → `git add dva/hunting.py dva/queries tests/test_hunting.py && git commit -m "feat: Advanced Hunting client with named query library and row-cap detection"`

---

### Task 8: Doctor

**Files:**
- Modify: `dva/doctor.py` (replace placeholder)
- Create: `tests/test_doctor.py`

**Interfaces:**
- Consumes: `Client`, `TokenProvider.from_env`, scopes, `load_sources`.
- Produces: `dva.doctor.checks(sources) -> list[Check]` where `Check(api, permission, scope, base_url, method, path, body)`; `run_checks(checks, client_factory) -> list[tuple[Check, bool, str]]`; `format_table(results) -> str`. CLI `dva doctor` prints the table and exits 1 if any check for an enabled source fails. `client_factory(scope, base_url) -> Client`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_doctor.py
from dva.doctor import checks, run_checks, format_table
from dva.config import Sources
from dva.http import Client
from tests.fakes import FakeSession, FakeResponse, FakeTokens

def test_checks_cover_phase1_permissions():
    names = {c.permission for c in checks(Sources(mde=True, hunting=True, cloud=False))}
    assert names == {"Machine.Read.All", "Vulnerability.Read.All", "Software.Read.All", "SecurityRecommendation.Read.All", "Score.Read.All", "ThreatHunting.Read.All"}

def test_run_checks_reports_pass_and_fail():
    cs = checks(Sources(mde=True, hunting=True))
    def factory(scope, base_url):
        routes = {f"{c.method} {c.base_url}{c.path}": [FakeResponse(403 if c.permission == "Score.Read.All" else 200, {"value": []})] for c in cs}
        return Client(FakeTokens(), scope, base_url=base_url, session=FakeSession(routes), sleep=lambda s: None, max_attempts=1)
    results = run_checks(cs, factory)
    status = {c.permission: ok for c, ok, _ in results}
    assert status["Machine.Read.All"] is True and status["Score.Read.All"] is False
    table = format_table(results)
    assert "FAIL" in table and "Score.Read.All" in table
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/doctor.py
from __future__ import annotations
from dataclasses import dataclass
from dva.auth import MDE_SCOPE, GRAPH_SCOPE, ARM_SCOPE
from dva.config import load_sources, Sources
from dva.errors import DvaError


@dataclass(frozen=True)
class Check:
    api: str
    permission: str
    scope: str
    base_url: str
    method: str
    path: str
    body: dict | None = None
    params: dict | None = None


def checks(sources: Sources) -> list[Check]:
    from dva.mde import MDE_BASE
    from dva.hunting import GRAPH_BASE
    out: list[Check] = []
    if sources.mde:
        out += [
            Check("MDE", "Machine.Read.All", MDE_SCOPE, MDE_BASE, "GET", "/machines", params={"$top": 1}),
            Check("MDE", "Vulnerability.Read.All", MDE_SCOPE, MDE_BASE, "GET", "/vulnerabilities", params={"$top": 1}),
            Check("MDE", "Software.Read.All", MDE_SCOPE, MDE_BASE, "GET", "/software", params={"$top": 1}),
            Check("MDE", "SecurityRecommendation.Read.All", MDE_SCOPE, MDE_BASE, "GET", "/recommendations", params={"$top": 1}),
            Check("MDE", "Score.Read.All", MDE_SCOPE, MDE_BASE, "GET", "/exposureScore"),
        ]
    if sources.hunting:
        out.append(Check("Graph", "ThreatHunting.Read.All", GRAPH_SCOPE, GRAPH_BASE, "POST", "/security/runHuntingQuery", body={"Query": "DeviceInfo | take 1"}))
    for sub in (sources.subscriptions if sources.cloud else []):
        out.append(Check("ARM", f"Reader ({sub})", ARM_SCOPE, "https://management.azure.com", "POST",
                         "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01",
                         body={"subscriptions": [sub], "query": "securityresources | take 1"}))
    return out


def run_checks(cs: list[Check], client_factory) -> list[tuple[Check, bool, str]]:
    results = []
    for c in cs:
        client = client_factory(c.scope, c.base_url)
        try:
            if c.method == "GET":
                client.get_json(c.path, c.params)
            else:
                client.post_json(c.path, c.body or {})
            results.append((c, True, f"{c.method} {c.path}"))
        except DvaError as e:
            results.append((c, False, str(e)))
    return results


def format_table(results) -> str:
    lines = []
    for c, ok, detail in results:
        lines.append(f"{c.api:<6}{c.permission:<34}{'ok  ' if ok else 'FAIL'} {detail}")
    return "\n".join(lines)


def register(sub) -> None:
    p = sub.add_parser("doctor", help="Check credentials and permissions")
    p.set_defaults(func=run)


def run(args) -> int:
    from dva.mde import make_client
    from dva.http import Client
    def factory(scope, base_url):
        c = make_client(scope, base_url); c.max_attempts = 2; return c
    results = run_checks(checks(load_sources()), factory)
    print(format_table(results))
    failed = [c.permission for c, ok, _ in results if not ok]
    if failed:
        print(f"doctor: {len(failed)} check(s) failed: {', '.join(failed)}. See setup/permissions.md.")
        return 1
    print("doctor: all checks passed.")
    return 0
```

- [ ] **Step 4: Run tests** → `pytest tests/test_doctor.py tests/test_cli.py -v` → passed.
- [ ] **Step 5: Commit** → `git add dva/doctor.py tests/test_doctor.py && git commit -m "feat: doctor command checks every required permission"`

---

### Task 9: Model and product roll-up

**Files:**
- Create: `dva/model.py`, `dva/rollup.py`, `tests/test_rollup.py`

**Interfaces:**
- Consumes: run files `machines.json`, `vulns.jsonl`, `recommendations.json`, optional `hunt-internet-facing.json`, `hunt-device-tags.json`, `hunt-exploited-cves.json`.
- Produces (`dva/model.py`):
  ```python
  @dataclass class Asset: id: str; name: str; kind: str  # "device" | "image"
      internet_facing: bool; exposure_level: str | None; device_value: str | None; tags: list[str]; group: str | None; public_lb: bool = False
  @dataclass class CveRef: id: str; severity: str; cvss: float; exploitability: str; first_seen: str | None
  @dataclass class Product: key: str; vendor: str; name: str; versions: dict[str,int]; cves: dict[str, CveRef]; asset_ids: set[str]
      remediation: str | None; remediation_type: str | None; recommended_version: str | None
  ```
  and `product_key(vendor, name) -> str` (lowercase, whitespace and underscores collapsed to one hyphen, e.g. `ivanti/connect-secure`). `dva/rollup.py`: `build(run) -> tuple[dict[str, Product], dict[str, Asset]]`; `display_name(product) -> str` (title-cased words, e.g. `Connect Secure`), `display_vendor(product) -> str`.
  Asset context merges MDE machine fields with hunting rows: internet-facing from `hunt-internet-facing.json` device ids or MDE `is_internet_facing`; exposure level and device value from MDE, falling back to hunting `ExposureLevel`/`AssetValue`; tags = MDE tags ∪ hunting `DeviceManualTags`/`DeviceDynamicTags` split on `,`. Exploitability is upgraded to at least `ExploitIsPublic` for CVEs listed in `hunt-exploited-cves.json`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_rollup.py
from dva.run import Run
from dva.rollup import build, display_name
from dva.model import product_key

def seed(tmp_path):
    run = Run.create(tmp_path)
    run.write_json("machines.json", [
        {"id": "m1", "name": "vpn-gw-01", "exposure_level": "High", "device_value": "High", "tags": ["Tier0"], "group": "Perimeter", "is_internet_facing": None, "azure_resource_id": None},
        {"id": "m2", "name": "ws-114", "exposure_level": "Medium", "device_value": "Normal", "tags": [], "group": "Workstations", "is_internet_facing": None, "azure_resource_id": None},
    ])
    run.write_jsonl("vulns.jsonl", [
        {"device_id": "m1", "device_name": "vpn-gw-01", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.1", "cve_id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "exploitability": "ExploitIsInKit", "first_seen": "2026-09-08", "recommendation_ref": "va-_-ivanti-_-connect_secure"},
        {"device_id": "m1", "device_name": "vpn-gw-01", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.1", "cve_id": "CVE-2025-46512", "severity": "High", "cvss": 8.2, "exploitability": "NoExploit", "first_seen": "2026-06-01", "recommendation_ref": "va-_-ivanti-_-connect_secure"},
        {"device_id": "m2", "device_name": "ws-114", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.0", "cve_id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "exploitability": "ExploitIsInKit", "first_seen": "2026-09-09", "recommendation_ref": "va-_-ivanti-_-connect_secure"},
        {"device_id": "m2", "device_name": "ws-114", "vendor": "adobe", "product": "acrobat_reader_dc", "version": "24.0", "cve_id": "CVE-2026-24433", "severity": "Critical", "cvss": 8.6, "exploitability": "NoExploit", "first_seen": "2026-09-01", "recommendation_ref": "va-_-adobe-_-acrobat_reader_dc"},
    ])
    run.write_json("recommendations.json", [{"id": "va-_-ivanti-_-connect_secure", "vendor": "ivanti", "product": "connect_secure", "name": "Update Ivanti Connect Secure to 22.7R2.5", "recommended_version": "22.7R2.5", "remediation_type": "Update"}])
    run.write_json("hunt-internet-facing.json", {"results": [{"DeviceId": "m1", "PublicIP": "1.2.3.4"}]})
    run.write_json("hunt-device-tags.json", {"results": [{"DeviceId": "m2", "DeviceManualTags": "Prod,Finance", "DeviceDynamicTags": "", "ExposureLevel": "Medium", "AssetValue": "Normal"}]})
    run.write_json("hunt-exploited-cves.json", {"results": [{"CveId": "CVE-2025-46512"}]})
    return run

def test_products_and_assets(tmp_path):
    products, assets = build(seed(tmp_path))
    ics = products[product_key("ivanti", "connect_secure")]
    assert set(ics.cves) == {"CVE-2026-21887", "CVE-2025-46512"} and ics.asset_ids == {"m1", "m2"}
    assert ics.versions == {"22.7R2.1": 1, "22.7R2.0": 1}
    assert ics.recommended_version == "22.7R2.5" and ics.remediation.startswith("Update Ivanti")
    assert ics.cves["CVE-2025-46512"].exploitability == "ExploitIsPublic"  # upgraded from hunting KB
    assert display_name(ics) == "Connect Secure"
    assert assets["m1"].internet_facing is True and assets["m1"].tags == ["Tier0"]
    assert assets["m2"].internet_facing is False and sorted(assets["m2"].tags) == ["Finance", "Prod"]
    adobe = products[product_key("adobe", "acrobat_reader_dc")]
    assert adobe.remediation is None and adobe.asset_ids == {"m2"}
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/model.py
from __future__ import annotations
import re
from dataclasses import dataclass, field

EXPLOIT_RANK = {"NoExploit": 0, "ExploitIsPublic": 1, "ExploitIsVerified": 2, "ExploitIsInKit": 3}
SEVERITIES = ("Critical", "High", "Medium", "Low")


def product_key(vendor: str | None, name: str | None) -> str:
    def norm(s): return re.sub(r"[\s_]+", "-", (s or "unknown").strip().lower())
    return f"{norm(vendor)}/{norm(name)}"


@dataclass
class Asset:
    id: str
    name: str
    kind: str = "device"
    internet_facing: bool = False
    exposure_level: str | None = None
    device_value: str | None = None
    tags: list[str] = field(default_factory=list)
    group: str | None = None
    public_lb: bool = False


@dataclass
class CveRef:
    id: str
    severity: str
    cvss: float
    exploitability: str
    first_seen: str | None


@dataclass
class Product:
    key: str
    vendor: str
    name: str
    versions: dict[str, int] = field(default_factory=dict)
    cves: dict[str, CveRef] = field(default_factory=dict)
    asset_ids: set[str] = field(default_factory=set)
    remediation: str | None = None
    remediation_type: str | None = None
    recommended_version: str | None = None
```

```python
# dva/rollup.py
from __future__ import annotations
from dva.model import Asset, CveRef, Product, product_key, EXPLOIT_RANK
from dva.run import Run


def _hunt(run: Run, name: str) -> list[dict]:
    p = run.path(f"hunt-{name}.json")
    if not p.exists():
        return []
    return run.read_json(f"hunt-{name}.json").get("results", [])


def _split_tags(s) -> list[str]:
    return [t.strip() for t in (s or "").split(",") if t.strip()]


def build(run: Run) -> tuple[dict[str, Product], dict[str, Asset]]:
    assets: dict[str, Asset] = {}
    for m in run.read_json("machines.json"):
        assets[m["id"]] = Asset(id=m["id"], name=m.get("name") or m["id"], internet_facing=bool(m.get("is_internet_facing")),
                                exposure_level=m.get("exposure_level"), device_value=m.get("device_value"),
                                tags=list(m.get("tags") or []), group=m.get("group"))
    for row in _hunt(run, "device-tags"):
        a = assets.setdefault(row["DeviceId"], Asset(id=row["DeviceId"], name=row.get("DeviceName") or row["DeviceId"]))
        a.exposure_level = a.exposure_level or row.get("ExposureLevel")
        a.device_value = a.device_value or row.get("AssetValue")
        for t in _split_tags(row.get("DeviceManualTags")) + _split_tags(row.get("DeviceDynamicTags")):
            if t not in a.tags:
                a.tags.append(t)
        if row.get("IsInternetFacing"):
            a.internet_facing = True
    for row in _hunt(run, "internet-facing"):
        a = assets.setdefault(row["DeviceId"], Asset(id=row["DeviceId"], name=row.get("DeviceName") or row["DeviceId"]))
        a.internet_facing = True

    exploited = {r["CveId"] for r in _hunt(run, "exploited-cves")}
    recs = {}
    for r in run.read_json("recommendations.json") if run.path("recommendations.json").exists() else []:
        recs[product_key(r.get("vendor"), r.get("product"))] = r

    products: dict[str, Product] = {}
    for v in run.read_jsonl("vulns.jsonl"):
        key = product_key(v.get("vendor"), v.get("product"))
        p = products.get(key)
        if p is None:
            rec = recs.get(key)
            p = products[key] = Product(key=key, vendor=v.get("vendor") or "unknown", name=v.get("product") or "unknown",
                                        remediation=rec.get("name") if rec else None, remediation_type=rec.get("remediation_type") if rec else None,
                                        recommended_version=rec.get("recommended_version") if rec else None)
        p.asset_ids.add(v["device_id"])
        if v.get("version"):
            p.versions[v["version"]] = p.versions.get(v["version"], 0) + 1
        expl = v.get("exploitability") or "NoExploit"
        if v["cve_id"] in exploited and EXPLOIT_RANK.get(expl, 0) < 1:
            expl = "ExploitIsPublic"
        cur = p.cves.get(v["cve_id"])
        ref = CveRef(id=v["cve_id"], severity=v.get("severity") or "Low", cvss=float(v.get("cvss") or 0.0), exploitability=expl, first_seen=v.get("first_seen"))
        if cur is None or EXPLOIT_RANK[ref.exploitability] > EXPLOIT_RANK[cur.exploitability] or ref.cvss > cur.cvss:
            p.cves[v["cve_id"]] = ref
        if v["device_id"] not in assets:
            assets[v["device_id"]] = Asset(id=v["device_id"], name=v.get("device_name") or v["device_id"], group=v.get("group"))
    return products, assets


def display_name(p: Product) -> str:
    return " ".join(w.upper() if w.lower() in {"dc", "ems", "ssh", "sql", "vpn"} else w.capitalize() for w in p.name.replace("_", " ").split())


def display_vendor(p: Product) -> str:
    return p.vendor.replace("_", " ").title()
```

Note: `versions` counts device rows per version, which is what the report's version breakdown needs; a device appears once per version it runs.

- [ ] **Step 4: Run tests** → `pytest tests/test_rollup.py -v` → passed.
- [ ] **Step 5: Commit** → `git add dva/model.py dva/rollup.py tests/test_rollup.py && git commit -m "feat: roll findings up to products and assets with hunting context"`

---

### Task 10: Scoring

**Files:**
- Create: `dva/scoring.py`, `tests/test_scoring.py`

**Interfaces:**
- Consumes: `Scoring` config, `Product`, `Asset`, `CveRef`, `EXPLOIT_RANK`.
- Produces:
  ```python
  @dataclass class CveIntel: cvss: float | None; epss: float | None; epss_percentile: float | None; kev: bool; kev_added: str | None
      ransomware: bool; exploit_public: bool; exploit_sources: list[str]; title: str | None; cwe: str | None; fetched_at: str | None
  def threat_score(ref: CveRef, intel: CveIntel | None, cfg: Scoring) -> float          # 0..1
  def asset_multiplier(asset: Asset, cfg: Scoring) -> float                            # 1.0..cfg.asset_cap
  def product_score(p: Product, assets: dict[str, Asset], intel: dict[str, CveIntel], cfg: Scoring, estate_size: int) -> ScoredProduct
  @dataclass class ScoredProduct: product: Product; score: int; label: str; driving: list[tuple[CveRef, float]]  # top 3 by threat, desc
      counts: dict[str,int]; asset_mean: float; reach: float; flags: dict[str,bool]; top_assets: list[tuple[Asset, float, str]]  # (asset, multiplier, why)
  def label_for(score: int, cfg: Scoring) -> str
  def reason_for(sp: ScoredProduct) -> str
  ```
  Exploit term for a CVE with no intel: `{"NoExploit": 0, "ExploitIsPublic": 0.5, "ExploitIsVerified": 0.75, "ExploitIsInKit": 1.0}[exploitability]`. With intel: `1.0` if `intel.exploit_public` else the Defender value. `why` for an asset joins the applicable signals with ` · `: `Internet-facing`, `Tier0` (each matching tag), `High value`, `Exposure High`, `Public LoadBalancer`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scoring.py
from dva.config import load_scoring
from dva.model import Asset, CveRef, Product
from dva.scoring import threat_score, asset_multiplier, product_score, CveIntel, label_for, reason_for

cfg = load_scoring()

def ref(id="CVE-1", cvss=9.8, expl="NoExploit", sev="Critical"):
    return CveRef(id=id, severity=sev, cvss=cvss, exploitability=expl, first_seen=None)

def test_threat_without_intel_uses_defender_fields():
    assert abs(threat_score(ref(cvss=10.0), None, cfg) - 0.35) < 1e-9
    assert abs(threat_score(ref(cvss=10.0, expl="ExploitIsInKit"), None, cfg) - 0.50) < 1e-9

def test_threat_with_intel():
    intel = CveIntel(cvss=9.8, epss=0.94, epss_percentile=0.99, kev=True, kev_added=None, ransomware=False, exploit_public=True, exploit_sources=["exploit-db"], title="t", cwe=None, fetched_at=None)
    t = threat_score(ref(), intel, cfg)
    assert abs(t - (0.35 * 0.98 + 0.25 * 0.99 + 0.25 + 0.15)) < 1e-9

def test_asset_multiplier_bonuses_and_cap():
    a = Asset(id="a", name="a", internet_facing=True, exposure_level="High", device_value="High", tags=["Tier0", "Prod"])
    assert asset_multiplier(a, cfg) == cfg.asset_cap  # 1 + .6 + .4 + .4 + .5 > cap
    b = Asset(id="b", name="b", exposure_level="Medium")
    assert abs(asset_multiplier(b, cfg) - 1.2) < 1e-9

def test_product_score_ranks_kev_gateway_above_fleet_mediums():
    gw = Product(key="ivanti/connect-secure", vendor="ivanti", name="connect_secure", asset_ids={"a"}, cves={"CVE-1": ref(expl="ExploitIsInKit")})
    fleet = Product(key="x/y", vendor="x", name="y", asset_ids={f"d{i}" for i in range(300)}, cves={f"CVE-{i}": ref(id=f"CVE-{i}", cvss=5.5, sev="Medium") for i in range(20)})
    assets = {"a": Asset(id="a", name="gw", internet_facing=True, tags=["Tier0"])}
    assets.update({f"d{i}": Asset(id=f"d{i}", name=f"d{i}") for i in range(300)})
    intel = {"CVE-1": CveIntel(cvss=9.8, epss=0.9, epss_percentile=0.99, kev=True, kev_added=None, ransomware=False, exploit_public=True, exploit_sources=[], title=None, cwe=None, fetched_at=None)}
    s_gw = product_score(gw, assets, intel, cfg, estate_size=2000)
    s_fleet = product_score(fleet, assets, {}, cfg, estate_size=2000)
    assert s_gw.score > s_fleet.score and s_gw.label == "Critical"
    assert s_gw.flags == {"kev": True, "exploit": True, "internet_facing": True}
    assert s_gw.top_assets[0][2] == "Internet-facing · Tier0"
    assert s_fleet.counts == {"critical": 0, "high": 0, "medium": 20, "low": 0}
    assert len(s_gw.driving) == 1 and len(s_fleet.driving) == 3

def test_label_and_reason():
    assert label_for(80, cfg) == "Critical" and label_for(59, cfg) == "Medium" and label_for(10, cfg) == "Low"
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/scoring.py
from __future__ import annotations
import math
from dataclasses import dataclass, field
from dva.config import Scoring
from dva.model import Asset, CveRef, Product, EXPLOIT_RANK, SEVERITIES

_EXPLOIT_TERM = {"NoExploit": 0.0, "ExploitIsPublic": 0.5, "ExploitIsVerified": 0.75, "ExploitIsInKit": 1.0}


@dataclass
class CveIntel:
    cvss: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_added: str | None = None
    ransomware: bool = False
    exploit_public: bool = False
    exploit_sources: list[str] = field(default_factory=list)
    title: str | None = None
    cwe: str | None = None
    fetched_at: str | None = None


@dataclass
class ScoredProduct:
    product: Product
    score: int
    label: str
    driving: list[tuple[CveRef, float]]
    counts: dict[str, int]
    asset_mean: float
    reach: float
    flags: dict[str, bool]
    top_assets: list[tuple[Asset, float, str]]


def threat_score(ref: CveRef, intel: CveIntel | None, cfg: Scoring) -> float:
    w = cfg.threat_weights
    cvss = (intel.cvss if intel and intel.cvss is not None else ref.cvss) or 0.0
    epss = (intel.epss_percentile if intel and intel.epss_percentile is not None else 0.0)
    kev = 1.0 if intel and intel.kev else 0.0
    exploit = 1.0 if intel and intel.exploit_public else _EXPLOIT_TERM.get(ref.exploitability, 0.0)
    return w["cvss"] * cvss / 10.0 + w["epss"] * epss + w["kev"] * kev + w["exploit"] * exploit


def asset_signals(asset: Asset, cfg: Scoring) -> list[tuple[str, float]]:
    b = cfg.asset_bonus
    sig: list[tuple[str, float]] = []
    if asset.internet_facing:
        sig.append(("Internet-facing", b["internet_facing"]))
    for t in asset.tags:
        if any(t.lower() == pat.lower() for pat in cfg.criticality_tags):
            sig.append((t, b["criticality_tag"]))
    if (asset.device_value or "").lower() == "high":
        sig.append(("High value", b["device_value_high"]))
    if (asset.exposure_level or "").lower() == "high":
        sig.append(("Exposure High", b["exposure_high"]))
    elif (asset.exposure_level or "").lower() == "medium":
        sig.append(("Exposure Medium", b["exposure_medium"]))
    if asset.public_lb:
        sig.append(("Public LoadBalancer", b["public_lb"]))
    return sig


def asset_multiplier(asset: Asset, cfg: Scoring) -> float:
    return min(cfg.asset_cap, 1.0 + sum(v for _, v in asset_signals(asset, cfg)))


def label_for(score: int, cfg: Scoring) -> str:
    if score >= cfg.bands["critical"]: return "Critical"
    if score >= cfg.bands["high"]: return "High"
    if score >= cfg.bands["medium"]: return "Medium"
    return "Low"


def product_score(p: Product, assets: dict[str, Asset], intel: dict[str, CveIntel], cfg: Scoring, estate_size: int) -> ScoredProduct:
    threats = sorted(((ref, threat_score(ref, intel.get(ref.id), cfg)) for ref in p.cves.values()), key=lambda x: (-x[1], -x[0].cvss, x[0].id))
    driving = threats[:3]
    top3 = sum(t for _, t in driving) / len(driving) if driving else 0.0
    ranked_assets = sorted(((assets.get(a) or Asset(id=a, name=a)) for a in p.asset_ids), key=lambda a: (-asset_multiplier(a, cfg), a.name))
    mults = [asset_multiplier(a, cfg) for a in ranked_assets]
    if mults:
        weights = [2.0 if i < 5 else 1.0 for i in range(len(mults))]
        asset_mean = sum(m * w for m, w in zip(mults, weights)) / sum(weights)
    else:
        asset_mean = 1.0
    reach = math.log10(1 + len(p.asset_ids)) / math.log10(1 + max(estate_size, 1)) if estate_size > 0 else 0.0
    any_kev = any(intel.get(r.id) and intel[r.id].kev for r, _ in driving)
    any_inet = any(a.internet_facing for a in ranked_assets)
    boost = 1.25 if (any_kev and any_inet) else 1.0
    raw = top3 * (0.6 + 0.3 * asset_mean / cfg.asset_cap + 0.1 * reach) * boost
    score = int(round(100 * min(1.0, raw)))
    counts = {s.lower(): sum(1 for r in p.cves.values() if r.severity == s) for s in SEVERITIES}
    flags = {
        "kev": any_kev,
        "exploit": any((intel.get(r.id) and intel[r.id].exploit_public) or EXPLOIT_RANK.get(r.exploitability, 0) >= 1 for r in p.cves.values()),
        "internet_facing": any_inet,
    }
    top_assets = [(a, asset_multiplier(a, cfg), " · ".join(n for n, _ in asset_signals(a, cfg)) or "No extra exposure") for a in ranked_assets[:5]]
    return ScoredProduct(p, score, label_for(score, cfg), driving, counts, asset_mean, reach, flags, top_assets)


def reason_for(sp: ScoredProduct) -> str:
    bits = []
    n_inet = sum(1 for a in sp.top_assets if a[0].internet_facing)
    if sp.flags["internet_facing"]:
        bits.append("internet-facing hosts affected")
    if sp.flags["kev"]:
        bits.append("KEV-listed CVE")
    elif sp.flags["exploit"]:
        bits.append("public exploit available")
    if len(sp.product.asset_ids) >= 100:
        bits.append(f"{len(sp.product.asset_ids)} devices affected")
    if sp.counts["critical"]:
        bits.append(f"{sp.counts['critical']} critical CVEs")
    return ", ".join(bits).capitalize() if bits else "Open vulnerabilities without exposure signals"
```

- [ ] **Step 4: Run tests** → `pytest tests/test_scoring.py -v` → 5 passed.
- [ ] **Step 5: Commit** → `git add dva/scoring.py tests/test_scoring.py && git commit -m "feat: threat, asset and product scoring"`

---

### Task 11: CVE intel cache and enrichment candidate selection

**Files:**
- Create: `dva/cache.py`, `dva/enrich.py`, `tests/test_enrich.py`

**Interfaces:**
- Consumes: `rollup.build`, `scoring.product_score`, `CveIntel`, `Scoring`.
- Produces: `dva.cache.IntelCache(dir, ttl_days)` with `get(cve_id) -> CveIntel | None` (None when missing or stale), `put(cve_id, intel: CveIntel)`, `all_fresh(ids) -> dict[str, CveIntel]`. `dva.enrich.select_candidates(products, assets, cache, cfg, estate_size) -> list[str]` implementing the spec's selection (per-product top N by `cvss` then `EXPLOIT_RANK` then newest `first_seen`; products in descending preliminary score; stop below `report_threshold` or at `enrich_max_cves`; skip cached). `dva.enrich.parse_store(payload: dict | list) -> dict[str, CveIntel]` accepting the CVE server's `bulk_cve_lookup`/`triage_cve` output shapes and normalizing them; `write_enrichment(run, cache, ids) -> dict` merging fresh cache entries for `ids` into `enrichment.json`. CLI: `dva enrich --list [--run]` prints JSON lines `{"chunk": n, "cve_ids": [...]}` (20 per chunk) and writes `enrich-candidates.json`; `dva enrich --store FILE [--run]` reads a JSON file with the tool result(s), caches them, and rewrites `enrichment.json`; prints `stored N, missing M`.

  `parse_store` field mapping (be liberal; the server's exact keys are captured into `tests/fixtures/cve/bulk.json` on first real use, see Task 17): for each entry keyed by CVE id or carrying `cve_id`/`id`: `cvss` ← first present of `cvss_v3_score`, `cvss_score`, `cvss.base_score`, `cvss`; `epss` ← `epss_score` or `epss.score`; `epss_percentile` ← `epss_percentile` or `epss.percentile`; `kev` ← `in_kev`, `kev.in_kev`, `cisa_kev`, `kev` (truthy); `kev_added` ← `kev.date_added` or `date_added`; `ransomware` ← `kev.known_ransomware_use` truthy; `exploit_public` ← `exploit_available`, `has_exploit`, `poc_available`, or non-empty `exploits`; `exploit_sources` ← `exploit_sources` or names in `exploits`; `title` ← `title` or first 120 chars of `description`; `cwe` ← `cwe` or `cwe_id`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_enrich.py
import json
from dva.cache import IntelCache
from dva.config import load_scoring
from dva.enrich import select_candidates, parse_store
from dva.model import Asset, CveRef, Product
from dva.scoring import CveIntel

cfg = load_scoring()

def ref(i, cvss, expl="NoExploit", fs="2026-01-01"):
    return CveRef(id=f"CVE-{i}", severity="High", cvss=cvss, exploitability=expl, first_seen=fs)

def test_cache_ttl(tmp_path):
    c = IntelCache(tmp_path, ttl_days=7)
    assert c.get("CVE-1") is None
    c.put("CVE-1", CveIntel(cvss=9.0, kev=True))
    assert c.get("CVE-1").kev is True
    stale = json.loads((tmp_path / "CVE-1.json").read_text()); stale["fetched_at"] = "2020-01-01T00:00:00+00:00"
    (tmp_path / "CVE-1.json").write_text(json.dumps(stale))
    assert c.get("CVE-1") is None

def test_select_top_per_product_and_caps(tmp_path):
    cache = IntelCache(tmp_path, 7)
    hot = Product(key="a/b", vendor="a", name="b", asset_ids={"x"}, cves={f"CVE-{i}": ref(i, 9.0 - i * 0.1, "ExploitIsPublic" if i == 4 else "NoExploit") for i in range(6)})
    cold = Product(key="c/d", vendor="c", name="d", asset_ids={"y"}, cves={"CVE-99": ref(99, 2.0)})
    assets = {"x": Asset(id="x", name="x", internet_facing=True, tags=["Tier0"]), "y": Asset(id="y", name="y")}
    cache.put("CVE-0", CveIntel(cvss=9.0))
    ids = select_candidates({"a/b": hot, "c/d": cold}, assets, cache, cfg, estate_size=10)
    # top 3 by cvss: CVE-0 (cached, skipped), CVE-1, CVE-2 ; cold product below threshold is excluded
    assert ids == ["CVE-1", "CVE-2"]

def test_parse_store_normalizes_bulk_shape():
    payload = {"results": [{"cve_id": "CVE-2026-1", "cvss_v3_score": 9.8, "epss_score": 0.9, "epss_percentile": 0.99, "in_kev": True, "exploits": [{"source": "exploit-db"}], "description": "Remote code execution in thing"}]}
    out = parse_store(payload)
    i = out["CVE-2026-1"]
    assert i.cvss == 9.8 and i.kev and i.exploit_public and i.exploit_sources == ["exploit-db"] and i.title.startswith("Remote code")
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/cache.py
from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dva.scoring import CveIntel


class IntelCache:
    def __init__(self, directory: Path, ttl_days: int):
        self.dir = Path(directory); self.dir.mkdir(parents=True, exist_ok=True); self.ttl = timedelta(days=ttl_days)

    def _p(self, cve_id: str) -> Path:
        return self.dir / f"{cve_id.upper()}.json"

    def get(self, cve_id: str) -> CveIntel | None:
        p = self._p(cve_id)
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        fetched = d.get("fetched_at")
        if not fetched or datetime.fromisoformat(fetched) < datetime.now(timezone.utc) - self.ttl:
            return None
        return CveIntel(**{k: d.get(k) for k in CveIntel.__dataclass_fields__})

    def put(self, cve_id: str, intel: CveIntel) -> None:
        intel.fetched_at = intel.fetched_at or datetime.now(timezone.utc).isoformat()
        self._p(cve_id).write_text(json.dumps(asdict(intel)))

    def all_fresh(self, ids) -> dict[str, CveIntel]:
        out = {}
        for i in ids:
            v = self.get(i)
            if v is not None:
                out[i] = v
        return out
```

```python
# dva/enrich.py
from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path
from dva.cache import IntelCache
from dva.config import Scoring, load_scoring
from dva.errors import DvaError
from dva.model import Asset, Product, EXPLOIT_RANK
from dva.rollup import build
from dva.run import Run, add_run_arg, resolve_run, cache_dir
from dva.scoring import CveIntel, product_score

CHUNK = 20


def _rank_key(r):
    # highest cvss, then strongest exploitability, then newest first_seen (ISO strings sort lexically)
    return (-r.cvss, -EXPLOIT_RANK.get(r.exploitability, 0), "" if r.first_seen is None else "".join(chr(0x10FFFF - ord(ch)) for ch in r.first_seen), r.id)


def select_candidates(products: dict[str, Product], assets: dict[str, Asset], cache: IntelCache, cfg: Scoring, estate_size: int) -> list[str]:
    prelim = [(product_score(p, assets, {}, cfg, estate_size).score, p) for p in products.values()]
    prelim.sort(key=lambda x: (-x[0], x[1].key))
    out: list[str] = []
    seen: set[str] = set()
    for score, p in prelim:
        if score < cfg.report_threshold:
            break
        for r in sorted(p.cves.values(), key=_rank_key)[: cfg.enrich_top_per_product]:
            if r.id in seen or cache.get(r.id) is not None:
                continue
            seen.add(r.id); out.append(r.id)
            if len(out) >= cfg.enrich_max_cves:
                return out
    return out


def _first(d: dict, *paths):
    for path in paths:
        cur = d
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                cur = None; break
            cur = cur[part]
        if cur is not None:
            return cur
    return None


def _one(cve_id: str, d: dict) -> CveIntel:
    exploits = _first(d, "exploits") or []
    sources = _first(d, "exploit_sources") or [e.get("source") or e.get("name") for e in exploits if isinstance(e, dict)]
    desc = _first(d, "title") or (_first(d, "description") or "")[:120] or None
    return CveIntel(
        cvss=_first(d, "cvss_v3_score", "cvss_score", "cvss.base_score", "cvss"),
        epss=_first(d, "epss_score", "epss.score"), epss_percentile=_first(d, "epss_percentile", "epss.percentile"),
        kev=bool(_first(d, "in_kev", "kev.in_kev", "cisa_kev", "kev")), kev_added=_first(d, "kev.date_added", "date_added"),
        ransomware=bool(_first(d, "kev.known_ransomware_use", "known_ransomware_use")),
        exploit_public=bool(_first(d, "exploit_available", "has_exploit", "poc_available") or exploits),
        exploit_sources=[s for s in sources if s], title=desc, cwe=_first(d, "cwe", "cwe_id"))


def parse_store(payload) -> dict[str, CveIntel]:
    entries = payload
    if isinstance(payload, dict):
        entries = payload.get("results") or payload.get("cves") or payload.get("data") or payload
    out: dict[str, CveIntel] = {}
    if isinstance(entries, dict):
        for k, v in entries.items():
            if k.upper().startswith("CVE-") and isinstance(v, dict):
                out[k.upper()] = _one(k.upper(), v)
        if not out and (payload.get("cve_id") or payload.get("id")):
            cid = (payload.get("cve_id") or payload.get("id")).upper(); out[cid] = _one(cid, payload)
        return out
    for e in entries or []:
        if isinstance(e, dict):
            cid = (e.get("cve_id") or e.get("id") or e.get("cve") or "").upper()
            if cid.startswith("CVE-"):
                out[cid] = _one(cid, e)
    return out


def write_enrichment(run: Run, cache: IntelCache, ids: list[str]) -> dict:
    fresh = cache.all_fresh(ids)
    doc = {"cves": {k: asdict(v) for k, v in fresh.items()}, "missing": sorted(set(ids) - set(fresh))}
    run.write_json("enrichment.json", doc)
    return doc


def register(sub) -> None:
    p = sub.add_parser("enrich", help="Select CVEs for enrichment and store CVE server results")
    add_run_arg(p)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true"); g.add_argument("--store")
    p.set_defaults(func=_run)


def _run(args) -> int:
    run, cfg = resolve_run(args), load_scoring()
    cache = IntelCache(cache_dir() / "cve", cfg.cache_ttl_days)
    products, assets = build(run)
    estate = len(run.read_json("machines.json")) if run.path("machines.json").exists() else len(assets)
    if args.list:
        ids = select_candidates(products, assets, cache, cfg, estate)
        run.write_json("enrich-candidates.json", ids)
        for n in range(0, len(ids), CHUNK):
            print(json.dumps({"chunk": n // CHUNK + 1, "cve_ids": ids[n:n + CHUNK]}))
        run.summary(f"Enrichment candidates: {len(ids)} CVEs in {(len(ids) + CHUNK - 1) // CHUNK} chunks (cached ones excluded).")
        return 0
    path = Path(args.store)
    if not path.exists():
        raise DvaError(f"store file not found: {path}")
    parsed = parse_store(json.loads(path.read_text()))
    for cid, intel in parsed.items():
        cache.put(cid, intel)
    wanted = run.read_json("enrich-candidates.json") if run.path("enrich-candidates.json").exists() else list(parsed)
    doc = write_enrichment(run, cache, wanted)
    run.summary(f"Enrichment stored: {len(parsed)} CVEs; enrichment.json now has {len(doc['cves'])} CVEs, {len(doc['missing'])} still missing.")
    return 0
```

- [ ] **Step 4: Run tests** → `pytest tests/test_enrich.py -v` → 3 passed.
- [ ] **Step 5: Commit** → `git add dva/cache.py dva/enrich.py tests/test_enrich.py && git commit -m "feat: CVE intel cache and enrichment candidate selection"`

---

### Task 12: Score command producing findings.json

**Files:**
- Create: `dva/score_cmd.py`, `tests/test_score_cmd.py`

**Interfaces:**
- Consumes: `build`, `product_score`, `reason_for`, `IntelCache`, `display_name`, `display_vendor`, `Run.latest(before=)`.
- Produces: `dva.score_cmd.compute(run, cfg, cache) -> dict` returning the `findings.json` document exactly as the spec shape: `run` (manifest), `summary` (`devices`, `products_total`, `products_action`, `kev_cves`, `internet_facing_at_risk`, `exposure_score`, `previous_exposure_score`, `generated_at`, `tenant`), `products` (ranked list, each with `rank, key, vendor, product, score, label, counts, flags, reason, remediation, remediation_type, recommended_version, versions, driving_cves[{id, severity, cvss, epss, kev, poc, title}], assets{count, breakdown, top[{name, why}]}, all_cves, all_assets, partial_intel: bool`), `diff_from_previous` (`entered_top10`, `left_top10`, `new_kev`, `previous_run_id`). `products` includes only those with `score >= cfg.report_threshold`, ranked by score desc then name. `breakdown` is built as `"<n> internet-facing · <m> <Tag> · <k> High value"` from counts over the product's assets, omitting zero parts, or `"No exposure signals"`. CLI `dva score [--run]` writes `findings.json` and prints `Scored P products; N need action; top: A (97), B (91), C (88).`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_score_cmd.py
from tests.test_rollup import seed
from dva.score_cmd import compute
from dva.config import load_scoring
from dva.cache import IntelCache
from dva.scoring import CveIntel

def test_findings_document(tmp_path):
    run = seed(tmp_path / "runs")
    cache = IntelCache(tmp_path / "cache", 7)
    cache.put("CVE-2026-21887", CveIntel(cvss=9.8, epss=0.94, epss_percentile=0.99, kev=True, exploit_public=True, title="Unauthenticated RCE"))
    run.write_json("exposure.json", {"score": 54.0, "by_group": {}})
    doc = compute(run, load_scoring(), cache)
    top = doc["products"][0]
    assert top["product"] == "Connect Secure" and top["rank"] == 1 and top["label"] == "Critical"
    assert top["driving_cves"][0] == {"id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "epss": 0.94, "kev": True, "poc": True, "title": "Unauthenticated RCE"}
    assert top["assets"]["count"] == 2 and top["assets"]["top"][0]["name"] == "vpn-gw-01"
    assert "1 internet-facing" in top["assets"]["breakdown"] and "1 Tier0" in top["assets"]["breakdown"]
    assert top["partial_intel"] is True  # CVE-2025-46512 has no intel
    assert doc["summary"]["devices"] == 2 and doc["summary"]["kev_cves"] == 1 and doc["summary"]["internet_facing_at_risk"] == 1
    assert doc["summary"]["exposure_score"] == 54.0 and doc["diff_from_previous"]["previous_run_id"] is None

def test_diff_against_previous(tmp_path):
    run = seed(tmp_path / "runs")
    (tmp_path / "runs" / "20200101T000000Z").mkdir()
    prev_dir = tmp_path / "runs" / "20200101T000000Z"
    prev_dir.joinpath("manifest.json").write_text('{"run_id": "20200101T000000Z", "sources": {}}')
    prev_dir.joinpath("findings.json").write_text('{"summary": {"exposure_score": 61.0}, "products": [{"key": "old/thing", "rank": 1, "flags": {"kev": false}}, {"key": "adobe/acrobat-reader-dc", "rank": 2, "flags": {"kev": false}}]}')
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "c", 7))
    d = doc["diff_from_previous"]
    assert d["previous_run_id"] == "20200101T000000Z" and "old/thing" in d["left_top10"] and "ivanti/connect-secure" in d["entered_top10"]
    assert doc["summary"]["previous_exposure_score"] == 61.0
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement**

```python
# dva/score_cmd.py
from __future__ import annotations
import os
from datetime import datetime, timezone
from dva.cache import IntelCache
from dva.config import Scoring, load_scoring
from dva.rollup import build, display_name, display_vendor
from dva.run import Run, add_run_arg, resolve_run, cache_dir, runs_dir
from dva.scoring import product_score, reason_for, asset_signals


def _breakdown(assets, cfg: Scoring) -> str:
    parts = []
    inet = sum(1 for a in assets if a.internet_facing)
    if inet: parts.append(f"{inet} internet-facing")
    for tag in cfg.criticality_tags:
        n = sum(1 for a in assets if any(t.lower() == tag.lower() for t in a.tags))
        if n: parts.append(f"{n} {tag}")
    hv = sum(1 for a in assets if (a.device_value or "").lower() == "high")
    if hv: parts.append(f"{hv} High value")
    return " · ".join(parts) if parts else "No exposure signals"


def compute(run: Run, cfg: Scoring, cache: IntelCache) -> dict:
    products, assets = build(run)
    estate = len(assets)
    all_ids = {cid for p in products.values() for cid in p.cves}
    intel = cache.all_fresh(all_ids)
    scored = sorted((product_score(p, assets, intel, cfg, estate) for p in products.values()), key=lambda s: (-s.score, s.product.name))
    rows = []
    for i, sp in enumerate(s for s in scored if s.score >= cfg.report_threshold):
        p = sp.product
        pa = [assets.get(a) for a in p.asset_ids if a in assets]
        rows.append({
            "rank": i + 1, "key": p.key, "vendor": display_vendor(p), "product": display_name(p), "score": sp.score, "label": sp.label,
            "counts": sp.counts, "flags": sp.flags, "reason": reason_for(sp),
            "remediation": p.remediation or (f"Update to {p.recommended_version}" if p.recommended_version else "Update to a fixed version; see vendor advisory."),
            "remediation_type": p.remediation_type, "recommended_version": p.recommended_version, "versions": p.versions,
            "driving_cves": [{"id": r.id, "severity": r.severity, "cvss": (intel[r.id].cvss if r.id in intel and intel[r.id].cvss is not None else r.cvss),
                              "epss": intel[r.id].epss if r.id in intel else None, "kev": bool(r.id in intel and intel[r.id].kev),
                              "poc": bool((r.id in intel and intel[r.id].exploit_public) or r.exploitability != "NoExploit"),
                              "title": intel[r.id].title if r.id in intel else None} for r, _ in sp.driving],
            "assets": {"count": len(p.asset_ids), "breakdown": _breakdown(pa, cfg), "top": [{"name": a.name, "why": why} for a, _, why in sp.top_assets]},
            "all_cves": sorted(p.cves), "all_assets": sorted(a.name for a in pa),
            "partial_intel": any(r.id not in intel for r, _ in sp.driving),
        })
    exposure = run.read_json("exposure.json") if run.path("exposure.json").exists() else {}
    prev = Run.latest(run.dir.parent, before=run.id)
    prev_doc = prev.read_json("findings.json") if prev and prev.path("findings.json").exists() else None
    top_now = [r["key"] for r in rows[: cfg.top_n]]
    top_prev = [r["key"] for r in (prev_doc or {}).get("products", [])[: cfg.top_n]]
    kev_prev = {r["key"] for r in (prev_doc or {}).get("products", []) if r.get("flags", {}).get("kev")}
    kev_ids = {cid for cid, it in intel.items() if it.kev and cid in all_ids}
    inet_risk = {a.id for p in products.values() for a in (assets.get(x) for x in p.asset_ids) if a and a.internet_facing and any(r.severity == "Critical" for r in p.cves.values())}
    return {
        "run": run.manifest,
        "summary": {"devices": estate, "products_total": len(products), "products_action": len(rows), "kev_cves": len(kev_ids),
                    "internet_facing_at_risk": len(inet_risk), "exposure_score": exposure.get("score"),
                    "previous_exposure_score": (prev_doc or {}).get("summary", {}).get("exposure_score"),
                    "generated_at": datetime.now(timezone.utc).isoformat(), "tenant": os.environ.get("DVA_TENANT_NAME", os.environ.get("DVA_TENANT_ID", "unknown"))},
        "products": rows,
        "diff_from_previous": {"previous_run_id": prev.id if prev_doc else None,
                               "entered_top10": [k for k in top_now if k not in top_prev], "left_top10": [k for k in top_prev if k not in top_now],
                               "new_kev": [r["key"] for r in rows if r["flags"]["kev"] and r["key"] not in kev_prev]},
    }


def register(sub) -> None:
    p = sub.add_parser("score", help="Roll up, score and write findings.json"); add_run_arg(p); p.set_defaults(func=_run)


def _run(args) -> int:
    run, cfg = resolve_run(args), load_scoring()
    doc = compute(run, cfg, IntelCache(cache_dir() / "cve", cfg.cache_ttl_days))
    run.write_json("findings.json", doc)
    top = ", ".join(f"{r['product']} ({r['score']})" for r in doc["products"][:3])
    run.summary(f"Scored {doc['summary']['products_total']} products; {doc['summary']['products_action']} need action; top: {top}.")
    return 0
```

- [ ] **Step 4: Run tests** → `pytest tests/test_score_cmd.py -v` → 2 passed.
- [ ] **Step 5: Commit** → `git add dva/score_cmd.py tests/test_score_cmd.py && git commit -m "feat: score command writes findings.json with diff from previous run"`

---

### Task 13: JSON and Markdown renderers

**Files:**
- Create: `dva/report_json.py`, `dva/report_md.py`, `dva/report_cmd.py`, `tests/test_report_md.py`, `tests/fixtures/sample-run/findings.json`, `tests/golden/report.md`

**Interfaces:**
- Consumes: `findings.json` document.
- Produces: `report_json.render(doc) -> str` (pretty JSON, sorted keys); `report_md.render(doc) -> str`; `report_cmd.register` adding `dva report [--run] [--md] [--html] [--json] [--all]` writing `report.md`, `report.html`, `findings.json` copy is already there so `--json` only re-pretty-prints to `report.json`. `tests/fixtures/sample-run/findings.json` is a hand-written 6-product document following the Task 12 shape (reuse the product data from `docs/design/report/Main.dc.html` for the top 3: Connect Secure, FortiClient EMS, Exchange Server 2019, plus Windows Server 2019, Acrobat Reader DC, Zoom Workplace) and is the demo data for all renderers.

Markdown layout (exact headings, in order): `# Vulnerability assessment — <tenant>`; a meta line `Run <id> · generated <generated_at> · previous run <prev or none>`; `## Executive summary` with one paragraph built from summary fields and one from the diff (omitted when no previous run); `## Top 10 products to patch` table with columns `#, Product, Vendor, Score, Devices, Crit, High, Med, Low, Flags`; `### <rank>. <Product> (<vendor>) — <score> <label>` sections per top-10 product containing `Why:`, `Remediation:`, a `Driving vulnerabilities` bullet list (`- CVE · CVSS x · EPSS y · KEV · Exploit · title`), `Affected assets (<count>): <breakdown>` followed by `- name — why` bullets and `+ N more in findings.json`; `## All prioritized products` compact table for ranks beyond 10; `## Method` paragraph copied from the spec's appendix text; `## Sources` list of manifest sources with status.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_md.py
import json, os
from pathlib import Path
from dva.report_md import render

FX = Path(__file__).parent / "fixtures" / "sample-run" / "findings.json"
GOLD = Path(__file__).parent / "golden" / "report.md"

def test_markdown_matches_golden():
    out = render(json.loads(FX.read_text()))
    if os.environ.get("DVA_UPDATE_GOLDEN"):
        GOLD.parent.mkdir(exist_ok=True); GOLD.write_text(out)
    assert out == GOLD.read_text()

def test_markdown_structure():
    out = render(json.loads(FX.read_text()))
    assert out.startswith("# Vulnerability assessment")
    assert "## Top 10 products to patch" in out and "### 1. Connect Secure" in out
    assert "CVE-2026-21887" in out and "+ 1 more in findings.json" in out
```

- [ ] **Step 2: Write the sample fixture** at `tests/fixtures/sample-run/findings.json` following the Task 12 shape with six products. Rank 1 must be `Connect Secure` with `assets.count` 6 and five `top` entries so the `+ 1 more` line appears. Include `run.sources` with `mde.machines` ok and `hunting.internet-facing` ok, and a `diff_from_previous` with `previous_run_id` set.

- [ ] **Step 3: Run to verify fail** → FAIL.

- [ ] **Step 4: Implement**

```python
# dva/report_json.py
import json
def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True)
```

```python
# dva/report_md.py
from __future__ import annotations

METHOD = ("Each product's score (0 to 100) combines threat signals for its CVEs (CVSS, EPSS, CISA KEV listing, public exploit "
          "availability), the context of the affected assets (internet exposure, Defender exposure level, device value, criticality "
          "tags) and the number of affected devices. Findings are grouped by software product so one row maps to one patch action; "
          "only the three CVEs contributing most to a product's score and its most critical assets are shown. Weights live in scoring.yaml.")


def _flags(r: dict) -> str:
    f = r["flags"]; return ", ".join(x for x, on in [("KEV", f["kev"]), ("exploit", f["exploit"]), ("internet-facing", f["internet_facing"])] if on) or "-"


def _row(r: dict) -> str:
    c = r["counts"]
    return f"| {r['rank']} | {r['product']} | {r['vendor']} | {r['score']} {r['label']} | {r['assets']['count']} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {_flags(r)} |"


def render(doc: dict) -> str:
    s, d, rows = doc["summary"], doc["diff_from_previous"], doc["products"]
    top, rest = rows[:10], rows[10:]
    out = [f"# Vulnerability assessment — {s.get('tenant', 'tenant')}", "",
           f"Run {doc['run'].get('run_id')} · generated {s.get('generated_at')} · previous run {d.get('previous_run_id') or 'none'}", "",
           "## Executive summary", ""]
    emergencies = [r for r in top if r["flags"]["kev"] and r["flags"]["internet_facing"]]
    out.append(f"{s['products_action']} of {s['products_total']} software products across {s['devices']} devices need action. "
               f"{len(emergencies)} of the top 10 carry KEV-listed CVEs on internet-facing hosts and should be treated as emergency changes. "
               f"{s['kev_cves']} KEV-listed CVEs are present; {s['internet_facing_at_risk']} internet-facing devices have at least one critical CVE."
               + (f" Exposure score is {s['exposure_score']}." if s.get("exposure_score") is not None else ""))
    if d.get("previous_run_id"):
        by_key = {r["key"]: r["product"] for r in rows}
        entered = ", ".join(by_key.get(k, k) for k in d["entered_top10"]) or "none"
        out += ["", f"Since run {d['previous_run_id']}: entered the top 10: {entered}; left the top 10: {', '.join(d['left_top10']) or 'none'}; "
                    f"newly KEV-listed products: {', '.join(by_key.get(k, k) for k in d['new_kev']) or 'none'}."
                    + (f" Exposure score moved from {s['previous_exposure_score']} to {s['exposure_score']}." if s.get("previous_exposure_score") is not None and s.get("exposure_score") is not None else "")]
    out += ["", "## Top 10 products to patch", "", "| # | Product | Vendor | Score | Devices | Crit | High | Med | Low | Flags |", "|---|---|---|---|---|---|---|---|---|---|"]
    out += [_row(r) for r in top]
    for r in top:
        out += ["", f"### {r['rank']}. {r['product']} ({r['vendor']}) — {r['score']} {r['label']}", "", f"Why: {r['reason']}", "", f"Remediation: {r['remediation']}", "",
                f"Driving vulnerabilities ({sum(r['counts'].values())} open CVEs in total" + (", partial intel" if r.get("partial_intel") else "") + "):"]
        for c in r["driving_cves"]:
            bits = [c["id"], f"CVSS {c['cvss']}"] + ([f"EPSS {c['epss']}"] if c.get("epss") is not None else []) + (["KEV"] if c["kev"] else []) + (["Exploit"] if c["poc"] else []) + ([c["title"]] if c.get("title") else [])
            out.append("- " + " · ".join(str(b) for b in bits))
        a = r["assets"]
        out += ["", f"Affected assets ({a['count']}): {a['breakdown']}"] + [f"- {x['name']} — {x['why']}" for x in a["top"]]
        more = a["count"] - len(a["top"])
        if more > 0:
            out.append(f"+ {more} more in findings.json")
    if rest:
        out += ["", "## All prioritized products", "", "| # | Product | Vendor | Score | Devices | Crit | High | Med | Low | Flags |", "|---|---|---|---|---|---|---|---|---|---|"] + [_row(r) for r in rest]
    out += ["", "## Method", "", METHOD, "", "## Sources", ""]
    for name, st in sorted(doc["run"].get("sources", {}).items()):
        out.append(f"- {name}: {st.get('status')}" + (f" ({st.get('count')} records)" if st.get("count") is not None else "") + (f" — {st.get('error')}" if st.get("error") else ""))
    return "\n".join(out) + "\n"
```

```python
# dva/report_cmd.py
from __future__ import annotations
from dva.run import add_run_arg, resolve_run
from dva import report_md, report_json


def register(sub) -> None:
    p = sub.add_parser("report", help="Render reports from findings.json"); add_run_arg(p)
    for f in ("md", "html", "json", "all"):
        p.add_argument(f"--{f}", action="store_true")
    p.set_defaults(func=_run)


def _run(args) -> int:
    run = resolve_run(args)
    doc = run.read_json("findings.json")
    want = {"md", "html", "json"} if args.all or not (args.md or args.html or args.json) else {f for f in ("md", "html", "json") if getattr(args, f)}
    written = []
    if "md" in want:
        run.path("report.md").write_text(report_md.render(doc)); written.append("report.md")
    if "json" in want:
        run.path("report.json").write_text(report_json.render(doc)); written.append("report.json")
    if "html" in want:
        from dva import report_html
        run.path("report.html").write_text(report_html.render(doc)); written.append("report.html")
    run.summary("Reports written: " + ", ".join(written) + f" in {run.dir}")
    return 0
```

- [ ] **Step 5: Generate golden and run** → `DVA_UPDATE_GOLDEN=1 pytest tests/test_report_md.py -v && pytest tests/test_report_md.py -v` → passed. Read `tests/golden/report.md` once and check it reads sensibly (headings in order, no `None` strings).
- [ ] **Step 6: Commit** → `git add dva/report_json.py dva/report_md.py dva/report_cmd.py tests/test_report_md.py tests/fixtures/sample-run tests/golden && git commit -m "feat: Markdown and JSON report renderers with golden test"`

---

### Task 14: HTML renderer in the Elevate report style

**Files:**
- Create: `dva/report_template.html`, `dva/report_html.py`, `tests/test_report_html.py`

**Interfaces:**
- Consumes: `findings.json` document; the approved mockup `docs/design/report/Main.dc.html` for layout and styles.
- Produces: `report_html.render(doc) -> str`: reads `report_template.html`, replaces the literal `__FINDINGS_JSON__` with `json.dumps(doc)` escaped so that `</script>` cannot occur (replace `</` with `<\/`), and `__TITLE__` with the tenant. The template is a single self-contained page: no external requests, inline CSS copied from the mockup (system font stack, `#101d32` ink, `#526176` muted, `#075bd8` blue, `#f5f7fb` mist header band, `#dce3ec` lines, 20px tiles, 999px pills, sticky toolbar with chips, 20px/16px radius cards), and inline vanilla JS that renders from the embedded JSON: header with meta grid and verdict, four tiles, toolbar (filter chips All / Has critical / KEV-listed / Internet-facing; sort chips Score / Devices / Critical CVEs; Expand all / Collapse all), top 10 cards (ranks 1 to 3 open by default) with severity counts, 6px stacked severity strip, score pill, driving CVEs, remediation, affected assets top 5 + "+N more in findings.json", then the "All prioritized products" list with collapsed rows, then the method appendix and a footer. Layout uses wrapping flex and `repeat(auto-fit, minmax(300px, 1fr))` grids only; no fixed-pixel column grids. Severity colors: critical `#b42318`, high `#c2410c`, medium `#d9910f`, low `#075bd8`. Print stylesheet hides the toolbar.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_html.py
import json
from pathlib import Path
from dva.report_html import render

FX = Path(__file__).parent / "fixtures" / "sample-run" / "findings.json"

def test_html_is_self_contained_and_embeds_data():
    doc = json.loads(FX.read_text())
    out = render(doc)
    assert out.startswith("<!doctype html>")
    assert "http://" not in out.replace("http://www.w3.org", "") and "https://" not in out
    assert "__FINDINGS_JSON__" not in out and '"Connect Secure"' in out
    assert "<\\/" in out or "</script>" not in json.dumps(doc)  # embedded JSON never closes the script tag
    for marker in ["Top 10 products to patch", "All prioritized products", "How scores are computed", "Expand all", "Internet-facing"]:
        assert marker in out

def test_html_escapes_script_close():
    doc = json.loads(FX.read_text()); doc["products"][0]["reason"] = "x</script><b>y"
    out = render(doc)
    assert "x</script>" not in out
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement `dva/report_html.py`**

```python
# dva/report_html.py
from __future__ import annotations
import html, json
from pathlib import Path

TEMPLATE = Path(__file__).parent / "report_template.html"


def render(doc: dict) -> str:
    payload = json.dumps(doc).replace("</", "<\\/")
    tenant = html.escape(str(doc.get("summary", {}).get("tenant", "tenant")))
    return TEMPLATE.read_text(encoding="utf-8").replace("__TITLE__", tenant).replace("__FINDINGS_JSON__", payload)
```

- [ ] **Step 4: Write `dva/report_template.html`**

Port `docs/design/report/Main.dc.html` to plain HTML. Keep its `<style>` rules (turn the inline styles into classes named after the Elevate stylesheet: `.report-header`, `.wrap`, `.eyebrow`, `.meta`, `.verdict`, `.tiles`, `.tile`, `.pill`, `.toolbar`, `.chip`, `.card`, `.rowhead`, `.label`, `.body`, `.cve`, `.asset`, `.appendix`). Skeleton:

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerability assessment — __TITLE__</title>
<style>
:root{--ink:#101d32;--muted:#526176;--blue:#075bd8;--mist:#f5f7fb;--line:#dce3ec;--navy:#0e2138;--crit:#b42318;--high:#c2410c;--med:#d9910f;--low:#075bd8;--font:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:#fff;color:var(--ink);font-family:var(--font);line-height:1.5;font-size:15px;-webkit-font-smoothing:antialiased}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline;text-underline-offset:4px}
.wrap{width:min(1120px,calc(100% - 48px));margin-inline:auto}
.report-header{background:var(--mist);border-bottom:1px solid var(--line);padding-block:40px 32px}
.eyebrow{margin:0 0 8px;color:var(--muted);font-size:14px;letter-spacing:.04em;text-transform:uppercase}
h1{margin:0 0 12px;font-size:clamp(32px,4vw,48px);letter-spacing:-.02em;line-height:1.1;text-wrap:balance}
h2{margin:0;font-size:24px;letter-spacing:-.01em}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px 24px;margin:0;padding:0;list-style:none;color:var(--muted);font-size:14px}
.meta strong{display:block;color:var(--ink);font-weight:600}
.verdict{margin:24px 0 0;font-size:clamp(18px,2vw,22px);line-height:1.35;max-width:900px;text-wrap:pretty}
.sub{margin:8px 0 0;color:var(--muted);max-width:900px;text-wrap:pretty}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:24px}
.tile{display:flex;flex-direction:column;gap:8px;background:#fff;border:1px solid var(--line);border-radius:20px;padding:20px}
.tile .head{display:flex;justify-content:space-between;align-items:center;gap:8px}.tile .name{font-weight:600}
.tile .counts{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap;min-height:32px}.tile .n{font-size:32px;font-weight:700;letter-spacing:-.02em;line-height:1}
.tile .unit,.tile .line{color:var(--muted);font-size:13px}.tile .line{margin:0}
.pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;letter-spacing:.02em;text-transform:uppercase;background:var(--mist);color:var(--muted);white-space:nowrap}
.pill.critical{background:#fee4e2;color:var(--crit)}.pill.high{background:#ffe8d9;color:var(--high)}.pill.medium{background:#fef0c7;color:#b54708}.pill.low{background:#e0ecff;color:var(--blue)}.pill.kev{background:#fee4e2;color:var(--crit)}.pill.exploit{background:#fef0c7;color:#b54708}.pill.inet{background:#e0ecff;color:var(--blue)}
.toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:10px;background:#fff;border:1px solid var(--line);border-radius:16px;padding:10px 12px;margin-top:24px;position:sticky;top:12px;z-index:2;box-shadow:0 6px 24px rgba(16,29,50,.06)}
.chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;padding:6px 12px;font:inherit;font-size:13px;font-weight:600;color:var(--ink);background:#fff;cursor:pointer}
.chip.on{background:var(--ink);color:#fff;border-color:var(--ink)}.sep{width:1px;height:24px;background:var(--line)}.tb-label{color:var(--muted);font-size:13px}
.section{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-top:40px}.section p{margin:4px 0 0;color:var(--muted)}
.legend{display:flex;gap:14px;font-size:13px;color:var(--muted);flex-wrap:wrap}.legend span{display:inline-flex;align-items:center;gap:6px}.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.cards{display:flex;flex-direction:column;gap:12px;margin-top:16px}
.card{border:1px solid var(--line);border-radius:20px;padding:16px 24px;min-width:0}.card.compact{border-radius:16px;padding:12px 20px}
.rowhead{display:flex;align-items:center;gap:16px;flex-wrap:wrap;min-width:0;cursor:pointer}
.rank{width:36px;height:36px;border-radius:50%;background:var(--navy);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;flex:none}.rank.small{width:auto;height:auto;background:none;color:var(--muted);font-size:14px;min-width:28px;justify-content:flex-start}
.title{flex:1 1 260px;min-width:0;display:flex;flex-direction:column;gap:4px}.title .row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.title .name{font-size:17px;font-weight:600}.title .vendor,.title .why{color:var(--muted);font-size:14px}
.counts{display:flex;gap:14px;align-items:baseline;flex-wrap:wrap}.counts span{white-space:nowrap}.counts b{font-size:20px;font-weight:700;letter-spacing:-.02em}.counts small{color:var(--muted);font-size:13px}
.strip{display:flex;height:6px;gap:2px;border-radius:3px;overflow:hidden;width:200px;max-width:100%;margin-top:6px}
.devices{display:flex;flex-direction:column;align-items:flex-end}.devices b{font-size:24px;font-weight:700;letter-spacing:-.02em;line-height:1}.devices small{color:var(--muted);font-size:13px}
.score{display:flex;align-items:center;gap:10px}.score b{font-size:24px;font-weight:700;letter-spacing:-.02em;min-width:40px;text-align:right}
.caret{width:20px;height:20px;flex:none;transition:transform .15s}.open .caret{transform:rotate(90deg)}
.body{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:24px 32px;margin-top:16px;align-items:start}.body>div{display:flex;flex-direction:column;gap:6px;min-width:0}
.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;font-weight:600}
.cve{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 14px;padding:10px 0;border-top:1px solid var(--line);min-width:0}.cve .id{font-weight:600;white-space:nowrap}.cve .nums{display:flex;gap:12px;font-size:13px;color:var(--muted);white-space:nowrap;align-items:baseline}.cve .t{flex:1 1 220px;min-width:0;font-size:14px;color:var(--muted)}
.asset{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:4px 12px;padding:6px 0;border-top:1px solid var(--line)}.asset .n{font-weight:600;white-space:nowrap}.asset .w{font-size:13px;color:var(--muted)}
.more,.breakdown{font-size:13px;color:var(--muted)}
.appendix{margin-top:48px;padding-top:24px;border-top:1px solid var(--line);color:var(--muted);font-size:14px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:24px 32px}.appendix h2{font-size:20px;color:var(--ink)}.appendix p{margin:6px 0 0;text-wrap:pretty}
footer{margin-block:48px 64px;color:var(--muted);font-size:13px}
@media print{.toolbar{display:none}.card{break-inside:avoid}.body{display:grid!important}}
</style></head>
<body>
<header class="report-header"><div class="wrap" id="head"></div></header>
<main class="wrap">
  <div class="toolbar" id="toolbar"></div>
  <section class="section"><div><h2>Top 10 products to patch</h2><p>One row per product, so one patch action fixes many CVEs. Ranked by composite score.</p></div>
    <div class="legend"><span><i class="dot" style="background:var(--crit)"></i>Critical</span><span><i class="dot" style="background:var(--high)"></i>High</span><span><i class="dot" style="background:var(--med)"></i>Medium</span><span><i class="dot" style="background:var(--low)"></i>Low</span></div></section>
  <div class="cards" id="top"></div>
  <section class="section" style="border-top:1px solid var(--line);padding-top:24px;margin-top:48px"><div><h2>All prioritized products</h2><p>Every product above the reporting threshold. Expand a row for its driving CVEs and assets.</p></div><span class="tb-label" id="shown"></span></section>
  <div class="cards" id="all"></div>
  <div class="appendix" id="appendix"></div>
  <footer>Generated by defender-vuln-agent. Read-only assessment; no changes were made in Defender.</footer>
</main>
<script id="data" type="application/json">__FINDINGS_JSON__</script>
<script>
(function(){
  var DOC = JSON.parse(document.getElementById('data').textContent);
  var S = DOC.summary, D = DOC.diff_from_previous, ROWS = DOC.products;
  var state = { filter: 'all', sort: 'score', open: {} };
  ROWS.slice(0, 3).forEach(function(r){ state.open['top:' + r.key] = true; });
  function esc(s){ return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }
  function pill(cls, txt){ return '<span class="pill ' + cls + '">' + esc(txt) + '</span>'; }
  function flags(r){ var f = r.flags; return (f.kev ? pill('kev','KEV') : '') + (f.exploit ? pill('exploit','Public exploit') : '') + (f.internet_facing ? pill('inet','Internet-facing') : ''); }
  function strip(c){ var t = c.critical + c.high + c.medium + c.low || 1; function w(n){ return Math.round(100 * n / t) + '%'; }
    return '<div class="strip"><div style="width:' + w(c.critical) + ';background:var(--crit)"></div><div style="width:' + w(c.high) + ';background:var(--high)"></div><div style="width:' + w(c.medium) + ';background:var(--med)"></div><div style="width:' + w(c.low) + ';background:var(--low)"></div></div>'; }
  function counts(c){ return '<div class="counts"><span><b style="color:' + (c.critical ? 'var(--crit)' : 'var(--muted)') + '">' + c.critical + '</b> <small>critical</small></span><span><b style="color:var(--high)">' + c.high + '</b> <small>high</small></span><span><b style="color:#b8860b">' + c.medium + '</b> <small>medium</small></span><span><b style="color:var(--blue)">' + c.low + '</b> <small>low</small></span></div>'; }
  function body(r){ var total = r.counts.critical + r.counts.high + r.counts.medium + r.counts.low;
    var cves = r.driving_cves.map(function(c){ return '<div class="cve"><span class="id">' + esc(c.id) + '</span><span class="nums"><span>CVSS <b>' + esc(c.cvss) + '</b></span>' + (c.epss != null ? '<span>EPSS <b>' + esc(c.epss) + '</b></span>' : '') + (c.kev ? pill('kev','KEV') : '') + (c.poc ? pill('','Exploit') : '') + '</span><span class="t">' + esc(c.title || '') + '</span></div>'; }).join('');
    var a = r.assets, more = a.count - a.top.length;
    var assets = a.top.map(function(x){ return '<div class="asset"><span class="n">' + esc(x.name) + '</span><span class="w">' + esc(x.why) + '</span></div>'; }).join('');
    return '<div class="body"><div><div class="label">Top 3 driving vulnerabilities · ' + total + ' open CVEs in total' + (r.partial_intel ? ' · partial intel' : '') + '</div>' + cves + '</div>' +
      '<div><div class="label">Remediation</div><div>' + esc(r.remediation) + '</div><div class="label" style="margin-top:14px">Affected assets · ' + a.count + '</div><div class="breakdown">' + esc(a.breakdown) + '</div>' + assets + (more > 0 ? '<div class="more">+ ' + more + ' more in findings.json</div>' : '') + '</div></div>'; }
  function card(r, compact){ var key = (compact ? 'all:' : 'top:') + r.key, open = !!state.open[key];
    return '<div class="card' + (compact ? ' compact' : '') + (open ? ' open' : '') + '" data-key="' + esc(key) + '"><div class="rowhead">' +
      '<div class="rank' + (compact ? ' small' : '') + '">' + r.rank + '</div><div class="title"><div class="row"><span class="name">' + esc(r.product) + '</span><span class="vendor">' + esc(r.vendor) + '</span>' + flags(r) + '</div>' + (compact ? '' : '<div class="why">' + esc(r.reason) + '</div>') + '</div>' +
      '<div>' + counts(r.counts) + (compact ? '' : strip(r.counts)) + '</div><div class="devices"><b>' + r.assets.count.toLocaleString() + '</b><small>devices</small></div>' +
      '<div class="score">' + pill(r.label.toLowerCase(), r.label) + '<b>' + r.score + '</b></div>' +
      '<svg class="caret" viewBox="0 0 20 20" fill="none" stroke="#526176" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M7.5 5l5 5-5 5"/></svg></div>' + (open ? body(r) : '') + '</div>'; }
  function tile(name, pillCls, pillTxt, nums, line){ return '<div class="tile"><div class="head"><span class="name">' + esc(name) + '</span>' + pill(pillCls, pillTxt) + '</div><div class="counts">' + nums.map(function(n){ return '<span><span class="n" style="color:' + (n[2] || 'inherit') + '">' + esc(n[0]) + '</span> <span class="unit">' + esc(n[1]) + '</span></span>'; }).join('') + '</div><p class="line">' + esc(line) + '</p></div>'; }
  function head(){ var top = ROWS.slice(0, 10), em = top.filter(function(r){ return r.flags.kev && r.flags.internet_facing; }).length;
    var verdict = '<strong>' + S.products_action + ' of ' + S.products_total + ' software products across ' + Number(S.devices).toLocaleString() + ' devices need action.</strong> ' + (em ? em + ' of the top 10 carry KEV-listed CVEs on internet-facing hosts; treat those as emergency changes.' : 'No top 10 product combines a KEV-listed CVE with an internet-facing host.');
    var sub = D.previous_run_id ? 'Since run ' + esc(D.previous_run_id) + ': ' + (D.entered_top10.length ? D.entered_top10.length + ' product(s) entered the top 10' : 'no changes to the top 10') + (D.left_top10.length ? ', ' + D.left_top10.length + ' left' : '') + '.' + (S.previous_exposure_score != null && S.exposure_score != null ? ' Exposure score moved from ' + S.previous_exposure_score + ' to ' + S.exposure_score + '.' : '') : 'First run; no previous run to compare with.';
    var failed = Object.keys(DOC.run.sources || {}).filter(function(k){ return DOC.run.sources[k].status !== 'ok'; });
    document.getElementById('head').innerHTML = '<p class="eyebrow">Vulnerability assessment · Microsoft Defender</p><h1>' + esc(S.tenant) + '</h1>' +
      '<ul class="meta"><li>Run at<strong>' + esc(S.generated_at) + '</strong></li><li>Previous run<strong>' + esc(D.previous_run_id || 'none') + '</strong></li><li>Sources<strong>' + esc(Object.keys(DOC.run.sources || {}).join(' · ') || 'fixture') + '</strong></li><li>Tool<strong>defender-vuln-agent</strong></li></ul>' +
      '<p class="verdict">' + verdict + '</p><p class="sub">' + sub + '</p><div class="tiles">' +
      tile('Emergency', 'critical', em ? 'Critical' : 'Clear', [[em, 'products', 'var(--crit)']], 'KEV-listed CVEs on internet-facing hosts.') +
      tile('Products needing action', 'medium', 'Attention', [[S.products_action, 'of ' + S.products_total]], 'Products scoring above the reporting threshold.') +
      tile('Known exploited', 'critical', D.new_kev.length ? '+' + D.new_kev.length + ' products' : 'KEV', [[S.kev_cves, 'CVEs', 'var(--crit)'], [S.internet_facing_at_risk, 'exposed devices']], 'CISA KEV entries present, and internet-facing devices with a critical CVE.') +
      tile('Coverage', failed.length ? 'medium' : 'low', failed.length ? failed.length + ' source issue(s)' : 'Complete', [[Number(S.devices).toLocaleString(), 'devices'], [S.exposure_score == null ? '–' : S.exposure_score, 'exposure score']], failed.length ? 'Sources not ok: ' + failed.join(', ') : 'All sources collected.') + '</div>'; }
  function toolbar(){ var f = [['all','All'],['critical','Has critical'],['kev','KEV-listed'],['inet','Internet-facing']], s = [['score','Score'],['devices','Devices'],['critical','Critical CVEs']];
    document.getElementById('toolbar').innerHTML = '<span class="tb-label">Show</span>' + f.map(function(x){ return '<button type="button" class="chip' + (state.filter === x[0] ? ' on' : '') + '" data-filter="' + x[0] + '">' + x[1] + '</button>'; }).join('') +
      '<span class="sep"></span><span class="tb-label">Sort</span>' + s.map(function(x){ return '<button type="button" class="chip' + (state.sort === x[0] ? ' on' : '') + '" data-sort="' + x[0] + '">' + x[1] + '</button>'; }).join('') +
      '<span class="sep"></span><button type="button" class="chip" data-open="1">Expand all</button><button type="button" class="chip" data-open="0">Collapse all</button>'; }
  function lists(){ var top = ROWS.slice(0, 10); document.getElementById('top').innerHTML = top.map(function(r){ return card(r, false); }).join('');
    var rows = ROWS.filter(function(r){ return state.filter === 'all' || (state.filter === 'critical' && r.counts.critical > 0) || (state.filter === 'kev' && r.flags.kev) || (state.filter === 'inet' && r.flags.internet_facing); });
    rows = rows.slice().sort(function(a, b){ return state.sort === 'score' ? b.score - a.score : state.sort === 'devices' ? b.assets.count - a.assets.count : b.counts.critical - a.counts.critical; });
    document.getElementById('all').innerHTML = rows.map(function(r){ return card(r, true); }).join('');
    document.getElementById('shown').textContent = rows.length + ' of ' + ROWS.length + ' products'; }
  function appendix(){ document.getElementById('appendix').innerHTML = '<div><h2>How scores are computed</h2><p>Each product\'s score (0 to 100) combines threat signals for its CVEs (CVSS, EPSS, CISA KEV listing, public exploit availability), the context of affected assets (internet exposure, Defender exposure level, device value, criticality tags) and the number of affected devices. Weights live in scoring.yaml.</p></div><div><h2>Grouping</h2><p>Findings are grouped by software product so one row maps to one patch action. Only the three CVEs contributing most to a product\'s score and its most critical assets are shown; full lists are in findings.json.</p></div><div><h2>Data freshness</h2><p>Generated ' + esc(S.generated_at) + '. CVE intelligence is cached for at most 7 days. Sources and their status are listed in the header.</p></div>'; }
  document.addEventListener('click', function(e){ var t = e.target.closest('[data-filter],[data-sort],[data-open],.rowhead'); if (!t) return;
    if (t.dataset.filter) { state.filter = t.dataset.filter; toolbar(); lists(); }
    else if (t.dataset.sort) { state.sort = t.dataset.sort; toolbar(); lists(); }
    else if (t.dataset.open !== undefined) { var v = t.dataset.open === '1'; state.open = {}; if (v) ROWS.forEach(function(r){ state.open['top:' + r.key] = true; state.open['all:' + r.key] = true; }); lists(); }
    else { var k = t.parentElement.dataset.key; state.open[k] = !state.open[k]; lists(); } });
  head(); toolbar(); lists(); appendix();
})();
</script>
</body></html>
```

- [ ] **Step 5: Run tests** → `pytest tests/test_report_html.py -v` → 2 passed. Then render the fixture to a file and open it in a browser to check it against the mockup at 1300 px and 820 px wide: `python -c "import json;from dva.report_html import render;open('/tmp/r.html','w').write(render(json.load(open('tests/fixtures/sample-run/findings.json'))))"`. Fix any visible layout difference from `docs/design/report/Main.dc.html` before committing.
- [ ] **Step 6: Commit** → `git add dva/report_template.html dva/report_html.py tests/test_report_html.py && git commit -m "feat: self-contained HTML report in the Elevate report style"`

---

### Task 15: App registration setup script and permission checklist

**Files:**
- Create: `setup/create-app.sh`, `setup/permissions.md`, `tests/test_setup_script.py`

**Interfaces:**
- Produces: a bash script that, given `--name` (default `defender-vuln-agent`), creates the app and service principal, adds the WindowsDefenderATP and Microsoft Graph application permissions by their well-known ids, prints the env vars, and prints the manual steps. `--dry-run` prints the `az` commands instead of running them (this is what the test exercises).

  Well-known ids: WindowsDefenderATP API app id `fc780465-2017-40d4-a0c5-307022471b92`; Microsoft Graph app id `00000003-0000-0000-c000-000000000000`; Graph `ThreatHunting.Read.All` application role id `dd98c7f5-2d42-42d3-a0e4-633161547251`. The WindowsDefenderATP role ids differ per tenant registration and are resolved at run time with `az ad sp show --id fc780465-2017-40d4-a0c5-307022471b92 --query "appRoles[?value=='<name>'].id"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_setup_script.py
import subprocess

def test_dry_run_prints_expected_commands():
    out = subprocess.run(["bash", "setup/create-app.sh", "--dry-run", "--name", "dva-test"], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "az ad app create --display-name dva-test" in out.stdout
    assert "fc780465-2017-40d4-a0c5-307022471b92" in out.stdout and "dd98c7f5-2d42-42d3-a0e4-633161547251" in out.stdout
    for perm in ["Machine.Read.All", "Vulnerability.Read.All", "Software.Read.All", "SecurityRecommendation.Read.All", "Score.Read.All"]:
        assert perm in out.stdout
    assert "DVA_TENANT_ID" in out.stdout and "admin consent" in out.stdout.lower()
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Write the script**

```bash
#!/usr/bin/env bash
# setup/create-app.sh — create the Entra app registration for defender-vuln-agent.
# Usage: setup/create-app.sh [--name NAME] [--dry-run]
set -euo pipefail
NAME="defender-vuln-agent"; DRY=0
while [[ $# -gt 0 ]]; do case "$1" in --name) NAME="$2"; shift 2;; --dry-run) DRY=1; shift;; *) echo "unknown arg $1" >&2; exit 2;; esac; done
MDE_APP="fc780465-2017-40d4-a0c5-307022471b92"
GRAPH_APP="00000003-0000-0000-c000-000000000000"
GRAPH_THREATHUNTING="dd98c7f5-2d42-42d3-a0e4-633161547251"
MDE_PERMS=(Machine.Read.All Vulnerability.Read.All Software.Read.All SecurityRecommendation.Read.All Score.Read.All)
run() { if [[ $DRY -eq 1 ]]; then echo "+ $*"; else "$@"; fi; }
echo "Creating app registration '$NAME'"
if [[ $DRY -eq 1 ]]; then echo "+ az ad app create --display-name $NAME --sign-in-audience AzureADMyOrg --query appId -o tsv"; APP_ID="<app-id>"; TENANT="<tenant-id>"
else APP_ID=$(az ad app create --display-name "$NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv); TENANT=$(az account show --query tenantId -o tsv); fi
run az ad sp create --id "$APP_ID"
for p in "${MDE_PERMS[@]}"; do
  if [[ $DRY -eq 1 ]]; then echo "+ ROLE=\$(az ad sp show --id $MDE_APP --query \"appRoles[?value=='$p'].id\" -o tsv)"; echo "+ az ad app permission add --id $APP_ID --api $MDE_APP --api-permissions \$ROLE=Role   # $p"
  else ROLE=$(az ad sp show --id "$MDE_APP" --query "appRoles[?value=='$p'].id" -o tsv); [[ -n "$ROLE" ]] || { echo "role $p not found on WindowsDefenderATP" >&2; exit 1; }
       az ad app permission add --id "$APP_ID" --api "$MDE_APP" --api-permissions "$ROLE=Role"; fi
done
run az ad app permission add --id "$APP_ID" --api "$GRAPH_APP" --api-permissions "$GRAPH_THREATHUNTING=Role"   # ThreatHunting.Read.All
if [[ $DRY -eq 1 ]]; then echo "+ az ad app credential reset --id $APP_ID --years 1 --query password -o tsv"; SECRET="<client-secret>"
else SECRET=$(az ad app credential reset --id "$APP_ID" --years 1 --query password -o tsv); fi
cat <<EOT

Set these in your shell (or a gitignored .env):
export DVA_TENANT_ID=$TENANT
export DVA_CLIENT_ID=$APP_ID
export DVA_CLIENT_SECRET=$SECRET

Manual steps remaining:
1. Grant admin consent: az ad app permission admin-consent --id $APP_ID   (needs a Global or Privileged Role Administrator)
2. For Defender for Cloud (phase 2): assign Reader on each subscription:
   az role assignment create --assignee $APP_ID --role Reader --scope /subscriptions/<sub-id>
3. Verify: python -m dva doctor
EOT
```

`setup/permissions.md`: the permission table from the spec plus one line per permission on what breaks without it and what doctor prints.

- [ ] **Step 4: Run tests** → `chmod +x setup/create-app.sh && pytest tests/test_setup_script.py -v` → passed.
- [ ] **Step 5: Commit** → `git add setup tests/test_setup_script.py && git commit -m "feat: app registration setup script and permission checklist"`

---

### Task 16: Agent definition, skills, and MCP registration

**Files:**
- Create: `.claude/agents/vuln-assessor.md`, `.claude/skills/defender-auth/SKILL.md`, `.claude/skills/defender-inventory/SKILL.md`, `.claude/skills/defender-hunting/SKILL.md`, `.claude/skills/vuln-prioritize-report/SKILL.md`, `.mcp.json`, `tests/test_agent_files.py`

**Interfaces:**
- Consumes: every CLI command above.
- Produces: the agent surface. The agent runs on **Sonnet** (`model: sonnet` in frontmatter) to keep cost down; the orchestration is command sequencing, not reasoning-heavy.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_agent_files.py
import json, re
from pathlib import Path

def test_agent_definition():
    text = Path(".claude/agents/vuln-assessor.md").read_text()
    fm = text.split("---")[1]
    assert "name: vuln-assessor" in fm and "model: sonnet" in fm
    assert re.search(r"tools:.*Bash", fm) and "mcp__cve-mcp__" in fm
    for step in ["dva doctor", "dva run new", "dva mde all", "dva hunt", "dva enrich --list", "bulk_cve_lookup", "triage_cve", "dva enrich --store", "dva score", "dva report --all"]:
        assert step in text
    assert "never read raw" in text.lower() or "never cat" in text.lower()

def test_skills_and_mcp():
    for s in ["defender-auth", "defender-inventory", "defender-hunting", "vuln-prioritize-report"]:
        t = Path(f".claude/skills/{s}/SKILL.md").read_text()
        assert t.startswith("---") and f"name: {s}" in t and "description:" in t
    mcp = json.loads(Path(".mcp.json").read_text())
    assert mcp["mcpServers"]["cve-mcp"]["command"] and "cve_mcp.server" in " ".join(mcp["mcpServers"]["cve-mcp"]["args"])
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Write the files**

`.mcp.json`:
```json
{
  "mcpServers": {
    "cve-mcp": {
      "command": "${CVE_MCP_PYTHON:-python}",
      "args": ["-m", "cve_mcp.server"],
      "env": { "NVD_API_KEY": "${NVD_API_KEY}", "GITHUB_TOKEN": "${GITHUB_TOKEN}" }
    }
  }
}
```
(Install the server into the same venv: `pip install -e /path/to/cve-mcp-server`; set `CVE_MCP_PYTHON` to that venv's python if different.)

`.claude/agents/vuln-assessor.md`:
```markdown
---
name: vuln-assessor
description: Runs a read-only vulnerability assessment against Microsoft Defender, enriches the top CVEs per product through the cve-mcp server, scores software products and writes Markdown, HTML and JSON reports. Use for "assess vulnerabilities", "what should we patch first", "weekly vuln report".
model: sonnet
tools: Bash, Read, Glob, Grep, mcp__cve-mcp__bulk_cve_lookup, mcp__cve-mcp__triage_cve, mcp__cve-mcp__lookup_cve, mcp__cve-mcp__check_kev_status, mcp__cve-mcp__get_epss_score
---

You are the vulnerability assessor for this repository. You run `python -m dva` commands in order, read only their printed summaries, call the CVE MCP tools for the exact ids `dva enrich --list` prints, and finish with a short summary. You never change anything in Defender or Azure; the app registration has no write permissions.

## Workflow

1. `python -m dva doctor`. If it exits non-zero, stop and report which permissions failed, pointing at setup/permissions.md.
2. `python -m dva run new` and export its output as `DVA_RUN` for the remaining commands (`export DVA_RUN=$(python -m dva run new)`).
3. Collect: `python -m dva mde all`, then `python -m dva hunt internet-facing exploited-cves device-tags`. Warnings about a single failed source are fine; continue.
4. Enrich: run `python -m dva enrich --list`. For each printed line `{"chunk": n, "cve_ids": [...]}` call `bulk_cve_lookup` with `cve_ids` set to that list, save the tool result unchanged to `$DVA_RUN/cve-chunk-<n>.json` with a heredoc, and run `python -m dva enrich --store $DVA_RUN/cve-chunk-<n>.json`. Then for every CVE the bulk result marks as in KEV or with EPSS ≥ 0.5, call `triage_cve` with `cve_id` and `depth` = `standard`, save to `$DVA_RUN/cve-triage-<id>.json`, and store it the same way. If the CVE server is unreachable, say so and continue; scoring works without it.
5. `python -m dva score`.
6. `python -m dva report --all`.
7. Read `$DVA_RUN/report.md` (this is the only run file you read) and reply with: the three top products with score and one-line reason, the count of products needing action, any source marked partial or failed, and the path of the run directory.

## Rules

- Never read raw run files (`vulns.jsonl`, `machines.json`, `hunt-*.json`, `enrichment.json`, `findings.json`). Summaries and `report.md` are enough. Never `cat` them.
- Ad hoc KQL only through `python -m dva hunt --kql "<query>" --name <name>`; read-only tables only; keep results under 10,000 rows with `summarize` or `take`.
- Do not paste CVE server results into your reply; store them to files and let `dva` merge them.
- If asked to change scoring, edit `config/scoring.yaml` and re-run steps 5 and 6 only.
```

Skills (each `SKILL.md` has frontmatter `name`, `description`, then a "When to use", "Commands", "Outputs", and "Gotchas" section; keep each under 60 lines):

- `defender-auth`: env vars, `dva doctor`, token cache location, what each permission unlocks, link to `setup/permissions.md`.
- `defender-inventory`: `dva mde machines|vulns|recommendations|score|all`, output files, the 50k page size, rate limits (30 calls/min on the export API), `--fixture` for offline runs.
- `defender-hunting`: `dva hunt <names>`, the five named queries and what each returns, `--kql` guard, the 10,000 row cap and how to narrow (`summarize`, `where Timestamp > ago(1d)`), `--timespan`.
- `vuln-prioritize-report`: the enrich loop with the exact tool names and argument names (`bulk_cve_lookup(cve_ids)`, `triage_cve(cve_id, depth)`), `dva enrich --list/--store`, `dva score`, `dva report --all`, where outputs land, how to tune `scoring.yaml`.

- [ ] **Step 4: Run tests** → `pytest tests/test_agent_files.py -v` → passed.
- [ ] **Step 5: Commit** → `git add .claude .mcp.json tests/test_agent_files.py && git commit -m "feat: vuln-assessor agent, skills and CVE MCP registration"`

---

### Task 17: Offline end-to-end run and README

**Files:**
- Create: `tests/fixtures/mde/all.json` (list of pages for `mde all --fixture`), `tests/fixtures/hunting/internet-facing.json`, `tests/fixtures/cve/bulk.json`, `tests/test_e2e.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the whole CLI.
- Produces: proof that `run new → mde all --fixture → hunt --fixture → enrich --list → enrich --store → score → report --all` works without credentials, and a README that documents the setup, the agent, and the offline demo.

  `tests/fixtures/mde/all.json` is a JSON list of the four responses `mde all` requests in order: machines (one page), vulns (one page), recommendations, exposure score, then `ByMachineGroups`; reuse the Task 6 fixture bodies. `tests/fixtures/cve/bulk.json` is a plausible `bulk_cve_lookup` result for `CVE-2026-21887` and `CVE-2026-21335` in the shape Task 11's `parse_store` accepts; **on the first real run, replace it with a real captured result** (the agent saves chunks to the run directory) so the parser is verified against the server's actual keys, and adjust `_one()` if a key differs. Record that step as a checklist item in the README.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_e2e.py
import json, os, subprocess, sys
from pathlib import Path

FX = Path(__file__).parent / "fixtures"

def dva(*args, env):
    r = subprocess.run([sys.executable, "-m", "dva", *args], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr + r.stdout
    return r.stdout

def test_offline_pipeline(tmp_path):
    env = dict(os.environ, DVA_RUNS_DIR=str(tmp_path / "runs"), DVA_CACHE_DIR=str(tmp_path / "cache"))
    run_dir = dva("run", "new", env=env).strip(); env["DVA_RUN"] = run_dir
    dva("mde", "all", "--fixture", str(FX / "mde" / "all.json"), env=env)
    dva("hunt", "internet-facing", "--fixture", str(FX / "hunting" / "internet-facing.json"), env=env)
    listing = dva("enrich", "--list", env=env)
    chunks = [json.loads(l) for l in listing.splitlines() if l.startswith("{")]
    assert chunks and "CVE-2026-21887" in chunks[0]["cve_ids"]
    dva("enrich", "--store", str(FX / "cve" / "bulk.json"), env=env)
    out = dva("score", env=env)
    assert "Connect Secure" in out
    dva("report", "--all", env=env)
    for f in ["findings.json", "report.md", "report.html", "report.json"]:
        assert (Path(run_dir) / f).exists()
    doc = json.loads((Path(run_dir) / "findings.json").read_text())
    assert doc["products"][0]["driving_cves"][0]["kev"] is True
```

- [ ] **Step 2: Run to verify fail** → FAIL (fixtures missing).
- [ ] **Step 3: Write the fixtures** as described, then run → `pytest tests/test_e2e.py -v` → passed. Run the full suite: `pytest -q` → all passed.
- [ ] **Step 4: Update README.md** with sections: What it does; Setup (venv, `pip install -e ".[dev]"`, install cve-mcp-server into the venv, `setup/create-app.sh`, env vars, `python -m dva doctor`); Running the agent (`claude` then ask for an assessment, or the manual command sequence); Offline demo (the e2e command list with `--fixture`); Tuning (`config/scoring.yaml` keys); Outputs (run directory layout); First-run checklist (capture a real `bulk_cve_lookup` result into `tests/fixtures/cve/bulk.json`).
- [ ] **Step 5: Commit** → `git add tests README.md && git commit -m "test: offline end-to-end pipeline and README"`

---

### Task 18 (phase 2): Defender for Cloud collector with de-duplication

**Files:**
- Create: `dva/cloud.py`, `tests/test_cloud.py`, `tests/fixtures/cloud/subassessments.json`
- Modify: `dva/rollup.py` (add cloud findings and image assets), `dva/__main__.py` (`COMMAND_MODULES` add `dva.cloud`), `config/sources.yaml` (`cloud: true`, subscriptions), `.claude/skills/defender-cloud/SKILL.md`, agent workflow step 3 (`python -m dva cloud vulns` when enabled)

**Interfaces:**
- Consumes: `Client` with `ARM_SCOPE`, `Run`, `load_sources`.
- Produces: `dva.cloud.ARM_BASE = "https://management.azure.com"`, `RG_PATH = "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"`, `collect_vulns(client, run, subscriptions) -> int` posting `{"subscriptions": [...], "query": QUERY, "options": {"$top": 1000, "$skip": n}}` pages until `count` < 1000 or `$skipToken` absent (Resource Graph paging uses `options.$skipToken` from the response's `$skipToken`), writing `cloud-vulns.jsonl` rows `{resource_id, resource_type, subscription, resource_group, cve_id, severity, cvss, patchable, image_repo, image_digest, display_name, assessment_key, duplicate_of}`. `QUERY`:

  ```kusto
  securityresources
  | where type == "microsoft.security/assessments/subassessments"
  | extend props = parse_json(properties)
  | where props.category in~ ("Vulnerability", "Container Vulnerability", "Image Vulnerability") or props.additionalData.assessedResourceType in~ ("ServerVulnerability", "ContainerRegistryVulnerability", "AzureContainerRegistryVulnerability", "AzureContainerImageVulnerability")
  | project id, subscriptionId, resourceGroup, assessmentKey = extract(".*assessments/(.+?)/.*", 1, id), cveId = tostring(props.id), displayName = tostring(props.displayName), severity = tostring(props.status.severity), resourceId = tostring(props.resourceDetails.id), assessedType = tostring(props.additionalData.assessedResourceType), cvss = todouble(props.additionalData.cvss.["3.0"].base), patchable = tobool(props.additionalData.patchable), repo = tostring(props.additionalData.repositoryName), digest = tostring(props.additionalData.imageDigest)
  | where cveId startswith "CVE-"
  ```

  De-duplication in `rollup.build`: a cloud row whose `resource_id` equals an MDE asset's `azure_resource_id` (case-insensitive) or whose resource name (last path segment) equals an MDE asset name's first label is marked `duplicate_of = <mde id>` and skipped; other server rows become `Asset(kind="device")` keyed by resource id; image rows become `Asset(kind="image", name=f"{repo}@{digest[:12]}")` and products keyed by `product_key(registry_host_from_repo, repo)`.

- [ ] **Step 1: Write the failing test** covering: paging with `$skipToken`, rows written, a VM row de-duplicated against an MDE machine with matching `azure_resource_id`, an image row producing an image asset and product.

```python
# tests/test_cloud.py
from dva.cloud import collect_vulns, ARM_BASE, RG_PATH
from dva.http import Client
from dva.run import Run
from dva.rollup import build
from dva.model import Asset
from tests.fakes import FakeSession, FakeResponse, FakeTokens

ROW_VM = {"id": "/subscriptions/s1/.../assessments/k1/subassessments/x", "subscriptionId": "s1", "resourceGroup": "rg", "assessmentKey": "k1", "cveId": "CVE-2026-21335", "displayName": "Win32k EoP", "severity": "High", "resourceId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vpn-gw-01", "assessedType": "ServerVulnerability", "cvss": 8.8, "patchable": True, "repo": "", "digest": ""}
ROW_IMG = {"id": "/subscriptions/s1/.../assessments/k2/subassessments/y", "subscriptionId": "s1", "resourceGroup": "rg", "assessmentKey": "k2", "cveId": "CVE-2026-1097", "displayName": "nginx QUIC overflow", "severity": "Critical", "resourceId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/prodacr", "assessedType": "AzureContainerRegistryVulnerability", "cvss": 9.1, "patchable": True, "repo": "prodacr.azurecr.io/nginx", "digest": "sha256:abcdef1234567890"}

def test_paging_and_dedup(tmp_path):
    run = Run.create(tmp_path)
    run.write_json("machines.json", [{"id": "m1", "name": "vpn-gw-01.corp.example", "exposure_level": "High", "device_value": "High", "tags": [], "group": "g", "is_internet_facing": True, "azure_resource_id": ROW_VM["resourceId"]}])
    run.write_jsonl("vulns.jsonl", [])
    s = FakeSession({f"POST {ARM_BASE}{RG_PATH}": [FakeResponse(200, {"data": [ROW_VM], "count": 1, "$skipToken": "t1"}), FakeResponse(200, {"data": [ROW_IMG], "count": 1})]})
    c = Client(FakeTokens(), "s", base_url=ARM_BASE, session=s, sleep=lambda x: None)
    assert collect_vulns(c, run, ["s1"]) == 2
    assert s.calls[1][2]["json"]["options"]["$skipToken"] == "t1"
    rows = list(run.read_jsonl("cloud-vulns.jsonl"))
    assert rows[0]["cve_id"] == "CVE-2026-21335" and rows[1]["image_repo"] == "prodacr.azurecr.io/nginx"
    products, assets = build(run)
    assert "prodacr.azurecr.io/nginx" in products and assets["prodacr.azurecr.io/nginx@sha256:abcde"].kind == "image"
    assert not any(a.kind == "device" and a.id != "m1" for a in assets.values())  # VM row de-duplicated
```

- [ ] **Step 2: Run to verify fail**, **Step 3: implement `dva/cloud.py` and the `rollup.build` extension** (cloud rows are read after MDE rows; the dedup rule above; image products get `vendor = registry host`, `name = repository path`, `versions = {tag or digest[:12]: 1}`), **Step 4: run tests** → passed, **Step 5: commit** → `git commit -m "feat: Defender for Cloud collector with MDE de-duplication"`.

---

## Self-review

**Spec coverage.** Auth + doctor (Tasks 3, 8, 15); MDE collectors (6); hunting with five named queries and the row cap (7); run directories, manifest, per-source status, logs (5); enrichment narrowed to top CVEs per product with cache and the `bulk_cve_lookup` chunking (11, 16); roll-up by product with asset context and exploit upgrade from the hunting KB (9); scoring formulas, bands, reason templates (10); `findings.json` shape and diff (12); three renderers including the Elevate-styled HTML (13, 14); agent definition with Sonnet, skills, MCP registration, the "never read raw files" rule (16); offline pipeline and golden tests (13, 17); phase 2 cloud with de-duplication (18). Error handling is spread across Tasks 4 (retry), 5 and 6 (manifest status), 7 (cap → partial), 11 (missing intel), 12 (`partial_intel`).

**Placeholder scan.** No TBD/TODO. Task 11 originally had redundant sort calls; replaced with the single `_rank_key` below. Task 18 leaves the implementation body to the executor but pins the query, the paging contract, the dedup rule and the test.

**Type consistency.** `Run.set_source(name, status, count, error)` used identically in 6, 7, 18. `product_score(...) -> ScoredProduct` fields `driving`, `counts`, `flags`, `top_assets` are what `score_cmd` reads. `CveIntel` field names match `IntelCache` and `parse_store`. `resolve_run`/`add_run_arg` are shared by every command. The findings keys used by `report_md`, `report_html` and the fixture match Task 12's writer.
