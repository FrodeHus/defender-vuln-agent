"""Multi-tenant support.

Each tenant lives in its own directory under ``tenants/`` (or ``$DVA_TENANTS_DIR``):

    tenants/<name>/.env           credentials for that tenant only (DVA_TENANT_ID, DVA_CLIENT_ID, ...)
    tenants/<name>/runs/          this tenant's run directories
    tenants/<name>/.cache/        this tenant's token cache and CVE intel cache
    tenants/<name>/scoring.yaml   optional override of config/scoring.yaml
    tenants/<name>/sources.yaml   optional override of config/sources.yaml (merged over the defaults)

Activating a tenant loads its .env with override (so nothing from the shell or the repo .env leaks
across tenants) and points DVA_RUNS_DIR / DVA_CACHE_DIR / DVA_TENANT_DIR / DVA_TENANT_NAME at it.
With no tenants directory the tool behaves as a single-tenant install.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dva.dotenv import parse
from dva.errors import DvaError

ROOT = Path(__file__).resolve().parent.parent
_SCOPED_KEYS = ("DVA_TENANT_ID", "DVA_CLIENT_ID", "DVA_CLIENT_SECRET", "DVA_CLIENT_CERT_PATH",
                "DVA_CLIENT_CERT_THUMBPRINT", "DVA_TENANT_NAME", "DVA_RUN")

ENV_TEMPLATE = """# Credentials for this tenant only. Never commit this file.
DVA_TENANT_ID=
DVA_CLIENT_ID=
DVA_CLIENT_SECRET=
# Or use a certificate instead of a secret:
# DVA_CLIENT_CERT_PATH=
# DVA_CLIENT_CERT_THUMBPRINT=
# Friendly name shown in reports (defaults to the directory name):
# DVA_TENANT_NAME=
"""


@dataclass(frozen=True)
class Tenant:
    name: str
    dir: Path


def tenants_root() -> Path:
    return Path(os.environ.get("DVA_TENANTS_DIR") or ROOT / "tenants")


def list_tenants() -> list[str]:
    root = tenants_root()
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))


def resolve_name(query: str) -> str:
    """Exact (case-insensitive) match first, then a unique case-insensitive prefix."""
    names = list_tenants()
    q = query.strip().lower()
    exact = [n for n in names if n.lower() == q]
    if exact:
        return exact[0]
    prefix = [n for n in names if n.lower().startswith(q)]
    if len(prefix) == 1:
        return prefix[0]
    if len(prefix) > 1:
        raise DvaError(f"ambiguous tenant '{query}': matches {', '.join(prefix)}")
    raise DvaError(f"unknown tenant '{query}'; known tenants: {', '.join(names) or 'none'} (see `dva tenant list`)")


def activate(query: str) -> Tenant:
    name = resolve_name(query)
    d = tenants_root() / name
    env_file = d / ".env"
    if not env_file.is_file():
        raise DvaError(f"tenant '{name}' has no .env at {env_file}; run `dva tenant init {name}` and fill it in")
    # Drop anything tenant-scoped inherited from the shell or a previously activated tenant.
    for k in _SCOPED_KEYS:
        os.environ.pop(k, None)
    for k, v in parse(env_file.read_text(encoding="utf-8")).items():
        os.environ[k] = v
    (d / "runs").mkdir(parents=True, exist_ok=True)
    (d / ".cache").mkdir(parents=True, exist_ok=True, mode=0o700)
    os.environ["DVA_RUNS_DIR"] = str(d / "runs")
    os.environ["DVA_CACHE_DIR"] = str(d / ".cache")
    os.environ["DVA_TENANT_DIR"] = str(d)
    os.environ.setdefault("DVA_TENANT_NAME", name)
    os.environ["DVA_TENANT"] = name
    return Tenant(name, d)


def current() -> Tenant | None:
    name = os.environ.get("DVA_TENANT")
    d = os.environ.get("DVA_TENANT_DIR")
    return Tenant(name, Path(d)) if name and d else None


def override_path(filename: str) -> Path | None:
    """Path to a per-tenant config override, if a tenant is active and the file exists."""
    d = os.environ.get("DVA_TENANT_DIR")
    if not d:
        return None
    p = Path(d) / filename
    return p if p.is_file() else None


def init(name: str) -> Path:
    if not name or "/" in name or name.startswith(".") or name != name.strip():
        raise DvaError(f"invalid tenant name '{name}'")
    d = tenants_root() / name
    if (d / ".env").exists():
        raise DvaError(f"tenant '{name}' already exists at {d}")
    (d / "runs").mkdir(parents=True, exist_ok=True)
    (d / ".cache").mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(d / ".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(ENV_TEMPLATE)
    return d


def register(sub) -> None:
    p = sub.add_parser("tenant", help="List, create and show tenants (each with its own credentials, runs and cache)")
    s = p.add_subparsers(dest="tenant_cmd", required=True)
    s.add_parser("list", help="print configured tenant names").set_defaults(func=_list)
    i = s.add_parser("init", help="create tenants/<name>/ with a .env template"); i.add_argument("name"); i.set_defaults(func=_init)
    s.add_parser("show", help="print the active tenant and its directories").set_defaults(func=_show)


def _list(args) -> int:
    for n in list_tenants():
        print(n)
    return 0


def _init(args) -> int:
    d = init(args.name)
    print(f"created {d}; fill in {d / '.env'} then run `dva --tenant {args.name} doctor`")
    return 0


def _show(args) -> int:
    t = current()
    if t is None:
        print("no tenant active (single-tenant mode); select one with --tenant NAME or DVA_TENANT=NAME")
        return 0
    print(f"tenant: {t.name}\ndir: {t.dir}\nruns: {os.environ.get('DVA_RUNS_DIR')}\ncache: {os.environ.get('DVA_CACHE_DIR')}")
    return 0
