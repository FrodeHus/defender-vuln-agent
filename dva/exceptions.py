"""Accepted-risk exceptions, per tenant.

Exceptions live in ``tenants/<name>/exceptions.yaml`` while a tenant is active, else
``config/exceptions.yaml``. Both are gitignored; ``config/exceptions.example.yaml`` is the
committed template. Exceptions are managed only through this CLI — never by hand-editing the file.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

from dva.errors import DvaError
from dva.model import Product


@dataclass
class Exception_:
    product: str | None
    cve: str | None
    reason: str
    until: str
    owner: str | None
    added: str
    source: str


def path_for_current() -> Path:
    d = os.environ.get("DVA_TENANT_DIR")
    if d:
        return Path(d) / "exceptions.yaml"
    return Path("config/exceptions.yaml")


def load(path: Path) -> list[Exception_]:
    path = Path(path)
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise DvaError(f"corrupt exceptions file {path}: {exc}")
    items = data.get("exceptions") if isinstance(data, dict) else None
    if items is None:
        items = []
    if not isinstance(items, list):
        raise DvaError(f"corrupt exceptions file {path}: 'exceptions' must be a list")
    def _str(v) -> str:
        # YAML auto-types bare ISO-looking dates/datetimes; normalize back to plain strings so
        # `until`/`added` are always `str` regardless of whether the value was quoted in the file.
        return v.isoformat() if hasattr(v, "isoformat") else str(v)

    result: list[Exception_] = []
    try:
        for it in items:
            result.append(Exception_(
                product=it.get("product"), cve=it.get("cve"), reason=it.get("reason") or "",
                until=_str(it["until"]), owner=it.get("owner"), added=_str(it.get("added") or ""), source=it.get("source") or "user",
            ))
    except (AttributeError, KeyError, TypeError) as exc:
        raise DvaError(f"corrupt exceptions file {path}: {exc}")
    return result


def save(path: Path, items: list[Exception_]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"exceptions": [asdict(i) for i in items]}
    text = yaml.safe_dump(doc, sort_keys=False)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def split(items: list[Exception_], today: date) -> tuple[list[Exception_], list[Exception_]]:
    """(active, expired); an item whose `until` is before `today` is expired."""
    active, expired = [], []
    for it in items:
        try:
            until = date.fromisoformat(it.until)
        except (TypeError, ValueError):
            active.append(it)  # unparsable date: treat as active rather than silently dropping it
            continue
        (expired if until < today else active).append(it)
    return active, expired


def apply(products: dict[str, Product], items_active: list[Exception_]) -> tuple[dict[str, Product], dict[str, Exception_]]:
    """Removes excepted CVEs from products, drops products with an active product exception.

    Returns (remaining products, {key: exception} for dropped products).
    """
    product_exc = {i.product: i for i in items_active if i.product}
    cve_exc_ids = {i.cve for i in items_active if i.cve}
    remaining: dict[str, Product] = {}
    dropped: dict[str, Exception_] = {}
    for key, p in products.items():
        if key in product_exc:
            dropped[key] = product_exc[key]
            continue
        if cve_exc_ids:
            for cid in list(p.cves):
                if cid in cve_exc_ids:
                    del p.cves[cid]
        remaining[key] = p
    return remaining, dropped


def register(sub) -> None:
    p = sub.add_parser("exception", help="Manage accepted-risk exceptions for the active tenant")
    s = p.add_subparsers(dest="exception_cmd", required=True)

    s.add_parser("list", help="list exceptions (kind, key, until, owner, status)").set_defaults(func=_list)

    a = s.add_parser("add", help="add an accepted-risk exception")
    a.add_argument("--product", help="product key (vendor/name), e.g. openssl/openssl")
    a.add_argument("--cve", help="CVE id, e.g. CVE-2023-0286")
    a.add_argument("--reason", required=True)
    a.add_argument("--until", required=True, help="ISO date (YYYY-MM-DD); must not be in the past")
    a.add_argument("--owner")
    a.set_defaults(func=_add)

    r = s.add_parser("remove", help="remove an accepted-risk exception")
    r.add_argument("--product", help="product key to remove")
    r.add_argument("--cve", help="CVE id to remove")
    r.set_defaults(func=_remove)


def _validate_key_against_latest_run(product: str | None, cve: str | None) -> None:
    from dva.rollup import build
    from dva.run import Run, runs_dir
    latest = Run.latest(runs_dir())
    if latest is None:
        print("warning: no run found; could not validate the key against a run")
        return
    products, _ = build(latest)
    if product and product not in products:
        print(f"warning: product '{product}' not found in latest run {latest.id}")
    if cve and not any(cve in p.cves for p in products.values()):
        print(f"warning: CVE '{cve}' not found in latest run {latest.id}")


def _add(args) -> int:
    if not args.product and not args.cve:
        raise DvaError("exception add requires --product or --cve")
    if args.product and args.cve:
        raise DvaError("exception add takes either --product or --cve, not both")
    try:
        until = date.fromisoformat(args.until)
    except ValueError:
        raise DvaError(f"invalid --until date '{args.until}'; expected YYYY-MM-DD")
    if until < date.today():
        raise DvaError(f"--until {args.until} is in the past")
    _validate_key_against_latest_run(args.product, args.cve)
    path = path_for_current()
    items = load(path)
    items.append(Exception_(product=args.product, cve=args.cve, reason=args.reason, until=args.until,
                             owner=args.owner, added=datetime.now(timezone.utc).isoformat(), source="user"))
    save(path, items)
    print(f"added exception for {'product ' + args.product if args.product else 'CVE ' + args.cve} until {args.until} ({path})")
    return 0


def _remove(args) -> int:
    if not args.product and not args.cve:
        raise DvaError("exception remove requires --product or --cve")
    path = path_for_current()
    items = load(path)
    kept = [i for i in items if not ((args.product and i.product == args.product) or (args.cve and i.cve == args.cve))]
    if len(kept) == len(items):
        raise DvaError(f"no matching exception found for {'product ' + args.product if args.product else 'CVE ' + args.cve}")
    save(path, kept)
    print(f"removed exception for {'product ' + args.product if args.product else 'CVE ' + args.cve}")
    return 0


def _list(args) -> int:
    items = load(path_for_current())
    if not items:
        print("no exceptions")
        return 0
    today = date.today()
    print(f"{'kind':<8} {'key':<34} {'until':<12} {'owner':<12} status")
    for it in items:
        kind = "product" if it.product else "cve"
        key = it.product or it.cve or ""
        try:
            status = "expired" if date.fromisoformat(it.until) < today else "active"
        except (TypeError, ValueError):
            status = "invalid"
        print(f"{kind:<8} {key:<34} {it.until:<12} {(it.owner or '-'):<12} {status}")
    return 0
