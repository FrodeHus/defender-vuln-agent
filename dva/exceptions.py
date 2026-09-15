"""Accepted-risk exceptions, per tenant.

Exceptions live in ``tenants/<name>/exceptions.yaml`` while a tenant is active, else
``config/exceptions.yaml``. Both are gitignored; ``config/exceptions.example.yaml`` is the
committed template. Exceptions are managed only through this CLI — never by hand-editing the file.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from dva.errors import DvaError
from dva.model import Product

_TOP_LEVEL_FOLDER_RE = re.compile(
    r"^(?:%ProgramFiles%\\|%ProgramFiles\(x86\)%\\|%LOCALAPPDATA%\\|/opt/|/usr/lib/)([^\\/]+)"
)


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

    A product left with no CVEs after CVE-exception removal is also dropped (nothing left to
    score or list it for) — it is not added to the returned `dropped` mapping since no exception
    names it directly; it simply has no open findings any more.

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
        if not p.cves:
            continue
        remaining[key] = p
    return remaining, dropped


def embedded_reasons(name: str | None, paths: list[dict] | None, cfg) -> list[str]:
    """Why a product looks like an embedded component: its name matches `exception_components`,
    or its evidence paths span 3+ distinct top-level product folders."""
    reasons: list[str] = []
    name_l = (name or "").lower()
    if any(component.lower() in name_l for component in cfg.exception_components):
        reasons.append("embedded component")
    top_level: set[str] = set()
    for entry in paths or []:
        m = _TOP_LEVEL_FOLDER_RE.match(entry.get("path") or "")
        if m:
            top_level.add(m.group(1))
    if len(top_level) >= 3:
        reasons.append(f"bundled across {len(top_level)} products")
    return reasons


def suggest(run, cfg) -> list[dict]:
    """Score-reason suggestions for accepted-risk exceptions (spec §1).

    Reuses `score_cmd.compute` for "the products the report would list" so this stays exactly
    in sync with the report, and so products already under an active exception are skipped for
    free (`compute` removes them before scoring). Reasons, per product:
    - "embedded component": `name` contains one of `cfg.exception_components` (case-insensitive);
    - "bundled across N products": the product's own evidence paths span 3+ distinct top-level
      product folders (the segment after %ProgramFiles%\\, %ProgramFiles(x86)%\\, %LOCALAPPDATA%\\,
      /opt/ or /usr/lib/);
    - "no vendor fix": no Defender recommendation for the product, or its remediation type is
      Uninstall/ConfigurationChange;
    - "end of support": the product is flagged EOS.
    Only products with at least one reason are returned.
    """
    from dva.cache import IntelCache
    from dva.run import cache_dir
    from dva.score_cmd import compute

    doc = compute(run, cfg, IntelCache(cache_dir() / "cve", cfg.cache_ttl_days))
    suggested_until = (date.today() + timedelta(days=90)).isoformat()
    out: list[dict] = []
    for row in doc["products"]:
        reasons = embedded_reasons(row.get("product"), row.get("paths"), cfg)
        remediation_type = row.get("remediation_type")
        if not remediation_type or remediation_type in ("Uninstall", "ConfigurationChange"):
            reasons.append("no vendor fix")
        if row.get("eos"):
            reasons.append("end of support")
        if not reasons:
            continue
        out.append({"product": row["key"], "name": row.get("product"), "reasons": reasons, "suggested_until": suggested_until})
    return out


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

    g = s.add_parser("suggest", help="suggest accepted-risk exceptions for products the report would list")
    from dva.run import add_run_arg
    add_run_arg(g)
    g.set_defaults(func=_suggest)


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
    new_item = Exception_(product=args.product, cve=args.cve, reason=args.reason, until=args.until,
                           owner=args.owner, added=datetime.now(timezone.utc).isoformat(), source="user")
    key = args.product or args.cve
    existing_idx = next((i for i, it in enumerate(items) if it.product == args.product and it.cve == args.cve), None)
    if existing_idx is None:
        items.append(new_item)
        print(f"added exception for {key} until {args.until} ({path})")
    else:
        items[existing_idx] = new_item
        print(f"updated exception for {key} until {args.until} ({path})")
    save(path, items)
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


def _suggest(args) -> int:
    from dva.config import load_scoring
    from dva.run import resolve_run
    run = resolve_run(args)
    suggestions = suggest(run, load_scoring())
    for s in suggestions:
        print(json.dumps(s))
    run.write_json("exception-suggestions.json", suggestions)
    if suggestions:
        print(f"{len(suggestions)} exception suggestion(s) written to exception-suggestions.json")
    else:
        print("no exception suggestions")
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
