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
_HAS_LIMIT = re.compile(r"\|\s*(take|limit)\s+\d+\s*$", re.I)


def _cap_query(kql: str) -> str:
    if _HAS_LIMIT.search(kql.rstrip()):
        return kql
    return f"{kql.rstrip()}\n| take {ROW_CAP}"


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
    kql = _cap_query(kql)
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
            kql = load_query(n)
        except DvaError as e:
            source = f"hunting.{n}"
            run.set_source(source, "failed", error=str(e))
            run.log(f"{source} failed: {e}")
            failures += 1; print(f"warning: {e}")
            continue
        try:
            run_query(client, run, n, kql)
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
