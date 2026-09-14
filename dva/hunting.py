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


def _evidence_kql(run: Run) -> str | None:
    """Installation-path evidence scoped to the products the report will list (needs vulns.jsonl)."""
    from dva.config import load_scoring
    from dva.evidence import build_query, listed_pairs
    pairs = listed_pairs(run, load_scoring())
    return build_query(pairs) if pairs else None


def _kql_id_list(values) -> str:
    return ", ".join('"' + v.replace('"', '\\"') + '"' for v in values)


def _mitigations_kql() -> str | None:
    """Compliance for the tenant's chosen compensating controls (scoring.yaml: mitigation_configs)."""
    from dva.config import load_scoring
    ids = load_scoring().mitigation_configs
    if not ids:
        return None
    return load_query("mitigations").replace("__CONFIG_IDS__", _kql_id_list(ids))


def run_named(client: Client, run: Run, names: list[str]) -> int:
    failures = 0
    for n in names:
        try:
            if n == "evidence":
                kql = _evidence_kql(run)
                skip_summary = "Hunting evidence: no listed products yet; skipped."
            elif n == "mitigations":
                kql = _mitigations_kql()
                skip_summary = "Hunting mitigations: skipped: no mitigation_configs configured."
            else:
                kql = load_query(n)
                skip_summary = None
            if kql is None:
                run.write_json(f"hunt-{n}.json", {"schema": [], "results": [], "capped": False})
                run.set_source(f"hunting.{n}", "ok", count=0)
                run.summary(skip_summary)
                continue
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
    p.add_argument("names", nargs="*", help="named queries from dva/queries, or 'evidence' (installation paths of the listed products; run after mde vulns)")
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
