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


def _credentials_line() -> str:
    from dva import tenant
    from dva.dotenv import find_env_file
    t = tenant.current()
    if t is not None:
        return f"tenant: {t.name} (credentials from {t.dir / '.env'})"
    env = find_env_file()
    return f"tenant: single-tenant mode (credentials from {env if env else 'the shell environment'})"


def run(args) -> int:
    from dva.mde import make_client
    def factory(scope, base_url):
        c = make_client(scope, base_url); c.max_attempts = 2; return c
    print(_credentials_line())
    results = run_checks(checks(load_sources()), factory)
    print(format_table(results))
    failed = [c.permission for c, ok, _ in results if not ok]
    if failed:
        print(f"doctor: {len(failed)} check(s) failed: {', '.join(failed)}. See setup/permissions.md.")
        return 1
    print("doctor: all checks passed.")
    return 0
