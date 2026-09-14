from __future__ import annotations
import json
import os
from pathlib import Path
from dva.auth import TokenProvider, MDE_SCOPE
from dva.errors import DvaError
from dva.http import Client
from dva.run import Run, add_run_arg, resolve_run, cache_dir

MDE_BASE = "https://api.securitycenter.microsoft.com/api"


def make_client(scope: str = MDE_SCOPE, base_url: str = MDE_BASE) -> Client:
    return Client(TokenProvider.from_env(cache_dir()), scope, base_url=base_url)


class _Guard:
    """Context manager: marks the source failed in the manifest if the body raises, then re-raises."""

    def __init__(self, run: Run, source: str):
        self.run, self.source = run, source

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        if ev is not None:
            self.run.set_source(self.source, "failed", error=str(ev))
            self.run.log(f"{self.source} failed: {ev}")
        return False


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
    with _Guard(run, "mde.machines"):
        machines = [_norm_machine(m) for m in client.paged("/machines", {"$top": 10000})]
        run.write_json("machines.json", machines)
        run.set_source("mde.machines", "ok", count=len(machines))
        run.summary(f"MDE machines: {len(machines)} devices collected.")
        return len(machines)


def collect_vulns(client: Client, run: Run, page_size: int = 50000) -> int:
    with _Guard(run, "mde.vulns"):
        tmp_name = "vulns.jsonl.tmp"
        try:
            rows = (
                _norm_vuln(v)
                for v in client.paged("/machines/SoftwareVulnerabilitiesByMachine", {"pageSize": page_size})
                if v.get("cveId")
            )
            n = run.write_jsonl(tmp_name, rows)
            os.replace(run.path(tmp_name), run.path("vulns.jsonl"))
        except BaseException:
            tmp_path = run.path(tmp_name)
            if tmp_path.exists():
                tmp_path.unlink()
            raise
        run.set_source("mde.vulns", "ok", count=n)
        run.summary(f"MDE vulnerabilities: {n} device/software/CVE rows written to vulns.jsonl.")
        return n


def collect_recommendations(client: Client, run: Run) -> int:
    with _Guard(run, "mde.recommendations"):
        recs = [_norm_rec(r) for r in client.paged("/recommendations")]
        run.write_json("recommendations.json", recs)
        run.set_source("mde.recommendations", "ok", count=len(recs))
        run.summary(f"MDE recommendations: {len(recs)} collected.")
        return len(recs)


def _round2(v):
    try:
        return round(float(v), 2)
    except (TypeError, ValueError):
        return None


def collect_score(client: Client, run: Run) -> None:
    with _Guard(run, "mde.score"):
        score = _round2(client.get_json("/exposureScore").get("score"))
        groups = {g.get("rbacGroupName"): _round2(g.get("score")) for g in client.get_json("/exposureScore/ByMachineGroups").get("value", [])}
        run.write_json("exposure.json", {"score": score, "by_group": groups})
        run.set_source("mde.score", "ok", count=1)
        run.summary(f"MDE exposure score: {score}.")


class _FixtureSession:
    """A JSON list is consumed as successive responses in request order (last one repeats); a single object is reused for every request."""

    def __init__(self, path: str):
        data = json.loads(Path(path).read_text())
        self.pages = list(data) if isinstance(data, list) else [data]

    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        from tests.fakes import FakeResponse  # reuse the test double for offline/fixture mode

        page = self.pages.pop(0) if len(self.pages) > 1 else self.pages[0]
        return FakeResponse(200, page)


def _client_for(args) -> Client:
    if getattr(args, "fixture", None):
        from tests.fakes import FakeTokens

        return Client(FakeTokens(), MDE_SCOPE, base_url=MDE_BASE, session=_FixtureSession(args.fixture))
    return make_client()


def _run_one(fn):
    def _handler(args) -> int:
        fn(_client_for(args), resolve_run(args))
        return 0

    return _handler


def _run_all(args) -> int:
    run, c = resolve_run(args), _client_for(args)
    collectors = (collect_machines, collect_vulns, collect_recommendations, collect_score)
    failures = 0
    for fn in collectors:
        try:
            fn(c, run)
        except DvaError as e:
            failures += 1
            print(f"warning: {e}")
    return 1 if failures == len(collectors) else 0


def register(sub) -> None:
    p = sub.add_parser("mde", help="Collect from the Defender for Endpoint API")
    s = p.add_subparsers(dest="mde_cmd", required=True)
    for name, fn in [
        ("machines", collect_machines),
        ("vulns", collect_vulns),
        ("recommendations", collect_recommendations),
        ("score", collect_score),
    ]:
        q = s.add_parser(name)
        add_run_arg(q)
        q.add_argument("--fixture", help="path to a canned API response JSON file, used instead of calling the API")
        q.set_defaults(func=_run_one(fn))

    a = s.add_parser("all")
    add_run_arg(a)
    a.add_argument("--fixture", help="path to a canned API response JSON file, used instead of calling the API")
    a.set_defaults(func=_run_all)
