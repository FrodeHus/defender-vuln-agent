from __future__ import annotations
from dva.auth import ARM_SCOPE
from dva.errors import DvaError
from dva.http import Client
from dva.mde import _Guard
from dva.run import Run, add_run_arg, resolve_run

ARM_BASE = "https://management.azure.com"
RG_PATH = "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
PAGE_TOP = 1000
MAX_PAGES = 1000  # safety cap against a misbehaving/looping API

QUERY = '''securityresources
| where type == "microsoft.security/assessments/subassessments"
| extend props = parse_json(properties)
| where props.category in~ ("Vulnerability", "Container Vulnerability", "Image Vulnerability") or props.additionalData.assessedResourceType in~ ("ServerVulnerability", "ContainerRegistryVulnerability", "AzureContainerRegistryVulnerability", "AzureContainerImageVulnerability")
| project id, subscriptionId, resourceGroup, assessmentKey = extract(".*assessments/(.+?)/.*", 1, id), cveId = tostring(props.id), displayName = tostring(props.displayName), severity = tostring(props.status.severity), resourceId = tostring(props.resourceDetails.id), assessedType = tostring(props.additionalData.assessedResourceType), cvss = todouble(props.additionalData.cvss.["3.0"].base), patchable = tobool(props.additionalData.patchable), repo = tostring(props.additionalData.repositoryName), digest = tostring(props.additionalData.imageDigest)
| where cveId startswith "CVE-"'''


def _norm_row(row: dict) -> dict:
    return {
        "resource_id": row.get("resourceId") or "",
        "resource_type": row.get("assessedType") or "",
        "subscription": row.get("subscriptionId"),
        "resource_group": row.get("resourceGroup"),
        "cve_id": row.get("cveId"),
        "severity": row.get("severity"),
        "cvss": row.get("cvss"),
        "patchable": row.get("patchable"),
        "image_repo": row.get("repo") or None,
        "image_digest": row.get("digest") or None,
        "display_name": row.get("displayName"),
        "assessment_key": row.get("assessmentKey"),
        "duplicate_of": None,
    }


def collect_vulns(client: Client, run: Run, subscriptions: list[str]) -> int:
    with _Guard(run, "cloud.vulns"):
        rows: list[dict] = []
        skip_token = None
        for _ in range(MAX_PAGES):
            options = {"$top": PAGE_TOP, "$skip": 0}
            if skip_token:
                options["$skipToken"] = skip_token
            body = {"subscriptions": list(subscriptions), "query": QUERY, "options": options}
            resp = client.post_json(RG_PATH, body)
            data = resp.get("data") or []
            rows.extend(_norm_row(r) for r in data)
            skip_token = resp.get("$skipToken")
            if not skip_token:
                break
        else:
            raise DvaError(f"Resource Graph paging did not terminate after {MAX_PAGES} pages")
        n = run.write_jsonl("cloud-vulns.jsonl", rows)
        run.set_source("cloud.vulns", "ok", count=n)
        run.summary(f"Defender for Cloud: {n} vulnerability findings written to cloud-vulns.jsonl.")
        return n


def _client(args) -> Client:
    if getattr(args, "fixture", None):
        from dva.mde import _FixtureSession
        from tests.fakes import FakeTokens
        return Client(FakeTokens(), ARM_SCOPE, base_url=ARM_BASE, session=_FixtureSession(args.fixture))
    from dva.mde import make_client
    return make_client(ARM_SCOPE, ARM_BASE)


def register(sub) -> None:
    p = sub.add_parser("cloud", help="Collect from Defender for Cloud (Resource Graph)")
    s = p.add_subparsers(dest="cloud_cmd", required=True)
    q = s.add_parser("vulns")
    add_run_arg(q)
    q.add_argument("--subscriptions", nargs="*", help="subscription ids (default: config/sources.yaml subscriptions)")
    q.add_argument("--fixture", help="path to a canned API response JSON file, used instead of calling the API")

    def _run(args) -> int:
        subs = args.subscriptions
        if not subs:
            from dva.config import load_sources
            subs = load_sources().subscriptions
        if not subs:
            raise DvaError("no subscriptions configured; pass --subscriptions or set config/sources.yaml subscriptions")
        collect_vulns(_client(args), resolve_run(args), subs)
        return 0

    q.set_defaults(func=_run)
