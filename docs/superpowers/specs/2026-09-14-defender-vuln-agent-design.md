# Defender vulnerability assessment agent — design

Date: 2026-09-14. Status: approved in brainstorming, awaiting implementation plan.

## Purpose

A Claude Code agent that assesses and prioritizes vulnerabilities across a Microsoft Defender estate.
It reads inventory and vulnerability data from Defender, enriches the distinct CVEs with threat
intelligence from the `cve-mcp-server` (https://github.com/mukul975/cve-mcp-server), scores findings
per **software product**, and produces a report that tells a security team what to patch first and
where. The agent is read-only: it never changes anything in Defender or Azure.

The unit of prioritization is a software product (vendor + product + version family), not a CVE,
because one patch action fixes many CVEs. The report shows, per product, the top three CVEs that
drive its score, its CVE counts by severity, and its most critical affected assets with a count.

## Decisions already made

| Topic | Decision |
|---|---|
| Runtime | Claude Code agent definition + skills + Python helper scripts. No standalone SDK app in phase 1. |
| Defender surfaces | Defender for Endpoint vulnerability management (MDE API), Defender XDR Advanced Hunting (KQL via Graph), Defender for Cloud (VM/Arc and container image findings via Azure Resource Graph). |
| Auth | One Entra app registration, client credentials. Setup script creates it; admin consent and Azure RBAC assignment are done by the user. |
| Output | Read-only. Markdown report, self-contained HTML report, JSON export. |
| Prioritization inputs | CVSS, EPSS, CISA KEV, public exploit availability (from the CVE server); Defender exposure level and device value, internet-facing status, device tags/groups as criticality; affected-device count. |
| Scale | 500 to 5,000 devices. Raw data goes to files, never into the model's context. |
| Scripting | Python 3.11+, one virtual environment shared with the CVE MCP server. |
| Location | This repository, `~/src/github.com/frodehus/defender-vuln-agent`. |
| Phasing | Phase 1: setup, doctor, MDE, hunting, enrichment, scoring, reports. Phase 2: Defender for Cloud with de-duplication. Phase 3 (optional): thin scheduled runner. |

## Repository layout

```
.claude/
  agents/vuln-assessor.md          # agent definition: role, workflow, tool allowlist
  skills/
    defender-auth/SKILL.md         # tokens, doctor, env vars
    defender-inventory/SKILL.md    # MDE machines, software vulnerabilities, recommendations
    defender-hunting/SKILL.md      # Advanced Hunting query library and ad hoc KQL
    defender-cloud/SKILL.md        # Defender for Cloud via Azure Resource Graph (phase 2)
    vuln-prioritize-report/SKILL.md# enrichment hand-off, scoring, report generation
.mcp.json                          # registers cve-mcp-server (stdio)
dva/                               # shared Python package
  __init__.py
  __main__.py                      # `python3 -m dva <command>`
  auth.py                          # MSAL client-credentials, per-resource token cache
  http.py                          # session with retry/backoff, Retry-After, OData paging
  run.py                           # run directory creation, manifest, summaries
  cache.py                         # disk cache with TTL (CVE enrichment)
  mde.py                           # MDE API collectors
  hunting.py                       # Graph runHuntingQuery client and query library loader
  cloud.py                         # Azure Resource Graph collectors (phase 2)
  model.py                         # dataclasses: Device, Finding, Product, Cve, Asset
  scoring.py                       # product roll-up and scoring
  report_md.py / report_html.py / report_json.py
  doctor.py
  queries/*.kql                    # named hunting queries
config/
  scoring.yaml                     # weights, thresholds, tag patterns, enrichment caps
  sources.yaml                     # which sources are enabled, subscriptions for MDC
setup/
  create-app.sh                    # az CLI: create app, add API permissions, print env vars
  permissions.md                   # checklist of permissions and roles, with why
docs/
  design/report/                   # Claude Design mockup source (Main.dc.html, canvas.json)
  superpowers/specs/               # this document
runs/                              # gitignored; one directory per run
.cache/                            # gitignored; CVE enrichment cache
tests/
  fixtures/                        # recorded JSON responses and a sample run
  test_*.py
```

## Authentication and setup

**App registration.** One Entra app named `defender-vuln-agent` with application permissions:

| API | Permission | Used for |
|---|---|---|
| WindowsDefenderATP | `Machine.Read.All` | device inventory, tags, exposure level, device value |
| WindowsDefenderATP | `Vulnerability.Read.All` | software vulnerabilities per machine, CVE metadata |
| WindowsDefenderATP | `Software.Read.All` | software inventory and version distribution |
| WindowsDefenderATP | `SecurityRecommendation.Read.All` | remediation text per product |
| WindowsDefenderATP | `Score.Read.All` | organization exposure score |
| Microsoft Graph | `ThreatHunting.Read.All` | Advanced Hunting queries |
| Azure RBAC | `Reader` on each subscription in `sources.yaml` | Resource Graph reads for Defender for Cloud (phase 2) |

`setup/create-app.sh` creates the app and service principal with `az ad app create` and
`az ad app permission add`, prints the three env vars below, and prints the two steps it cannot do:
granting admin consent and assigning the Azure Reader role. It never stores the secret; the user
sets it in their shell or a `.env` file that is gitignored.

**Environment variables.** `DVA_TENANT_ID`, `DVA_CLIENT_ID`, and either `DVA_CLIENT_SECRET` or
`DVA_CLIENT_CERT_PATH`. Optional `DVA_RUNS_DIR` (default `runs/`) and `DVA_CACHE_DIR` (default
`.cache/`). The CVE server's own keys (`NVD_API_KEY` and others) live in its `.env`, not here.

**Tokens.** `dva.auth` uses MSAL `ConfidentialClientApplication.acquire_token_for_client` with one
scope per resource: `https://api.securitycenter.microsoft.com/.default`,
`https://graph.microsoft.com/.default`, `https://management.azure.com/.default`. Tokens are cached in
memory for the run and on disk in `.cache/tokens.json` (mode 600) so repeated commands do not
re-authenticate.

**Doctor.** `python3 -m dva doctor` makes one cheap call per permission and prints a table:

```
MDE  Machine.Read.All               ok   GET /machines?$top=1
MDE  Vulnerability.Read.All         ok   GET /vulnerabilities?$top=1
MDE  Software.Read.All              ok   GET /software?$top=1
MDE  SecurityRecommendation.Read.All ok  GET /recommendations?$top=1
MDE  Score.Read.All                 ok   GET /exposureScore
Graph ThreatHunting.Read.All        ok   runHuntingQuery DeviceInfo | take 1
ARM  Reader (sub 1234…)             FAIL 403 AuthorizationFailed
CVE  cve-mcp-server reachable       ok   (checked by the agent, not doctor)
```

Exit code is non-zero if any phase-1 check fails. The agent runs doctor first and stops on failure.

## Data collection

All collectors write JSON files into `runs/<UTC timestamp>/` and print a one-paragraph summary to
stdout. They never print raw records. Each run directory has a `manifest.json` with the run id, start
and end times, enabled sources, per-source status (`ok`, `partial`, `failed`, `skipped`), record
counts, and errors.

### defender-inventory (MDE API, base `https://api.securitycenter.microsoft.com/api`)

| Command | Endpoint | Output file | Notes |
|---|---|---|---|
| `dva mde machines` | `GET /machines` | `machines.json` | Paged with `$top=10000` and `@odata.nextLink`. Keeps id, computerDnsName, osPlatform, osVersion, healthStatus, exposureLevel, deviceValue, machineTags, rbacGroupName, lastSeen, isInternetFacing when present, aadDeviceId, vmMetadata. |
| `dva mde vulns` | `GET /machines/SoftwareVulnerabilitiesByMachine?pageSize=50000` | `vulns.jsonl` | The export API built for large estates. One line per (machine, software, CVE). Keeps machineId, cveId, softwareVendor, softwareName, softwareVersion, vulnerabilitySeverityLevel, cvssScore, exploitabilityLevel, firstSeenTimestamp, diskPaths, registryPaths are dropped. Follows `@odata.nextLink` until exhausted. |
| `dva mde recommendations` | `GET /recommendations` | `recommendations.json` | Joined to products by vendor + product name to supply remediation text and `remediationType`. |
| `dva mde score` | `GET /exposureScore` and `/exposureScore/ByMachineGroups` | `exposure.json` | Used only for the summary. |

### defender-hunting (Graph, `POST https://graph.microsoft.com/v1.0/security/runHuntingQuery`)

`dva hunt <name>` runs a named query from `dva/queries/`, `dva hunt --kql "<text>"` runs ad hoc KQL.
Output goes to `hunt-<name>.json`. Every query is wrapped so that it returns at most 10,000 rows;
if the row count hits the cap the collector marks the source `partial` and prints a warning telling
the agent to narrow the query. The phase-1 query library:

| Name | Purpose | Tables |
|---|---|---|
| `internet-facing` | Device ids flagged internet-facing in the last 7 days | `DeviceInfo` (IsInternetFacing), `DeviceNetworkInfo` (public IPs) |
| `vuln-counts-by-device` | CVE counts per device by severity | `DeviceTvmSoftwareVulnerabilities` |
| `exploited-cves` | CVEs with `IsExploitAvailable` or KEV flag in Defender's own KB | `DeviceTvmSoftwareVulnerabilitiesKB` |
| `device-tags` | Device tags and groups, cheaper than paging `/machines` for large estates | `DeviceInfo` |
| `product-versions` | Version distribution per product across devices | `DeviceTvmSoftwareInventory` |

The hunting collector is the preferred source for anything aggregatable; the MDE REST API is used
where hunting lacks a field (deviceValue, recommendations, exposure score) or is capped.

### defender-cloud (phase 2, Azure Resource Graph)

`dva cloud vulns` posts to `https://management.azure.com/providers/Microsoft.ResourceGraph/resources`
with a query over `securityresources` where `type == "microsoft.security/assessments/subassessments"`
and the assessment is a vulnerability assessment (VM, Arc server, or container image). Output is
`cloud-vulns.jsonl` with one line per (resource, CVE): resource id, resource type, subscription,
resource group, CVE id, severity, cvss, patchable, image digest and repository for containers, running
workload references for AKS where the assessment carries them.

**De-duplication.** A VM or Arc finding is a duplicate of an MDE finding when the Azure resource id
in MDE's `vmMetadata` matches, or when the DNS hostname matches case-insensitively. Duplicates are
kept in the file but marked `duplicate_of: <mde machine id>` and excluded from counts and scoring.
Container images are never duplicates; they become assets of kind `image` and are counted by
running pod count when available, otherwise by image.

## Enrichment

Enrichment is deliberately narrow to keep token use and CVE-server calls small. Defender already
supplies a CVSS score, severity level and exploitability level for every finding, so those fields
carry the bulk of scoring. Only the CVEs that can change a product's rank get external intelligence.

**Candidate selection.** After roll-up (below), `dva enrich --list` selects, per product, the
`enrich_top_per_product` CVEs (default 3) with the highest Defender `cvssScore`, ties broken by
`exploitabilityLevel` (ExploitIsInKit > ExploitIsVerified > ExploitIsPublic > NoExploit) then by
newest `firstSeenTimestamp`. Products are considered in descending order of their preliminary score
(computed from Defender fields alone) and selection stops at `enrich_max_cves` (default 200) or when
the preliminary score drops below `report_threshold` (default 40), whichever comes first. The list
is de-duplicated across products, minus anything already cached, and printed as JSON lines in chunks
of 20 (the CVE server's bulk limit).

**Calls.** The agent calls `bulk_cve_lookup` with each chunk, then `triage_cve` (depth `standard`)
only for CVEs that the bulk result marks as KEV-listed or with EPSS ≥ 0.5, and writes results with
`dva enrich --store <file>`. A full run on a 5,000 device estate is therefore bounded at roughly
10 bulk calls plus a few dozen triage calls, and the agent's context sees only the JSON lines for
the selected ids and the store confirmations.

**Cache.** `dva.cache` stores one JSON per CVE under `.cache/cve/<id>.json` with a fetched-at
timestamp; TTL is 7 days (configurable). `enrichment.json` in the run directory is the merged view for
the run: for each enriched CVE, cvss (base and vector), epss score and percentile, kev (listed, date
added, ransomware use), exploit availability (Exploit-DB, GitHub PoC, Nuclei template, Metasploit),
cwe, a one-line title, and the source timestamps. CVEs that were not selected have no entry and
scoring uses Defender fields only for them.

If the CVE server is unreachable or a chunk fails, enrichment for those CVEs is marked missing.
Scoring proceeds using Defender's own fields, and the report marks affected products with
"partial intel". Enrichment is never blocking.

## Prioritization

### Roll-up to products

A **product** is keyed by normalized `(vendor, product name)` from MDE, with version families kept as
a breakdown inside the product. Container images are products keyed by `(registry, repository)` with
tags as versions. Each product has:

- the set of CVEs affecting it, with severity from Defender's `vulnerabilitySeverityLevel`;
- the set of affected assets (devices or images), each with its context fields;
- CVE counts by severity (critical, high, medium, low);
- the top three CVEs by their individual threat score (below), shown as "driving vulnerabilities";
- remediation text from the matching MDE recommendation, or a generic "update to a fixed version"
  line when none matches;
- the most critical assets, ranked by asset context score, capped at 5 in the report, with the
  remaining count.

### Scores

All weights and thresholds live in `config/scoring.yaml`. Defaults:

**CVE threat score** (0 to 1):

```
threat = 0.35 * cvss/10
       + 0.25 * epss_percentile
       + 0.25 * (1 if kev else 0)
       + 0.15 * (1 if public exploit else 0.5 if Defender says exploit available else 0)
```

For a CVE without enrichment, `cvss` is Defender's `cvssScore`, `epss_percentile` is 0, `kev` is
false, and the exploit term comes from Defender's `exploitabilityLevel` alone (0.5 for
ExploitIsPublic, 0.75 for ExploitIsVerified, 1.0 for ExploitIsInKit). The preliminary product score
used for enrichment selection is the product score computed with these defaults for every CVE.

**Asset context multiplier** (1.0 to 2.5, additive bonuses then capped):

| Signal | Bonus |
|---|---|
| internet-facing (hunting or MDE flag) | +0.6 |
| MDE exposureLevel High / Medium | +0.4 / +0.2 |
| MDE deviceValue High | +0.4 |
| tag matches a pattern in `criticality_tags` (default `Tier0`, `Prod`, `DMZ`) | +0.5 |
| container image with a public LoadBalancer service | +0.6 |

**Product score** (0 to 100):

```
top3 = mean of the three highest CVE threat scores for the product
asset = mean asset multiplier over affected assets, weighted so the top 5 assets count double
reach = log10(1 + affected asset count) / log10(1 + estate size)   # 0..1
score = 100 * min(1, top3 * (0.6 + 0.3 * asset / 2.5 + 0.1 * reach) * asset_boost)
asset_boost = 1.25 if any affected asset is internet-facing AND any driving CVE is KEV else 1.0
```

Rationale: a product with one KEV-listed CVE on one internet-facing gateway must outrank a product
with many medium CVEs on hundreds of workstations, but reach still lifts fleet-wide problems. The
formula is deliberately simple and explained in the report appendix; tuning happens in YAML, not code.

**Report thresholds** (also in YAML): products with score ≥ 40 are "needing action" and appear in
the full list; the top 10 by score are the prioritized list; score bands map to labels Critical
(≥ 80), High (≥ 60), Medium (≥ 40), Low.

### Outputs of scoring

`dva score` reads the run directory and writes `findings.json`:

```json
{
  "run": {...manifest...},
  "summary": { "devices": 2318, "products_total": 214, "products_action": 23, "kev_cves": 14,
               "internet_facing_at_risk": 41, "exposure_score": 54, "previous_exposure_score": 61 },
  "products": [ { "rank": 1, "vendor": "...", "product": "...", "score": 97, "label": "Critical",
                  "counts": {"critical": 4, "high": 7, "medium": 12, "low": 3},
                  "flags": {"kev": true, "exploit": true, "internet_facing": true},
                  "reason": "...", "remediation": "...",
                  "driving_cves": [ {"id": "...", "severity": "critical", "cvss": 9.8, "epss": 0.94,
                                     "kev": true, "poc": true, "title": "..."} ],
                  "assets": {"count": 6, "breakdown": "All 6 internet-facing · 6 Tier0",
                             "top": [ {"name": "...", "why": "Internet-facing · Tier0 · High"} ] },
                  "all_cves": ["..."], "all_assets": ["..."] } ],
  "diff_from_previous": { "entered_top10": [...], "left_top10": [...], "new_kev": [...] }
}
```

The `reason` line is generated from the strongest signals (for example "VPN gateways, all
internet-facing, two KEV entries added this week") using fixed templates, not free text.

## Reporting

Three renderers read `findings.json` and nothing else, so they stay consistent.

- **`report.md`**: header with tenant, run time, sources; executive summary paragraph built from the
  summary block and the diff; a top 10 table (rank, product, score, devices, counts by severity,
  flags); one section per top 10 product with driving CVEs, remediation, assets; a compact table of
  the remaining products; appendix on scoring and data freshness.
- **`report.html`**: the layout in `docs/design/report/Main.dc.html`, rendered as a single
  self-contained file (inline CSS and JS, no external requests) that follows the Elevate Audit
  report style: system font stack, navy ink on white, mist header band, meta grid, verdict paragraph,
  four tiles, sticky chip toolbar (filter by all / has critical / KEV-listed / internet-facing; sort
  by score / devices / critical count; expand all / collapse all), top 10 cards with ranks 1 to 3
  open by default, full product list with collapsed rows, appendix. Every row uses wrapping flex,
  never fixed-pixel grids, so it holds at 800 px wide and prints.
- **`findings.json`**: the file above, unchanged.

The agent may publish `report.html` as an artifact when asked.

## Agent definition and workflow

`.claude/agents/vuln-assessor.md` defines a subagent named `vuln-assessor` running on Claude Sonnet
(`model: sonnet` in the frontmatter) to keep cost down, since the work is command sequencing rather than
deep reasoning. Its tools are limited to
Bash, Read, Glob, Grep, and the CVE MCP server's tools. Its instructions:

1. Run `python3 -m dva doctor`. Stop and report if it fails.
2. Create a run: `python3 -m dva run new` prints the run directory.
3. Collect: `dva mde machines`, `dva mde vulns`, `dva mde recommendations`, `dva mde score`, then
   `dva hunt internet-facing`, `dva hunt exploited-cves`, `dva hunt device-tags`. In phase 2 also
   `dva cloud vulns` when `sources.yaml` enables it. Read only the printed summaries.
4. Enrich: loop over `dva enrich --list` chunks (top CVEs per product by Defender CVSS, capped),
   call `bulk_cve_lookup` per chunk, then `triage_cve` only for ids the bulk result marks KEV or
   EPSS ≥ 0.5, store with `dva enrich --store`. Skip gracefully if the server is down.
5. Score: `python3 -m dva score`.
6. Report: `python3 -m dva report --all`.
7. Read `report.md` (only this file) and give the user a five-line summary with the top three
   products and any source marked partial or failed.

The definition states explicitly: never `cat` files under `runs/` other than `report.md` and
`manifest.json`; never write to Defender; ad hoc KQL is allowed only through `dva hunt --kql` and only
read-only tables. Read-only is enforced by the app registration having no write permissions, so the
prompt rule is a courtesy, not the control.

## Error handling

- Every `dva` command exits non-zero with a single-line reason on stderr; details go to
  `runs/<id>/log.txt`.
- HTTP 429 and 503 retry with exponential backoff and honor `Retry-After`, up to 5 attempts. MDE's
  documented limits (100 calls per minute, 1,500 per hour) are respected with a token bucket.
- A source failing marks that source `failed` in the manifest; other sources continue. `dva score`
  runs with whatever is present and the report states which sources are missing and what that means
  (for example "no internet-facing data: asset multipliers exclude that signal").
- Partial CVE enrichment is flagged per product with a "partial intel" pill.
- Hunting queries that hit the 10,000 row cap mark the source `partial`.
- If no previous run exists, the diff block is empty and the report omits the "since last run"
  sentences.

## Testing

- **Unit tests** with recorded JSON fixtures under `tests/fixtures/`: paging and `@odata.nextLink`
  handling, MDE record normalization, hunting row cap detection, product roll-up and key
  normalization, enrichment candidate selection (per-product top N, global cap, threshold stop),
  scoring formula against hand-computed cases, de-duplication (phase 2), diff against
  a previous run, each renderer against a golden file generated from `tests/fixtures/sample-run/`.
- **Offline pipeline**: every collector accepts `--fixture <file>` so `dva score` and `dva report`
  run end to end without credentials. The sample run doubles as the demo data for the HTML report.
- **Integration**: `dva doctor` against the real tenant is the integration test. No test hits live
  APIs.
- Golden files are regenerated with `DVA_UPDATE_GOLDEN=1 pytest`.

## Non-goals

- Writing anything to Defender, Azure, or ticketing systems.
- Per-device detail in reports; `findings.json` carries full lists for downstream use.
- Multi-tenant support in phase 1. The env vars select one tenant; running twice with different
  env selects another.
- Sentinel workspace queries.
- A scheduled runner (phase 3, only if requested).

## Open items for the implementation plan

- Exact field names in `SoftwareVulnerabilitiesByMachine` and Resource Graph subassessment
  properties must be confirmed against Microsoft Learn during implementation and captured in fixtures.
- The CVE server's tool argument shapes must be observed once against a running instance before the
  agent instructions hardcode call examples.
