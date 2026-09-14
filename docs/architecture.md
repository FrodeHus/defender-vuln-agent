# Architecture

## Pipeline

```
Defender for Endpoint API ─┐
Advanced Hunting (Graph) ──┼─► run directory files ─► roll-up by product ─► select top CVEs ─► CVE server (triage_cve)
Defender for Cloud (ARG) ──┘                                │                                        │
                                                            └────────────── score ◄── enrichment.json ┘
                                                                              │
                                                                       findings.json ─► report.md / report.html / report.json
```

Every stage is a `python3 -m dva` command that reads and writes files under one run directory and prints a one-line summary. The Claude Code agent sequences the commands and performs the CVE-server calls, which are the only step that needs an MCP tool. Raw data never passes through the model.

## Modules

| Module | Responsibility |
|---|---|
| `dva/auth.py` | MSAL client-credentials tokens per scope, cached on disk with mode 600 |
| `dva/http.py` | HTTP client: bearer auth, retry on 429/5xx with `Retry-After`, network errors wrapped, OData paging |
| `dva/run.py` | Run directories, `manifest.json`, JSON/JSONL helpers, run selection |
| `dva/tenant.py` | Tenant directories, `.env` activation, config overrides |
| `dva/mde.py` | Machines, per-device vulnerabilities (bulk export, atomic write), recommendations, exposure score |
| `dva/hunting.py` | `runHuntingQuery` client, named KQL library, read-only guard, 10k row cap |
| `dva/cloud.py` | Resource Graph subassessments for VMs, Arc servers and container images |
| `dva/rollup.py` | Devices and vulnerabilities into products and assets; end-of-support and fix-version rollups; de-duplication of cloud findings against MDE |
| `dva/evidence.py` | Generalizes disk/registry installation paths, grouped per product, for the report and exception suggestions |
| `dva/scoring.py` | Threat score per CVE, asset multiplier, product score, labels, reason text |
| `dva/enrich.py` | Candidate selection, parsing of CVE server output (including vendor advisories), cache merge |
| `dva/cache.py` | TTL cache of CVE intel; reads and writes the SQLite store exclusively |
| `dva/store.py` | `dva.sqlite` store: CVE intel and per-run history (mode 600, WAL) |
| `dva/exceptions.py` | Accepted-risk exceptions: load/save, apply to products before scoring, suggestions |
| `dva/score_cmd.py` | `findings.json` writer with the diff from the previous run, SLA/EOS/trend/posture/score-trend; records the run in the store |
| `dva/report_md.py`, `report_html.py`, `report_json.py`, `report_tickets.py` | Renderers that read only `findings.json` |
| `dva/doctor.py` | One cheap call per permission |

## Data model

A **product** is `(vendor, name)` as reported by Defender, normalized to a key such as `ivanti/connect-secure`. Container images are products keyed by registry host and repository. A product carries its CVEs (one merged reference per CVE with the strongest exploitability and highest CVSS seen across devices), its affected assets, version counts per distinct device, and remediation text from the matching Defender recommendation.

An **asset** is a device or an image with the context that affects scoring: internet-facing, exposure level, device value, tags, group.

Cloud findings for a VM that MDE also covers are duplicates: matched by Azure resource id, or by hostname only when the MDE record has no resource id. Duplicates are excluded from counts and scoring.

## Scoring

Per CVE, with `w` from `threat_weights`:

```
threat = w.cvss · cvss/10 + w.epss · epss_percentile + w.kev · [in KEV] + w.exploit · exploit_term + w.ransomware · [ransomware]
```

`exploit_term` is `intel.exploit_maturity` when the CVE server set it (parsed from `triage_cve`'s `PoC:`/`KEV:` lines, `check_poc_exists`'s `Confidence:` label, or `check_exploit_availability`'s public PoC count — public/weaponized/high maps to 1.0, medium to 0.85, low/poc to 0.7, five or more public sources raises the floor to 0.85), otherwise Defender's exploitability level (0, 0.5, 0.75, 1.0 for none, public, verified, in kit). `[ransomware]` is 1 when the CVE server marks known ransomware use (triage `KEV:` line or `check_kev`'s `Ransomware Use: Known`). Without enrichment, EPSS is 0, KEV and ransomware false, and `exploit_term` falls back to Defender's level. The five weights sum to 1.10 by default, so `threat` is capped implicitly by the later `min(1, …)` on the product score.

Per asset: `multiplier = min(asset_cap, 1 + sum of applicable bonuses)`, where bonuses now also include `privileged_user` (a privileged identity signs into the device), `attack_path` (the device sits on a Defender for Cloud attack path, cloud tenants only) and `mitigated` (a negative bonus/discount when all of the tenant's chosen compensating controls are compliant on the device).

Per product:

```
top3       = mean threat of the three highest-scoring CVEs
asset_mean = weighted mean multiplier over affected assets, top 5 counted double
reach      = log10(1 + affected assets) / log10(1 + estate size)
boost      = 1.25 if a driving CVE is in KEV and an asset is internet-facing, else 1.0
overdue    = overdue_boost (default 1.10) if any of the product's CVEs has exceeded its severity's sla_days age, else 1.0
score      = 100 · min(1, top3 · (0.6 + 0.3 · asset_mean / asset_cap + 0.1 · reach) · boost · overdue)
```

The intent: one KEV-listed CVE on one internet-facing gateway outranks many medium CVEs on hundreds of workstations, reach still lifts fleet-wide problems, and a CVE that has sat open past its SLA window nudges its product back to the top even without a context change.

Accepted-risk exceptions (`dva exception`) are applied before any of this: an actively-excepted product is removed entirely from `products`, the top list and scoring, and listed under `accepted_risks.active` instead with the score it would otherwise have carried; a CVE exception removes just that CVE from every product. See [configuration.md](configuration.md#exceptionsyaml).

## Enrichment selection

Products are ordered by their preliminary score (no intel). For each product above `enrich_threshold`, the top `enrich_top_per_product` CVEs by Defender CVSS, exploitability and recency are selected, skipping ids already fresh in the cache, until `enrich_max_cves` is reached. The agent calls `triage_cve` once per id; the parser reads the server's text output. On a mid-size estate this is a few dozen calls per run.

## Failure model

Every command exits 1 with `dva: <reason>` on stderr; details go to `log.txt` in the run. A source that fails is marked `failed` in `manifest.json` and the run continues; a hunting query that hits the row cap is `partial`. Scoring runs with whatever is present and the report shows which sources are missing. `vulns.jsonl` is written atomically so a mid-stream failure leaves no truncated file.

## Security boundaries

Only read permissions exist on the app registration, so read-only is enforced by the token, not the prompt. Credentials and token caches are mode 600. The HTML report escapes every Defender-derived string and embeds its data in a JSON script island. The only outbound data beyond Microsoft APIs is CVE identifiers sent to the local CVE server.
