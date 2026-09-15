# Usage

## With the Claude Code agent

Start `claude` in the repository and ask in plain language, naming the tenant when you have more than one:

```
Use the vuln-assessor agent to run a vulnerability assessment for contoso
```

```
What should fabrikam patch first this week?
```

The agent lists tenants, matches the name (a unique prefix is enough; it stops and asks if the name is missing or ambiguous), verifies permissions with `dva doctor`, creates a run, collects inventory and vulnerabilities, runs the hunting queries, runs `dva enrich --fetch` (which sends the selected CVEs to the CVE server one `triage_cve` call at a time and stores the results), scores, renders the reports, and replies with the top products, the count needing action and any source that was partial or failed. It replies from `dva report --brief` (a dozen lines) and reads `report.md` only when asked for more; raw data never enters the conversation.

The same works on a local model: the agent makes no CVE tool calls and reads only short summaries, so a 30B-class coding model through Ollama handles it. Start Claude Code as described in [install.md](install.md#running-the-agent-on-a-local-model-with-ollama) (bare mode, no MCP servers, only this plugin) or the opening request will not fit the model's context window. Expect a slower first turn and check the reply against `python3 -m dva report --brief` the first few runs.

Follow-ups that work well:

- `Continue the assessment from runs/<id>` (or `tenants/<name>/runs/<id>`) resumes after a failure.
- `Re-score contoso with report_threshold 30` edits the tenant's `scoring.yaml` override and re-runs only the score and report steps.
- `Run the internet-facing hunting query again for contoso` runs one named query.

The agent runs on Claude Sonnet by design (see `agents/vuln-assessor.md`); change `model:` there if you prefer another.

## From the command line

Every command accepts `--tenant NAME` before the subcommand, or `DVA_TENANT=NAME` in the environment. Omit both for a single-tenant install or when only one tenant is configured (it is selected automatically); with several tenants the command refuses to guess.

```bash
source .venv/bin/activate                                   # or prefix each command with: uv run
export DVA_TENANT=contoso                                   # optional
export DVA_RUN=$(python3 -m dva run new)                    # new run directory
python3 -m dva doctor
python3 -m dva mde all                                      # machines, vulns, recommendations, exposure+secure score, vuln changes
python3 -m dva hunt internet-facing exploited-cves device-tags product-versions evidence privileged-logons mitigations certificates config-findings
python3 -m dva cloud vulns                                  # only if sources.yaml has cloud: true
python3 -m dva cloud attack-paths                            # only if sources.yaml has cloud: true
python3 -m dva enrich --fetch                               # calls the CVE server per selected CVE; prints "fetched N results, M failed" and "stored N, missing M"
python3 -m dva score                                        # writes findings.json
python3 -m dva report --all                                 # report.md, report.html, report.json, tickets.json
python3 -m dva exception suggest                             # suggested accepted-risk exceptions, writes exception-suggestions.json
python3 -m dva report --brief                               # a dozen-line summary for the reply; writes nothing
```

`python3 -m dva --help` and `python3 -m dva <command> --help` list every flag. The package also installs a `dva` console script, so `dva doctor` works inside the venv.

## Exceptions (accepted risk)

Some products are known, accepted risks — bundled components a vendor controls the patch cadence for, software already flagged for retirement, and so on. Mark those with an exception so they stop showing up as action items while still being tracked:

```bash
python3 -m dva exception list
python3 -m dva exception add --product openssl/openssl --reason "Bundled OpenSSL in vendor appliances" --until 2026-12-31 --owner frode
python3 -m dva exception add --cve CVE-2023-0286 --reason "Tracked in the vendor's own ticket" --until 2026-12-31 --owner frode
python3 -m dva exception remove --product openssl/openssl
python3 -m dva exception suggest                              # print and write exception-suggestions.json
```

A product exception drops that product entirely from scoring and the report; a CVE exception removes just that CVE from every product (a product left with no CVEs is dropped too). Excepted products are listed under `findings.json`'s `accepted_risks.active` with their reason, owner, until date and the score they would otherwise carry; once `until` passes they re-enter ranking, flagged `flags.exception_expired` on the row and listed under `accepted_risks.expired`. `exception suggest` scores every product the report would list against common accepted-risk reasons (embedded component, bundled across several unrelated products, no vendor fix available, end of support) and suggests a 90-day `until`. Exceptions live in `tenants/<name>/exceptions.yaml` (or `config/exceptions.yaml` with no active tenant), are gitignored and per tenant, and are managed only through this CLI — the agent never edits the file directly, and only adds an exception when the user explicitly confirms it.

## Named hunting queries

| Name | Returns |
|---|---|
| `internet-facing` | Devices Defender marks as internet-facing in the last 7 days, with public IP, exposure level and asset value |
| `device-tags` | Manual and dynamic device tags, exposure level, asset value and Azure resource id per device |
| `exploited-cves` | CVEs present in the estate that Defender's knowledge base marks as having a public exploit |
| `vuln-counts-by-device` | Open CVE counts per device by severity |
| `product-versions` | Device count per software vendor, product and version, plus end-of-support status and date |
| `evidence` | Dynamic: disk and registry installation paths of the products the report will list, generalized (`%ProgramFiles%`, `%LOCALAPPDATA%`, `<version>`, `<drive>:`) and counted per device; shown collapsed under each product. Run after `mde all`. |
| `privileged-logons` | Devices a privileged (Entra-role-assigned or high-criticality) identity signed into in the last 7 days; needs Defender for Identity or MDE P2. Feeds the `privileged_user` asset bonus. |
| `mitigations` | Devices compliant with the compensating controls listed in `scoring.yaml`'s `mitigation_configs`; feeds the `mitigated` asset bonus. Skipped with a note when the list is empty. |
| `mitigation-catalog` | The full compensating-control catalog, to help you pick ids for `mitigation_configs`. Not scored. |
| `certificates` | Certificates expiring in the next 30 days; feeds the report's Posture appendix. Not scored. |
| `config-findings` | Non-compliant secure-configuration assessments with the knowledge-base display name, description and remediation text (the first link in that text becomes the documentation link); feeds the report's Posture appendix. Not scored. |

Ad hoc KQL: `python3 -m dva hunt --kql "DeviceInfo | summarize count() by OSPlatform" --name os-mix`. Every query is capped at 10,000 rows server-side; a capped result marks the source `partial` in the manifest, so narrow the query with `where` or `summarize`. Management and ingestion commands are rejected.

## Reading the reports

- **`report.md`**: executive summary (exposure score, secure score, SLA breaches, end-of-support products, CVEs patched in the last 7 days, the 12-month score trend when available), top 10 products, each with a plain-language "Risk" paragraph explaining what the most critical vulnerability lets an attacker do and what is exposed, the three CVEs driving the score, remediation text from Defender's recommendations (with a fix-version rollup line and vendor advisory links when known), and the affected assets as counts by type (Windows / Linux / macOS / container images, internet-facing, critical, high value, privileged sign-in, attack path) plus the top tags, followed by the five most exposed devices by name; the full device list stays in `findings.json`. Installation paths are capped at `max_paths` (10) with the total shown. Diffable between runs. Accepted-risk exceptions, long-standing vulnerabilities and a Posture appendix (expiring certificates, non-compliant configuration) follow the product list; the HTML report shows these three as full-width tabs.
- **`report.html`**: the same content as a self-contained page with filters (has critical, KEV-listed, internet-facing), sorting, expandable rows and an inline SVG sparkline of the score trend. Open it in a browser or share the file; it makes no network requests.
- **`report.json`** and **`findings.json`**: the full scored data, including every CVE and every asset per product, accepted risks, trend and posture, for downstream tooling.
- **`tickets.json`** (written by `report --tickets` or `--all`): one ticket per listed product not under exception — key, title, priority, labels, a Markdown description — ready to hand to a ticketing system. No API calls are made.

Products are ranked by a 0 to 100 score; see [architecture.md](architecture.md#scoring) for the formula and [configuration.md](configuration.md) for the weights. The top 10 are always listed; `report_threshold` decides how many count as needing action.

## Offline demo

The pipeline runs without credentials or network using canned responses:

```bash
export DVA_RUNS_DIR=/tmp/dva-demo/runs DVA_CACHE_DIR=/tmp/dva-demo/cache
export DVA_RUN=$(python3 -m dva run new)
python3 -m dva mde all --fixture tests/fixtures/mde/all.json
python3 -m dva hunt internet-facing --fixture tests/fixtures/hunting/internet-facing.json
python3 -m dva enrich --store tests/fixtures/cve/triage-e2e.txt   # offline stand-in for enrich --fetch
python3 -m dva exception add --product adobe/acrobat-reader-dc --reason "vendor patches on their own cadence" --until 2099-01-01 --owner demo
python3 -m dva score
python3 -m dva report --all
python3 -m dva exception suggest
```

This is exactly what `tests/test_e2e.py` runs.

`enrich --fetch` starts the CVE server itself over stdio: `scripts/cve-mcp.sh` by default (under `DVA_HOME` when set), or the command line in `DVA_CVE_MCP` / `--server CMD`. It calls `triage_cve(cve_id, depth="standard")` for every selected CVE and `lookup_cve` plus `get_vendor_advisory` for the CVE driving each listed product, saves each text result under the run directory and merges them, so nothing needs to go through Claude. To do the calls by hand instead (for example with the MCP Inspector), `enrich --list` prints the ids, 20 per `{"chunk": n, "cve_ids": [...]}` line plus a `{"describe": [...]}` line; save each result as `$DVA_RUN/cve-triage-<id>.txt`, `cve-lookup-<id>.txt` or `cve-advisory-<id>.txt` and merge with `enrich --store "$DVA_RUN"/cve-*.txt`. The resulting report shows an Ivanti Connect Secure product driven by a KEV-listed CVE on an internet-facing Tier0 gateway, with Acrobat Reader DC excluded from scoring as an accepted risk.

## Run directory layout

| File | Written by | Contents |
|---|---|---|
| `manifest.json` | every command | Run id, start time, per-source status (`ok`/`partial`/`failed`) and counts |
| `machines.json` | `mde machines` | Normalized device inventory |
| `vulns.jsonl` | `mde vulns` | One row per device, software and CVE |
| `recommendations.json` | `mde recommendations` | Remediation text and recommended versions |
| `exposure.json` | `mde score` | Organization exposure score, per-group exposure and the organization secure score |
| `vuln-changes.jsonl` | `mde changes` | Vulnerability status deltas (Fixed/New/...) over the last `--since-days` (default 7) |
| `hunt-<name>.json` | `hunt` | Raw Advanced Hunting result |
| `cloud-vulns.jsonl` | `cloud vulns` | Defender for Cloud findings per resource and CVE |
| `cloud-attackpaths.json` | `cloud attack-paths` | Attack paths from Resource Graph, only when `cloud: true` |
| `enrich-candidates.json`, `enrich-describe.json` | `enrich --fetch`/`--list` | CVE ids selected for enrichment and for descriptions |
| `cve-triage-*.txt`, `cve-lookup-*.txt`, `cve-advisory-*.txt` | `enrich --fetch` | Saved CVE server results (triage, descriptions, vendor advisories) |
| `enrichment.json` | `enrich --fetch`/`--store` | Parsed CVE intel for this run |
| `findings.json` | `score` | Scored products, accepted risks, long-standing products, trend, posture and the diff from the previous run |
| `tickets.json` | `report --tickets`/`--all` | One ticket per listed product not under exception |
| `exception-suggestions.json` | `exception suggest` | Suggested accepted-risk exceptions with reasons |
| `report.md` / `.html` / `.json` | `report` | Rendered reports |
| `summary.txt`, `log.txt` | every command | One-line summaries; errors from failed sources |
