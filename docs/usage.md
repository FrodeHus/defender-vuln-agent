# Usage

## With the Claude Code agent

Start `claude` in the repository and ask in plain language, naming the tenant when you have more than one:

```
Use the vuln-assessor agent to run a vulnerability assessment for contoso
```

```
What should fabrikam patch first this week?
```

The agent lists tenants, matches the name (a unique prefix is enough; it stops and asks if the name is missing or ambiguous), verifies permissions with `dva doctor`, creates a run, collects inventory and vulnerabilities, runs the hunting queries, sends the selected CVEs to the CVE server one `triage_cve` call at a time, stores the results, scores, renders the reports, and replies with the top products, the count needing action and any source that was partial or failed. It only ever reads `report.md`; raw data never enters the conversation.

Follow-ups that work well:

- `Continue the assessment from runs/<id>` (or `tenants/<name>/runs/<id>`) resumes after a failure.
- `Re-score contoso with report_threshold 30` edits the tenant's `scoring.yaml` override and re-runs only the score and report steps.
- `Run the internet-facing hunting query again for contoso` runs one named query.

The agent runs on Claude Sonnet by design (see `.claude/agents/vuln-assessor.md`); change `model:` there if you prefer another.

## From the command line

Every command accepts `--tenant NAME` before the subcommand, or `DVA_TENANT=NAME` in the environment. Omit both for a single-tenant install.

```bash
source .venv/bin/activate
export DVA_TENANT=contoso                                   # optional
export DVA_RUN=$(python3 -m dva run new)                    # new run directory
python3 -m dva doctor
python3 -m dva mde all                                      # machines, vulns, recommendations, exposure score
python3 -m dva hunt internet-facing exploited-cves device-tags
python3 -m dva cloud vulns                                  # only if sources.yaml has cloud: true
python3 -m dva enrich --list                                # prints the CVE ids to look up, 20 per line
```

Enrichment needs the CVE server. From Claude Code the agent does this step; by hand, call `triage_cve(cve_id, depth="standard")` for each listed id (for example with the MCP Inspector, `npx @modelcontextprotocol/inspector .venv/bin/python3 -m cve_mcp.server`), save each text result as `$DVA_RUN/cve-triage-<id>.txt`. `enrich --list` also prints a `{"describe": [...]}` line: call `lookup_cve(cve_id)` for those and save to `$DVA_RUN/cve-lookup-<id>.txt`; their descriptions feed the per-product risk summary. Then:

```bash
python3 -m dva enrich --store "$DVA_RUN"/cve-*.txt          # prints "stored N, missing M"
python3 -m dva score                                        # writes findings.json
python3 -m dva report --all                                 # report.md, report.html, report.json
```

`python3 -m dva --help` and `python3 -m dva <command> --help` list every flag. The package also installs a `dva` console script, so `dva doctor` works inside the venv.

## Named hunting queries

| Name | Returns |
|---|---|
| `internet-facing` | Devices Defender marks as internet-facing in the last 7 days, with public IP, exposure level and asset value |
| `device-tags` | Manual and dynamic device tags, exposure level, asset value and Azure resource id per device |
| `exploited-cves` | CVEs present in the estate that Defender's knowledge base marks as having a public exploit |
| `vuln-counts-by-device` | Open CVE counts per device by severity |
| `product-versions` | Device count per software vendor, product and version |

Ad hoc KQL: `python3 -m dva hunt --kql "DeviceInfo | summarize count() by OSPlatform" --name os-mix`. Every query is capped at 10,000 rows server-side; a capped result marks the source `partial` in the manifest, so narrow the query with `where` or `summarize`. Management and ingestion commands are rejected.

## Reading the reports

- **`report.md`**: executive summary, top 10 products, each with a plain-language "Risk" paragraph explaining what the most critical vulnerability lets an attacker do and what is exposed, the three CVEs driving the score, remediation text from Defender's recommendations, and the most critical affected assets with a count. Diffable between runs.
- **`report.html`**: the same content as a self-contained page with filters (has critical, KEV-listed, internet-facing), sorting and expandable rows. Open it in a browser or share the file; it makes no network requests.
- **`report.json`** and **`findings.json`**: the full scored data, including every CVE and every asset per product, for downstream tooling.

Products are ranked by a 0 to 100 score; see [architecture.md](architecture.md#scoring) for the formula and [configuration.md](configuration.md) for the weights. The top 10 are always listed; `report_threshold` decides how many count as needing action.

## Offline demo

The pipeline runs without credentials or network using canned responses:

```bash
export DVA_RUNS_DIR=/tmp/dva-demo/runs DVA_CACHE_DIR=/tmp/dva-demo/cache
export DVA_RUN=$(python3 -m dva run new)
python3 -m dva mde all --fixture tests/fixtures/mde/all.json
python3 -m dva hunt internet-facing --fixture tests/fixtures/hunting/internet-facing.json
python3 -m dva enrich --list
python3 -m dva enrich --store tests/fixtures/cve/triage-e2e.txt
python3 -m dva score
python3 -m dva report --all
```

This is exactly what `tests/test_e2e.py` runs. The resulting report shows an Ivanti Connect Secure product driven by a KEV-listed CVE on an internet-facing Tier0 gateway.

## Run directory layout

| File | Written by | Contents |
|---|---|---|
| `manifest.json` | every command | Run id, start time, per-source status (`ok`/`partial`/`failed`) and counts |
| `machines.json` | `mde machines` | Normalized device inventory |
| `vulns.jsonl` | `mde vulns` | One row per device, software and CVE |
| `recommendations.json` | `mde recommendations` | Remediation text and recommended versions |
| `exposure.json` | `mde score` | Organization and per-group exposure score |
| `hunt-<name>.json` | `hunt` | Raw Advanced Hunting result |
| `cloud-vulns.jsonl` | `cloud vulns` | Defender for Cloud findings per resource and CVE |
| `enrich-candidates.json` | `enrich --list` | CVE ids selected for enrichment |
| `cve-triage-*.txt`, `cve-lookup-*.txt` | the agent | Saved CVE server results (triage and descriptions) |
| `enrichment.json` | `enrich --store` | Parsed CVE intel for this run |
| `findings.json` | `score` | Scored products and the diff from the previous run |
| `report.md` / `.html` / `.json` | `report` | Rendered reports |
| `summary.txt`, `log.txt` | every command | One-line summaries; errors from failed sources |
