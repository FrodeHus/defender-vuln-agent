# Defender Vulnerability Agent

A command-line tool and Claude Code agent for assessing Microsoft Defender for Endpoint (MDE) vulnerability data. It pulls machine inventory, software vulnerabilities, recommendations, exposure score and Advanced Hunting results from MDE, enriches the highest-risk CVEs with threat intelligence (CVSS, EPSS, CISA KEV, public exploits) through a CVE MCP server, scores affected products by exploitability and asset criticality, and writes Markdown, HTML and JSON reports. It is read-only: the app registration used for authentication has no write permissions against Defender, Graph or Azure.

## What it does

1. Collects device inventory, per-device software vulnerabilities, security recommendations and the organizational exposure score from the MDE API.
2. Runs Advanced Hunting KQL queries (`dva/queries/*.kql`) for internet-facing devices, already-exploited CVEs and device tags.
3. Rolls devices and vulnerabilities up into affected products, selects the top CVEs per product worth enriching, and fetches CVSS/EPSS/KEV/exploit data for them via the `cve-mcp` server.
4. Scores each product using a configurable weighted formula (threat signals + asset criticality bonuses) and writes `findings.json`.
5. Renders `report.md`, `report.html` and `report.json` from the findings.

## Setup

1. Create and activate a virtual environment, then install the package in editable/dev mode:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. Install the [`cve-mcp-server`](https://github.com/mukul975/cve-mcp-server) into the **same** venv, so its MCP server process shares the environment the agent runs in:

   ```bash
   git clone https://github.com/mukul975/cve-mcp-server ../cve-mcp-server
   pip install -e ../cve-mcp-server
   export NVD_API_KEY=<your-nvd-api-key>
   ```

3. Create the Entra app registration used for authentication (requires the Azure CLI and Global Administrator or Application Administrator + Privileged Role Administrator consent rights):

   ```bash
   setup/create-app.sh
   ```

   This creates the app, assigns the MDE and Graph application permissions listed in `setup/permissions.md`, and prints the environment variables to export. Use `--dry-run` to preview the `az` commands without making changes.

4. Export the credentials it prints (client secret shown here; a client certificate also works — see `setup/permissions.md`):

   ```bash
   export DVA_TENANT_ID=<tenant-id>
   export DVA_CLIENT_ID=<app-id>
   export DVA_CLIENT_SECRET=<client-secret>
   ```

   Alternatively put the same `KEY=VALUE` lines in a `.env` file in the repository root (it is
   gitignored). `python3 -m dva` reads `.env` from the current directory or the repository root at
   startup; variables already exported in the shell take precedence over the file.

   Other environment variables the tool honours:

   | Variable | Purpose | Default |
   |---|---|---|
   | `DVA_TENANT_ID` / `DVA_CLIENT_ID` / `DVA_CLIENT_SECRET` | App registration credential (client secret) | none |
   | `DVA_CLIENT_CERT_PATH` / `DVA_CLIENT_CERT_THUMBPRINT` | App registration credential (client certificate, used instead of a secret) | none |
   | `DVA_RUNS_DIR` | Where run directories are created | `runs/` |
   | `DVA_CACHE_DIR` | Where the token cache and CVE intel cache live | `.cache/` |
   | `DVA_RUN` | Pin commands to a specific run directory instead of the latest under `DVA_RUNS_DIR` | latest run |
   | `DVA_TENANT_NAME` | Friendly tenant name shown in reports (falls back to `DVA_TENANT_ID`) | `unknown` |

5. Verify credentials and permissions:

   ```bash
   python3 -m dva doctor
   ```

   This calls each required API with a minimal read-only request and prints a pass/fail table. See `setup/permissions.md` for what each permission is used for and how to fix a failure.

## Running the agent

The easiest way is to ask the `vuln-assessor` Claude Code agent for an assessment from inside `claude`:

```
claude
> ask vuln-assessor for a vulnerability assessment
```

It runs `dva doctor`, collects from MDE and Advanced Hunting, enriches the CVEs `dva enrich --list` selects via the `cve-mcp` tools, scores, renders reports, and replies with the top products, the count needing action, and any source that failed or was partial.

To run the same pipeline manually:

```bash
export DVA_RUN=$(python3 -m dva run new)
python3 -m dva mde all
python3 -m dva hunt internet-facing exploited-cves device-tags
python3 -m dva enrich --list                      # prints {"chunk": N, "cve_ids": [...]} lines
# for each chunk, call bulk_cve_lookup with those cve_ids, save the result, then:
python3 -m dva enrich --store "$DVA_RUN/cve-chunk-1.json"
python3 -m dva score
python3 -m dva report --all
```

Reports land in `$DVA_RUN/report.md`, `report.html` and `report.json`.

## Offline demo

The full pipeline can be exercised with no credentials and no network access, using canned API responses (`--fixture`) instead of live calls. This is also what `tests/test_e2e.py` runs:

```bash
export DVA_RUNS_DIR=/tmp/dva-demo/runs DVA_CACHE_DIR=/tmp/dva-demo/cache
export DVA_RUN=$(python3 -m dva run new)
python3 -m dva mde all --fixture tests/fixtures/mde/all.json
python3 -m dva hunt internet-facing --fixture tests/fixtures/hunting/internet-facing.json
python3 -m dva enrich --list
python3 -m dva enrich --store tests/fixtures/cve/bulk.json
python3 -m dva score
python3 -m dva report --all
```

`$DVA_RUN` then contains a complete run: `report.md`/`report.html`/`report.json` describing an Ivanti Connect Secure product driven by the KEV-listed `CVE-2026-21887` on the internet-facing, Tier0, high-value device `vpn-gw-01.corp.example`.

## Tuning

Scoring is controlled by `config/scoring.yaml`:

| Key | Meaning |
|---|---|
| `threat_weights` | Weights (`cvss`, `epss`, `kev`, `exploit`) applied to the normalized threat signal that feeds the score |
| `asset_bonus` | Score bonuses for asset context: `internet_facing`, `exposure_high`, `exposure_medium`, `device_value_high`, `criticality_tag`, `public_lb` |
| `asset_cap` | Maximum total asset bonus applied per product |
| `criticality_tags` | Device tags (e.g. `Tier0`, `Prod`, `DMZ`) that count toward `criticality_tag` |
| `enrich_top_per_product` | How many CVEs per product are candidates for CVE-server enrichment |
| `enrich_max_cves` | Overall cap on CVEs sent for enrichment in one run |
| `report_threshold` | Minimum score for a product to appear in `findings.json` / reports |
| `top_n` | How many top products are tracked for the run-over-run diff |
| `cache_ttl_days` | How long cached CVE intel is considered fresh before re-enrichment |
| `bands` | Score thresholds (`critical`, `high`, `medium`) for the label shown per product |

Which data sources are collected is controlled by `config/sources.yaml` (`mde`, `hunting`, `cloud`, `subscriptions`, `hunting_queries`).

## Outputs

Each run lives in its own directory under `DVA_RUNS_DIR` (default `runs/<timestamp>/`):

| File | Written by | Contents |
|---|---|---|
| `manifest.json` | every command | Run id, start time, per-source status (`ok`/`partial`/`failed`) and row counts |
| `machines.json` | `dva mde machines` / `mde all` | Normalized device inventory |
| `vulns.jsonl` | `dva mde vulns` / `mde all` | One row per device/software/CVE |
| `recommendations.json` | `dva mde recommendations` / `mde all` | Remediation text and recommended versions per product |
| `exposure.json` | `dva mde score` / `mde all` | Organization exposure score and per-group scores |
| `hunt-<name>.json` | `dva hunt <name>` | Raw Advanced Hunting query result (schema + rows) |
| `enrich-candidates.json` | `dva enrich --list` | CVE ids selected for enrichment |
| `enrichment.json` | `dva enrich --store` | Enriched CVE intel merged into the cache, plus any still missing |
| `findings.json` | `dva score` | Scored products, driving CVEs, asset breakdowns and the diff from the previous run |
| `report.md` / `report.html` / `report.json` | `dva report` | Rendered reports from `findings.json` |
| `summary.txt` | every command | One line per command run, appended |
| `log.txt` | every command | Timestamped errors from failed sources |

## First-run checklist

- [ ] On the first real (non-fixture) run, capture the actual `bulk_cve_lookup` result for a chunk into `tests/fixtures/cve/bulk.json` in place of the placeholder data, and compare its keys against `dva/enrich.py:_one()`/`parse_store`. Adjust the key paths there if the live server's shape differs from what's assumed (e.g. different field names for CVSS, EPSS, KEV or exploit info).
