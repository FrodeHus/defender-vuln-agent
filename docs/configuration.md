# Configuration

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `DVA_TENANT_ID`, `DVA_CLIENT_ID`, `DVA_CLIENT_SECRET` | App registration credential (client secret) | required |
| `DVA_CLIENT_CERT_PATH`, `DVA_CLIENT_CERT_THUMBPRINT` | Client certificate instead of a secret | |
| `DVA_TENANT` | Tenant to act on (same as `--tenant`) | none, single-tenant mode |
| `DVA_TENANTS_DIR` | Where tenant directories live | `tenants/` |
| `DVA_TENANT_NAME` | Friendly name shown in reports | looked up from Graph (`CrossTenantInformation.ReadBasic.All`, cached per tenant), else the tenant directory name, else `DVA_TENANT_ID` |
| `DVA_RUNS_DIR` | Where run directories are created | `runs/`, or `tenants/<name>/runs/` |
| `DVA_CACHE_DIR` | Token cache, `dva.sqlite` (run history) and `cve/dva.sqlite` (CVE intel) — see below | `.cache/`, or `tenants/<name>/.cache/` |
| `DVA_RUN` | Pin commands to one run directory instead of the latest | latest run |
| `CVE_MCP_PYTHON` | Interpreter Claude Code uses to start the CVE server | `.venv/bin/python3` |

Precedence: a selected tenant's `.env` overrides everything; otherwise exported shell variables override the repository `.env`.

## `config/scoring.yaml`

| Key | Default | Meaning |
|---|---|---|
| `threat_weights` | cvss 0.35, epss 0.25, kev 0.25, exploit 0.15, ransomware 0.10 | Weights of the five threat signals in a CVE's threat score (they sum to 1.10 before the score is capped at 1) |
| `asset_bonus` | internet_facing 0.6, exposure_high 0.4, exposure_medium 0.2, device_value_high 0.4, criticality_tag 0.5, public_lb 0.6, privileged_user 0.4, attack_path 0.6, mitigated -0.2 | Additive multiplier bonuses (and one discount, `mitigated`) for asset context |
| `asset_cap` | 2.5 | Ceiling for the asset multiplier |
| `criticality_tags` | Tier0, Prod, DMZ | Device tags (case-insensitive) that earn `criticality_tag` |
| `enrich_top_per_product` | 3 | CVEs per product sent for enrichment, ranked by Defender CVSS, exploitability, then recency |
| `enrich_max_cves` | 200 | Cap on CVEs enriched per run |
| `enrich_threshold` | 20 | Products whose preliminary score is below this are not enriched |
| `report_threshold` | 40 | Score at which a product counts as needing action |
| `top_n` | 10 | Products always listed and tracked in the run-to-run diff |
| `cache_ttl_days` | 7 | How long CVE intel stays fresh before it is fetched again |
| `bands` | critical 80, high 60, medium 40 | Label thresholds |
| `sla_days` | critical 14, high 30, medium 90, low 180 | Age (from a CVE's earliest `first_seen`) after which it counts as an SLA breach for its severity |
| `overdue_boost` | 1.10 | Multiplier applied to a product's score, before the cap, when it has any overdue CVE |
| `mitigation_configs` | [] | `DeviceTvmSecureConfigurationAssessment` `ConfigurationId`s treated as compensating controls for the `mitigations` hunting query and the `mitigated` asset bonus; pick ids from the `mitigation-catalog` query. Empty list skips the query. |
| `exception_components` | openssl, zlib, curl, libxml2, libxslt, sqlite, log4j, jre, jdk, java, python, node, ".net runtime", redistributable, msxml, expat, libpng | Case-insensitive substrings of a product's name that `dva exception suggest` flags as a commonly-bundled embedded component |
| `trend_runs` | 8 | How many previous runs' `findings.json` feed the run-to-run trend table when no SQLite store history is available |

Edit, then re-run only `dva score` and `dva report --all`; no re-collection needed. A tenant can carry its own copy at `tenants/<name>/scoring.yaml`, which replaces the defaults entirely for that tenant.

## `config/sources.yaml`

| Key | Default | Meaning |
|---|---|---|
| `mde` | true | Collect from the Defender for Endpoint API |
| `hunting` | true | Run Advanced Hunting queries |
| `cloud` | false | Collect Defender for Cloud findings via Azure Resource Graph |
| `subscriptions` | [] | Subscription ids for `cloud` (the app needs `Reader` on each) |
| `hunting_queries` | internet-facing, exploited-cves, device-tags, vuln-counts-by-device, product-versions, evidence, privileged-logons, mitigations, certificates, config-findings | Queries `dva hunt` runs when given no names |
| `shared_cve_cache` | false | When true, CVE intel is shared across all tenants in one file at `<repo>/.cache/cve.sqlite` instead of each tenant's own cache. Run history stays per tenant regardless. |

A tenant's `tenants/<name>/sources.yaml` is merged over the defaults, so it can contain only the keys that differ, typically `cloud` and `subscriptions`.

## `dva.sqlite` store

Each tenant's cache directory holds two SQLite files (both mode 600, WAL journaling), not one:

- `<cache>/dva.sqlite` — run history: a `runs`/`product_history` pair recording every `dva score` run (`exposure_score`, `secure_score`, and per-product scores) for trend reporting without rescanning old `findings.json` files. Opened by `open_store()`, always per tenant.
- `<cache>/cve/dva.sqlite` — CVE intel: the `cve_intel` table backing `IntelCache`. Opened by `open_intel_store()`; when `shared_cve_cache` is true this instead points at the repo-level `<repo>/.cache/cve.sqlite`, shared across tenants.

The intel store is the sole source of truth for CVE intel: `dva/cache.py`'s `IntelCache.get`/`put`/`all_fresh` read and write only it. Pre-existing per-CVE JSON files from before this cache was store-backed are imported into it once, the first time a cache directory is opened; after that the JSON files are never read again, even if new ones are dropped in later. `dva/score_cmd.py`'s `compute()` reads trend rows from the run-history store when one is passed and it already has rows, otherwise it falls back to scanning previous run directories.

## `exceptions.yaml`

Accepted-risk exceptions live at `tenants/<name>/exceptions.yaml` while a tenant is active, else `config/exceptions.yaml` (`config/exceptions.example.yaml` is the committed template); both are gitignored, mode 600, and per tenant. Each entry names either a `product` (vendor/name key) or a `cve` id, a `reason`, a required `until` ISO date, an optional `owner`, an `added` timestamp and a `source` (`user` or `suggested`). Manage the file only with `dva exception list|add|remove|suggest` — never edit it by hand; the agent follows the same rule and only adds an exception when the user explicitly confirms it, with `--owner` set to their name. See [usage.md](usage.md#exceptions-accepted-risk) for the commands and how exceptions affect scoring.

## Tenants

```
tenants/
  contoso/
    .env             credentials (mode 600)
    scoring.yaml      optional, replaces config/scoring.yaml for this tenant
    sources.yaml      optional, merged over config/sources.yaml
    exceptions.yaml   accepted-risk exceptions for this tenant (mode 600)
    runs/             this tenant's runs
    .cache/           this tenant's token cache, dva.sqlite (run history) and cve/dva.sqlite (CVE intel)
```

`dva tenant init NAME` creates the skeleton; `dva tenant list` and `dva tenant show` inspect. Nothing is shared between tenants except code and the repo-level defaults. The whole `tenants/` directory is gitignored.

## Agent and skills

The Claude Code agent is `.claude/agents/vuln-assessor.md`; its `model:` line picks the model and `tools:` restricts it to Bash, file reading and the CVE server tools. The skills under `.claude/skills/` document each command group for the agent. `tests/test_agent_files.py` pins the commands and flags they cite to the real CLI, so update the tests if you change them.

## CVE server

`.mcp.json` starts `cve-mcp` with the project venv's interpreter. Its API keys come from `../cve-mcp-server/.env`. Only `triage_cve` is required; the parser also understands `compare_cves`, `get_epss_score`, `lookup_cve`, `check_kev`, `check_poc_exists` and `get_vendor_advisory` output if you save any of those into the run directory.
