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
| `DVA_CACHE_DIR` | Token cache, CVE intel and the `dva.sqlite` store (CVE intel, run history) | `.cache/`, or `tenants/<name>/.cache/` |
| `DVA_RUN` | Pin commands to one run directory instead of the latest | latest run |
| `CVE_MCP_PYTHON` | Interpreter Claude Code uses to start the CVE server | `.venv/bin/python3` |

Precedence: a selected tenant's `.env` overrides everything; otherwise exported shell variables override the repository `.env`.

## `config/scoring.yaml`

| Key | Default | Meaning |
|---|---|---|
| `threat_weights` | cvss 0.35, epss 0.25, kev 0.25, exploit 0.15 | Weights of the four threat signals in a CVE's threat score |
| `asset_bonus` | internet_facing 0.6, exposure_high 0.4, exposure_medium 0.2, device_value_high 0.4, criticality_tag 0.5, public_lb 0.6 | Additive multiplier bonuses for asset context |
| `asset_cap` | 2.5 | Ceiling for the asset multiplier |
| `criticality_tags` | Tier0, Prod, DMZ | Device tags (case-insensitive) that earn `criticality_tag` |
| `enrich_top_per_product` | 3 | CVEs per product sent for enrichment, ranked by Defender CVSS, exploitability, then recency |
| `enrich_max_cves` | 200 | Cap on CVEs enriched per run |
| `enrich_threshold` | 20 | Products whose preliminary score is below this are not enriched |
| `report_threshold` | 40 | Score at which a product counts as needing action |
| `top_n` | 10 | Products always listed and tracked in the run-to-run diff |
| `cache_ttl_days` | 7 | How long CVE intel stays fresh before it is fetched again |
| `bands` | critical 80, high 60, medium 40 | Label thresholds |

Edit, then re-run only `dva score` and `dva report --all`; no re-collection needed. A tenant can carry its own copy at `tenants/<name>/scoring.yaml`, which replaces the defaults entirely for that tenant.

## `config/sources.yaml`

| Key | Default | Meaning |
|---|---|---|
| `mde` | true | Collect from the Defender for Endpoint API |
| `hunting` | true | Run Advanced Hunting queries |
| `cloud` | false | Collect Defender for Cloud findings via Azure Resource Graph |
| `subscriptions` | [] | Subscription ids for `cloud` (the app needs `Reader` on each) |
| `hunting_queries` | the five named queries | Queries `dva hunt` runs when given no names |
| `shared_cve_cache` | false | When true, CVE intel is shared across all tenants in one file at `<repo>/.cache/cve.sqlite` instead of each tenant's own cache. Run history stays per tenant regardless. |

A tenant's `tenants/<name>/sources.yaml` is merged over the defaults, so it can contain only the keys that differ, typically `cloud` and `subscriptions`.

## `dva.sqlite` store

Each tenant's cache directory holds `dva.sqlite` (mode 600, WAL journaling): a `cve_intel` table backing `IntelCache` and a `runs`/`product_history` pair recording every `dva score` run (`exposure_score`, `secure_score` once Task 9 lands, and per-product scores) for trend reporting without rescanning old `findings.json` files. The store is the sole source of truth for CVE intel: `dva/cache.py`'s `IntelCache.get`/`put`/`all_fresh` read and write only the store. Pre-existing per-CVE JSON files from before this cache was store-backed are imported into the store once, the first time a cache directory is opened; after that the JSON files are never read again, even if new ones are dropped in later. `dva/score_cmd.py`'s `compute()` reads trend rows from the store when one is passed and it already has rows, otherwise it falls back to scanning previous run directories.

## Tenants

```
tenants/
  contoso/
    .env            credentials (mode 600)
    scoring.yaml    optional, replaces config/scoring.yaml for this tenant
    sources.yaml    optional, merged over config/sources.yaml
    runs/           this tenant's runs
    .cache/         this tenant's token and CVE caches
```

`dva tenant init NAME` creates the skeleton; `dva tenant list` and `dva tenant show` inspect. Nothing is shared between tenants except code and the repo-level defaults. The whole `tenants/` directory is gitignored.

## Agent and skills

The Claude Code agent is `.claude/agents/vuln-assessor.md`; its `model:` line picks the model and `tools:` restricts it to Bash, file reading and the CVE server tools. The skills under `.claude/skills/` document each command group for the agent. `tests/test_agent_files.py` pins the commands and flags they cite to the real CLI, so update the tests if you change them.

## CVE server

`.mcp.json` starts `cve-mcp` with the project venv's interpreter. Its API keys come from `../cve-mcp-server/.env`. Only `triage_cve` is required; the parser also understands `compare_cves`, `get_epss_score`, `lookup_cve`, `check_kev` and `check_poc_exists` output if you save any of those into the run directory.
