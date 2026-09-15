# Changelog

## Unreleased

- Non-compliant configurations in the Posture appendix show the knowledge-base display name (id underneath in HTML, id alone when the KB has no row) with the description as a tooltip, linked to the control's documentation when the KB text carries an absolute link, plus a Portal column deep-linking to the recommendation in the Defender portal; `config-findings.kql` joins `DeviceTvmSecureConfigurationAssessmentKB`, and the KB's HTML is flattened to plain text in `findings.json`.
- Every driving CVE of a listed product gets a description and vendor advisories, not just the top one: `enrich --fetch`/`--list` request `lookup_cve` and `get_vendor_advisory` for all `enrich_top_per_product` CVEs, `findings.json` carries `description` per driving CVE, both reports show it under the CVE line, and a product's advisories are merged across its driving CVEs.
- Long-standing vulnerabilities: `findings.json` gains `long_standing` (products still carrying CVEs first seen more than `long_standing_days`, default 90, ago, regardless of score, with counts, oldest age and severity split) and `summary.long_standing_products`; both reports render it as a section and `report --brief` names them. These are the products no patch regime is picking up.
- `dva report --brief` prints the dozen lines the agent's reply needs (top 3 with reasons, counts, SLA, end of support, long-standing, patched in 7 days, score trend, sources not ok, accepted risks, exception suggestions, run path) and writes nothing; the agent replies from it instead of reading the 13 KB `report.md`.
- CVE cache refresh keeps what never changes: an entry past `cache_ttl_days` is triaged again for EPSS/KEV/PoC but keeps its description, vector, CWE and vendor advisories, and `enrich --fetch`/`--list` no longer re-request descriptions for it.
- HTML report: the score trend is drawn as two panels, exposure score (0-100, lower is better) and secure score (%, higher is better), instead of two opposite-direction series on one axis; the trend sparklines are framed boxes with first/last values instead of bare lines.
- `dva enrich --fetch` does the whole enrichment step itself: it starts the CVE server over stdio through a small stdlib-only MCP client (`dva/mcp_client.py`), calls `triage_cve`, `lookup_cve` and `get_vendor_advisory` for the selected CVEs, saves and merges the results. The agent no longer relays CVE text through its context (previously up to ~250 tool calls and as many heredocs per run) and needs no MCP tools; `--list`/`--store` remain for manual use. `DVA_CVE_MCP` / `--server CMD` override the server command.
- The CVE server is no longer cloned next to the repo: `.mcp.json` runs `scripts/cve-mcp.sh`, which starts a pinned upstream `cve-mcp-server` commit through `uvx` (MCP SDK pinned below 2) and passes `NVD_API_KEY` from this repo's `.env`. Works unchanged for marketplace installs via `${CLAUDE_PLUGIN_ROOT}`. `CVE_MCP_PYTHON` and `scripts/install.sh --cve-server-dir` are gone.
- A lone configured tenant is selected automatically when `--tenant`/`DVA_TENANT` is absent; with several tenants the CLI now errors instead of silently using the repo `.env`. `dva doctor` prints which `.env` it checked.
- `uv sync --locked` is the primary install path (`uv.lock` committed, `dependency-groups.dev`); the installer and CI use uv, with a pip fallback.
- Packaged as a Claude Code plugin: `.claude-plugin/plugin.json` and `marketplace.json`, with the agent and skills moved from `.claude/agents/` and `.claude/skills/` to `agents/` and `skills/` at the repo root. Install from the checkout with `claude --plugin-dir .`, or from `/plugin marketplace add FrodeHus/defender-vuln-agent` into another project (see `docs/install.md` for pointing the bundled CVE server at this checkout via `DVA_HOME`). Version bumped to 0.3.0.
- Accepted-risk exceptions: `dva exception list|add|remove|suggest` records known, accepted risks per tenant (a product or a CVE, with a reason, owner and expiry); excepted products are pulled out of scoring and the report and listed under `accepted_risks`, and re-enter ranking flagged once expired. `dva exception suggest` proposes candidates (embedded components, evidence bundled across unrelated products, no vendor fix, end of support).
- SLA age: products carrying a CVE overdue against `scoring.yaml`'s `sla_days` get an `overdue_boost` to their score; the report shows an "Overdue by N days" pill and the estate-wide `sla_breaches` count.
- End of support, fix-version rollups and vendor advisories: `Product.eos` flags software Defender marks end-of-support; `Product.fixes` rolls up which vendor update fixes how many open CVEs; the agent now also calls `get_vendor_advisory` per described CVE and the report links advisory ids (Red Hat, MSRC, Ubuntu).
- Exploit maturity and ransomware signals parsed from the CVE server feed a fifth threat-score weight (`ransomware`) alongside CVSS/EPSS/KEV/exploit.
- Identity context and compensating controls: `privileged-logons` and `mitigations` hunting queries feed new `privileged_user` and `mitigated` asset bonuses; `mitigation-catalog` helps pick compensating-control ids.
- Attack paths (cloud tenants): `dva cloud attack-paths` and the new `attack_path` asset bonus.
- Trend and ticket export: `findings.json` gains a run-to-run `trend` and a 12-month `score_trend` (secure score included), plus new/fixed CVE diffs by severity; `dva report --tickets` (included in `--all`) writes `tickets.json`, one ticket per action item.
- Posture appendix: `certificates` and `config-findings` hunting queries surface expiring certificates and non-compliant configuration in both reports (not scored).
- Per-tenant SQLite store (`dva.sqlite`) is now the sole source of truth for CVE intel and backs run history for trend reporting without rescanning old runs.
- `dva mde changes` collects vulnerability status deltas (`vuln-changes.jsonl`); `mde score` also records the organization's secure score; the report shows CVEs patched in the last 7 days per product and an estate-wide total.
- Installation-path evidence per product (DeviceTvmSoftwareEvidenceBeta), generalized across devices and shown collapsed in both reports; `dva hunt evidence`.
- Plain-language risk summary per product, built from the driving CVE, its description (via `lookup_cve`), CVSS vector and asset exposure.
- Tenant display name resolved through Graph `findTenantInformationByTenantId` (optional `CrossTenantInformation.ReadBasic.All`), with `DVA_TENANT_NAME` and directory-name fallbacks.
- Exposure scores rounded to two decimals.
- HTML report: filter and sort bar now sits directly above the list it controls; new inline SVG sparklines for the trend and 12-month score chart.

## 0.2.0 - 2026-09-14

- Multi-tenant support: `tenants/<name>/` holds each tenant's credentials, runs, caches and optional config overrides; select with `--tenant` or `DVA_TENANT`; `dva tenant list|init|show`.
- Enrichment rewritten for the real `cve-mcp` server contract: one `triage_cve` call per selected CVE, text output parsed from captured fixtures, `enrich --store` takes many files.
- `.env` loading at CLI startup; `python3` everywhere; `cve-mcp` launched from the project venv.
- Reports always list the top 10 products even when none clear the action threshold.
- `exploited-cves` hunting query scoped to CVEs present in the estate.
- Open-source packaging: MIT license, `dva` console script, CI, installer, docs.

## 0.1.0 - 2026-09-14

- First working pipeline: MDE and Advanced Hunting collectors, Defender for Cloud collector with de-duplication, product roll-up, scoring, Markdown/HTML/JSON reports, `vuln-assessor` Claude Code agent and skills, app-registration setup script, offline end-to-end test.
