# Changelog

## Unreleased

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
