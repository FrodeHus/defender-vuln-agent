# Changelog

## Unreleased

## 0.2.0 - 2026-09-14

- Multi-tenant support: `tenants/<name>/` holds each tenant's credentials, runs, caches and optional config overrides; select with `--tenant` or `DVA_TENANT`; `dva tenant list|init|show`.
- Enrichment rewritten for the real `cve-mcp` server contract: one `triage_cve` call per selected CVE, text output parsed from captured fixtures, `enrich --store` takes many files.
- `.env` loading at CLI startup; `python3` everywhere; `cve-mcp` launched from the project venv.
- Reports always list the top 10 products even when none clear the action threshold.
- `exploited-cves` hunting query scoped to CVEs present in the estate.
- Open-source packaging: MIT license, `dva` console script, CI, installer, docs.

## 0.1.0 - 2026-09-14

- First working pipeline: MDE and Advanced Hunting collectors, Defender for Cloud collector with de-duplication, product roll-up, scoring, Markdown/HTML/JSON reports, `vuln-assessor` Claude Code agent and skills, app-registration setup script, offline end-to-end test.
