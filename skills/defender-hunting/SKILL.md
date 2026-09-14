---
name: defender-hunting
description: Run the named or ad hoc Advanced Hunting KQL queries against Microsoft Defender and understand the row-cap guard.
---

## When to use

After `dva mde all`, to pull context the export APIs don't cover (internet-facing devices, exploited CVEs, device tags, product versions, vuln counts by device), or to answer a specific hunting question with ad hoc KQL.

## Commands

```
python3 -m dva hunt [names ...] [--run RUN] [--timespan SPAN] [--fixture FILE]
python3 -m dva hunt --kql "<query>" --name <name> [--run RUN] [--timespan SPAN]
```

Named queries (files in `dva/queries/`, pass the stem as `names`):
- `internet-facing` — devices with internet-facing exposure.
- `exploited-cves` — CVEs on devices with known exploitation activity.
- `device-tags` — device tag assignments.
- `product-versions` — installed product/version distribution, including end-of-support status and date.
- `evidence` — dynamic, not a file: disk and registry installation paths (DeviceTvmSoftwareEvidenceBeta) for the products the report will list, generalized and counted per device. Run it after `mde vulns`; it is skipped with a note when no products are known yet.
- `vuln-counts-by-device` — vulnerability counts per device.
- `privileged-logons` — devices where a user with an assigned Entra role or `CriticalityLevel <= 1` signed in over the last 7 days (needs Defender for Identity or MDE P2 for `IdentityInfo`); feeds the `privileged_user` asset bonus. A failed query is tolerated.
- `mitigations` — devices compliant with the tenant's chosen compensating controls; scoped by `config/scoring.yaml`'s `mitigation_configs` list. With an empty list the query is skipped with a note. Feeds the `mitigated` asset bonus (a discount when all configured controls are compliant).
- `mitigation-catalog` — the full compensating-control catalog (`ConfigurationId`, name, category, subcategory, impact) so you can pick ids to put in `mitigation_configs`. Not scored itself.
- `certificates` — certificates expiring in the next 30 days, feeds the report's Posture appendix (not scored).
- `config-findings` — non-compliant secure-configuration assessments, feeds the report's Posture appendix (not scored).

`--run` defaults to `$DVA_RUN` or the latest run under `runs/`. `--timespan` bounds the query window as an ISO-8601 duration (e.g. `P1D`, `P7D`, `P30D`), default `P7D`. `--fixture` replaces the live call for offline runs.

## Outputs

One `hunt-<name>.json` file per query under the run directory, plus a printed one-line summary (row count, and whether the source is partial/failed).

## Gotchas

- Ad hoc KQL only through `--kql "<query>" --name <name>`; only read-only tables are allowed.
- Results are capped at 10,000 rows. Narrow a broad ad hoc query with `summarize`, `take`, or `where Timestamp > ago(1d)` rather than relying on the cap to truncate silently.
- A single failed or partial source is not fatal — continue to enrichment and scoring; note the partial source in the final summary.
- Never `cat` `hunt-*.json`; use the printed summary or `report.md`.
