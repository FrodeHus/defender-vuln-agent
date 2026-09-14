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
- `product-versions` — installed product/version distribution.
- `vuln-counts-by-device` — vulnerability counts per device.

`--run` defaults to `$DVA_RUN` or the latest run under `runs/`. `--timespan` bounds the query window as an ISO-8601 duration (e.g. `P1D`, `P7D`, `P30D`), default `P7D`. `--fixture` replaces the live call for offline runs.

## Outputs

One `hunt-<name>.json` file per query under the run directory, plus a printed one-line summary (row count, and whether the source is partial/failed).

## Gotchas

- Ad hoc KQL only through `--kql "<query>" --name <name>`; only read-only tables are allowed.
- Results are capped at 10,000 rows. Narrow a broad ad hoc query with `summarize`, `take`, or `where Timestamp > ago(1d)` rather than relying on the cap to truncate silently.
- A single failed or partial source is not fatal — continue to enrichment and scoring; note the partial source in the final summary.
- Never `cat` `hunt-*.json`; use the printed summary or `report.md`.
