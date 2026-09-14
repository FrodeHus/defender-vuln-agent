---
name: defender-inventory
description: Collect device, vulnerability, software, recommendation and exposure-score data from the Defender for Endpoint API into a run directory.
---

## When to use

After `dva run new` (or with `--run` pointed at an existing run), to pull the inventory that scoring and reporting need.

## Commands

```
python -m dva mde machines [--run RUN] [--fixture FILE]
python -m dva mde vulns [--run RUN] [--fixture FILE]
python -m dva mde recommendations [--run RUN] [--fixture FILE]
python -m dva mde score [--run RUN] [--fixture FILE]
python -m dva mde all [--run RUN] [--fixture FILE]
```

`mde all` runs the four collectors in sequence against one run directory; prefer it over calling each collector separately. `--run` defaults to `$DVA_RUN` or the latest run under `runs/`. `--fixture` replaces the live API call with a canned JSON response file, for offline runs and tests.

## Outputs

Written under the run directory: `machines.json`, `vulns.jsonl`, `recommendations.json`, `score.json`. A one-line summary per collector is printed to stdout — that summary, not the raw files, is what you should read back.

## Gotchas

- The vulnerability export uses a 50,000-row page size (`pageSize=50000` on `/machines/SoftwareVulnerabilitiesByMachine`); large tenants may need several pages, handled automatically.
- The Defender export APIs are rate-limited to roughly 30 calls/minute; `mde all` paces itself, but running collectors in a tight loop across many runs can hit the limit — space out repeated runs.
- `--fixture` is per-collector: pass a fixture file matching that collector's expected API shape, not a whole run's worth of data.
- Never `cat` `vulns.jsonl` or `machines.json` directly — they can be very large; use the printed summaries or downstream `report.md`.
