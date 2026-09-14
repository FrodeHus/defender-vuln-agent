---
name: defender-inventory
description: Collect device, vulnerability, software, recommendation and exposure-score data from the Defender for Endpoint API into a run directory.
---

## When to use

After `dva run new` (or with `--run` pointed at an existing run), to pull the inventory that scoring and reporting need.

## Commands

```
python3 -m dva mde machines [--run RUN] [--fixture FILE]
python3 -m dva mde vulns [--run RUN] [--fixture FILE]
python3 -m dva mde recommendations [--run RUN] [--fixture FILE]
python3 -m dva mde score [--run RUN] [--fixture FILE]
python3 -m dva mde all [--run RUN] [--fixture FILE]
```

`mde all` runs the four collectors in sequence against one run directory; prefer it over calling each collector separately. `--run` defaults to `$DVA_RUN` or the latest run under `runs/`. `--fixture` replaces the live API call with a canned JSON response file, for offline runs and tests.

## Outputs

Written under the run directory: `machines.json`, `vulns.jsonl`, `recommendations.json`, `exposure.json`. A one-line summary per collector is printed to stdout — that summary, not the raw files, is what you should read back.

## Gotchas

- The vulnerability export uses a 50,000-row page size (`pageSize=50000` on `/machines/SoftwareVulnerabilitiesByMachine`); large tenants may need several pages, handled automatically.
- The client retries on HTTP 429, honoring the `Retry-After` header; it does not pre-emptively pace calls. MDE's documented limits are 100 calls/min and 1,500/hour for most endpoints, and 30 calls/min and 1,000/hour for the vulnerabilities export. A throttled run takes longer to finish; it does not produce incomplete data.
- `--fixture` is per-collector: pass a fixture file matching that collector's expected API shape, not a whole run's worth of data.
- Never `cat` `vulns.jsonl` or `machines.json` directly — they can be very large; use the printed summaries or downstream `report.md`.
