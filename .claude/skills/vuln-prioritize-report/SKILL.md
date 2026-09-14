---
name: vuln-prioritize-report
description: Enrich collected CVEs through the cve-mcp server, score products, and render Markdown/HTML/JSON reports.
---

## When to use

After `dva mde all` and `dva hunt` have populated a run directory, to select which CVEs need external enrichment, merge that enrichment back in, compute product scores, and produce the final reports.

## Commands

```
python -m dva enrich --list [--run RUN]
python -m dva enrich --store FILE [--run RUN]
python -m dva score [--run RUN]
python -m dva report [--md] [--html] [--json] [--all] [--run RUN]
```

`enrich --list` prints one JSON line per chunk: `{"chunk": n, "cve_ids": [...]}` (cached CVEs already excluded). For each chunk, call the cve-mcp tool `bulk_cve_lookup(cve_ids)` with that exact list (max 20 ids per call — `enrich --list` already chunks to this size), save the raw tool result to a file, then run `dva enrich --store FILE` to merge it in. For any CVE the bulk result flags as KEV or EPSS ≥ 0.5, call `triage_cve(cve_id, depth)` with `depth="standard"` (use `"deep"` only if asked for more detail), save the result, and store it with `enrich --store` the same way. `dva score` writes `findings.json`; `dva report --all` (equivalent to `--md --html --json`) renders it.

## Outputs

`enrichment.json` (merged CVE data), `findings.json` (scored products), and under `--all`: `report.md`, `report.html`, `report.json` in the run directory.

## Tuning

`config/scoring.yaml` controls scoring: `threat_weights` (cvss/epss/kev/exploit), `asset_bonus` and `asset_cap`, `criticality_tags`, `enrich_top_per_product` and `enrich_max_cves` (how many CVEs `enrich --list` selects), `report_threshold`, `top_n`, `cache_ttl_days`, `bands` (critical/high/medium score cutoffs). Edit this file, then re-run only `dva score` and `dva report --all` — no need to re-collect.

## Gotchas

- Never paste raw CVE server results into a reply; write them to a file and let `dva enrich --store` merge them.
- `enrich --list` excludes CVEs already cached within `cache_ttl_days`; an empty chunk list means nothing new needs enrichment.
- Never `cat` `enrichment.json` or `findings.json`; read `report.md` instead.
