---
name: vuln-prioritize-report
description: Enrich collected CVEs through the cve-mcp server, score products, and render Markdown/HTML/JSON reports.
---

## When to use

After `dva mde all` and `dva hunt` have populated a run directory, to select which CVEs need external enrichment, merge that enrichment back in, compute product scores, and produce the final reports.

## Commands

```
python3 -m dva enrich --list [--run RUN]
python3 -m dva enrich --store FILE [--run RUN]
python3 -m dva score [--run RUN]
python3 -m dva report [--md] [--html] [--json] [--all] [--run RUN]
```

`enrich --list` prints one JSON line per chunk: `{"chunk": n, "cve_ids": [...]}` (cached CVEs already excluded). The cve-mcp server returns formatted text and has no batch lookup, so for every listed id call `triage_cve(cve_id, depth="standard")` (one call per CVE; it fans out NVD, EPSS, CISA KEV and PoC checks), save each result to `$DVA_RUN/cve-triage-<id>.txt`, and for each id in the `{"describe": [...]}` line call `lookup_cve(cve_id)` and save it to `$DVA_RUN/cve-lookup-<id>.txt` (its description powers the per-product risk summary); then merge everything at once with `dva enrich --store "$DVA_RUN"/cve-*.txt` (`--store` accepts many files). `dva enrich --store` also understands `compare_cves`, `get_epss_score` (comma-separated ids as ONE string), `lookup_cve`, `check_kev` and `check_poc_exists` output if you ever use those instead. `dva score` writes `findings.json`; `dva report --all` (equivalent to `--md --html --json`) renders it.

## Outputs

`enrichment.json` (merged CVE data), `findings.json` (scored products), and under `--all`: `report.md`, `report.html`, `report.json` in the run directory.

## Tuning

`config/scoring.yaml` controls scoring: `threat_weights` (cvss/epss/kev/exploit), `asset_bonus` and `asset_cap`, `criticality_tags`, `enrich_top_per_product` and `enrich_max_cves` (how many CVEs `enrich --list` selects), `report_threshold`, `top_n`, `cache_ttl_days`, `bands` (critical/high/medium score cutoffs). Edit this file, then re-run only `dva score` and `dva report --all` — no need to re-collect.

## Gotchas

- Never paste raw CVE server results into a reply; write them to a file and let `dva enrich --store` merge them. Use a quoted heredoc delimiter (`cat <<'TXT' > FILE` ... `TXT`) so the shell writes the text byte for byte — an unquoted delimiter expands `$`, backticks and backslash escapes and corrupts it.
- `enrich --list` excludes CVEs already cached within `cache_ttl_days`; an empty chunk list means nothing new needs enrichment.
- Never `cat` `enrichment.json` or `findings.json`; read `report.md` instead.
