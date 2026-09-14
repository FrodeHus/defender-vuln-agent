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
python3 -m dva report [--md] [--html] [--json] [--tickets] [--all] [--run RUN]
python3 -m dva exception list
python3 -m dva exception add --product KEY | --cve ID --reason TEXT --until DATE [--owner NAME]
python3 -m dva exception remove --product KEY | --cve ID
python3 -m dva exception suggest [--run RUN]
```

`enrich --list` prints one JSON line per chunk: `{"chunk": n, "cve_ids": [...]}` (cached CVEs already excluded). The cve-mcp server returns formatted text and has no batch lookup, so for every listed id call `triage_cve(cve_id, depth="standard")` (one call per CVE; it fans out NVD, EPSS, CISA KEV and PoC checks), save each result to `$DVA_RUN/cve-triage-<id>.txt`, and for each id in the `{"describe": [...]}` line call both `lookup_cve(cve_id)` (save to `$DVA_RUN/cve-lookup-<id>.txt`, powers the per-product risk summary) and `get_vendor_advisory(cve_id)` (save to `$DVA_RUN/cve-advisory-<id>.txt`, powers the vendor advisory links per product); then merge everything at once with `dva enrich --store "$DVA_RUN"/cve-*.txt` (`--store` accepts many files). `dva enrich --store` also understands `compare_cves`, `get_epss_score` (comma-separated ids as ONE string), `lookup_cve`, `check_kev` and `check_poc_exists` output if you ever use those instead. `dva score` writes `findings.json`; `dva report --all` (equivalent to `--md --html --json --tickets`) renders it.

## Exceptions (accepted risk)

Products under an active exception are excluded from scoring, the top list and the ticket export; they are listed under `findings.json`'s `accepted_risks.active` with reason, until, owner and the score they would otherwise have. An exception whose `until` date has passed re-enters ranking with `flags.exception_expired = true` on its row, and is listed under `accepted_risks.expired`. Exceptions live in `tenants/<name>/exceptions.yaml` (or `config/exceptions.yaml` outside a tenant), are per tenant, and are managed ONLY through `dva exception add|remove|list|suggest` — never by hand-editing the file.

After `dva report --all`, run `dva exception suggest`: it prints one JSON line per product worth an exception, with `reasons` such as `embedded component` (matches a common bundled library like OpenSSL, zlib, a JRE/JDK...), `bundled across N products` (the same evidenced install spans 3+ unrelated top-level product folders), `no vendor fix` (no Defender recommendation, or it's Uninstall/ConfigurationChange), or `end of support`, plus a `suggested_until` 90 days out; it also writes `exception-suggestions.json`. Report the suggestions to the user and add one only when they explicitly confirm, with `--owner` set to their name (ask if you don't have it).

## Outputs

`enrichment.json` (merged CVE data), `findings.json` (scored products, accepted risks, trend, posture), and under `--all`: `report.md`, `report.html`, `report.json`, `tickets.json` in the run directory. `dva report --tickets` (included in `--all`) writes `tickets.json`, one ticket per listed product not under exception, with a priority, labels and a Markdown description — no API calls are made, it's a file for you to hand to a ticketing system.

## Trend and recently patched

`findings.json`'s `trend` (up to the last `trend_runs` runs) and `score_trend` (last 12 months, from the per-tenant SQLite store) back the report's trend table and exposure/secure-score sparkline. Each product row's `patched_7d` counts Critical/High CVEs Defender marked Fixed in the last 7 days (from `dva mde changes`); `findings.json`'s `summary.patched_7d_critical` is the estate-wide total. Mention SLA breaches (`summary.sla_breaches`), end-of-support products (`summary.eos_products`), the patched-in-7-days total and the score trend in your reply whenever they are present.

## Tuning

`config/scoring.yaml` controls scoring: `threat_weights` (cvss/epss/kev/exploit/ransomware), `asset_bonus` and `asset_cap`, `criticality_tags`, `enrich_top_per_product` and `enrich_max_cves` (how many CVEs `enrich --list` selects), `report_threshold`, `top_n`, `cache_ttl_days`, `bands` (critical/high/medium score cutoffs), `sla_days` and `overdue_boost`, `mitigation_configs`, `exception_components`, `trend_runs`. Edit this file, then re-run only `dva score` and `dva report --all` — no need to re-collect.

## Gotchas

- Never paste raw CVE server results into a reply; write them to a file and let `dva enrich --store` merge them. Use a quoted heredoc delimiter (`cat <<'TXT' > FILE` ... `TXT`) so the shell writes the text byte for byte — an unquoted delimiter expands `$`, backticks and backslash escapes and corrupts it.
- `enrich --list` excludes CVEs already cached within `cache_ttl_days`; an empty chunk list means nothing new needs enrichment.
- Never `cat` `enrichment.json` or `findings.json`; read `report.md` instead.
- Exceptions are never shared across tenants and are never edited by hand — always go through `dva exception`.
