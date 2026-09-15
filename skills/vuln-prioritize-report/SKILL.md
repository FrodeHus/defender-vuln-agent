---
name: vuln-prioritize-report
description: Enrich collected CVEs through the cve-mcp server with dva enrich --fetch, score products, and render Markdown/HTML/JSON reports.
---

## When to use

After `dva mde all` and `dva hunt` have populated a run directory, to fetch external enrichment for the CVEs that matter, compute product scores, and produce the final reports.

## Commands

```
python3 -m dva enrich --fetch [--server CMD] [--run RUN]
python3 -m dva enrich --list [--run RUN]
python3 -m dva enrich --store FILE... [--run RUN]
python3 -m dva score [--run RUN]
python3 -m dva report [--md] [--html] [--json] [--tickets] [--all] [--run RUN]
python3 -m dva report --brief [--run RUN]
python3 -m dva exception list
python3 -m dva exception add --product KEY | --cve ID --reason TEXT --until DATE [--owner NAME]
python3 -m dva exception remove --product KEY | --cve ID
python3 -m dva exception suggest [--run RUN]
```

`enrich --fetch` is the whole enrichment step: it selects the CVEs to look up (cached ones excluded), starts the CVE server over stdio (`scripts/cve-mcp.sh`, or `$DVA_CVE_MCP` / `--server CMD`), calls `triage_cve(cve_id, depth="standard")` once per selected CVE plus `lookup_cve` and `get_vendor_advisory` for the one CVE that drives each listed product, saves every text result as `$DVA_RUN/cve-triage-<id>.txt`, `cve-lookup-<id>.txt` and `cve-advisory-<id>.txt`, and merges them into the cache and `enrichment.json`. It prints `fetched N results, M failed` and `stored N, missing M`; a failed CVE is a `warning:` line and is skipped. No CVE text passes through the conversation, so never call CVE tools yourself. `--list` (prints the ids, 20 per `{"chunk": n, "cve_ids": [...]}` line plus a `{"describe": [...]}` line) and `--store FILE...` (parses saved tool outputs: `triage_cve`, `lookup_cve`, `get_vendor_advisory`, `compare_cves`, `get_epss_score`, `check_kev`, `check_poc_exists`) remain for doing the calls by hand. `dva score` writes `findings.json`; `dva report --all` (equivalent to `--md --html --json --tickets`) renders it. `dva report --brief` writes nothing and prints the reply ingredients in a dozen lines (top 3 with reasons, each followed by a `Risk:` line naming the driving CVE and its threat signals, action count, SLA breaches, end of support, long-standing products, patched in 7 days, score trend, sources not ok, accepted risks, exception suggestions when `exception-suggestions.json` exists, run directory); reply from it instead of reading `report.md`.

## Exceptions (accepted risk)

Products under an active exception are excluded from scoring, the top list and the ticket export; they are listed under `findings.json`'s `accepted_risks.active` with reason, until, owner and the score they would otherwise have. An exception whose `until` date has passed re-enters ranking with `flags.exception_expired = true` on its row, and is listed under `accepted_risks.expired`. Exceptions live in `tenants/<name>/exceptions.yaml` (or `config/exceptions.yaml` outside a tenant), are per tenant, and are managed ONLY through `dva exception add|remove|list|suggest` — never by hand-editing the file.

After `dva report --all`, run `dva exception suggest`: it prints one JSON line per product worth an exception, with `reasons` such as `embedded component` (matches a common bundled library like OpenSSL, zlib, a JRE/JDK...), `bundled across N products` (the same evidenced install spans 3+ unrelated top-level product folders), `no vendor fix` (no Defender recommendation, or it's Uninstall/ConfigurationChange), or `end of support`, plus a `suggested_until` 90 days out; it also writes `exception-suggestions.json`. Report the suggestions to the user and add one only when they explicitly confirm, with `--owner` set to their name (ask if you don't have it).

## Outputs

`cve-*.txt` (raw CVE server results, never read by the agent), `enrichment.json` (merged CVE data), `findings.json` (scored products with a description per driving CVE, accepted risks, long-standing products, trend, posture), and under `--all`: `report.md`, `report.html`, `report.json`, `tickets.json` in the run directory. `dva report --tickets` (included in `--all`) writes `tickets.json`, one ticket per listed product not under exception, with a priority, labels and a Markdown description — no API calls are made, it's a file for you to hand to a ticketing system.

## Long-standing vulnerabilities

`findings.json`'s `long_standing` lists every product not under exception that still carries CVEs first seen more than `long_standing_days` (default 90) ago, whatever its score, with the count over the threshold, the oldest age and a severity split; `summary.long_standing_products` is the count. Both reports render it as a section after accepted risks, and `report --brief` names the first five. A product there with a low score is not urgent but is proof that no patch process covers it; mention them when present.

## Trend and recently patched

`findings.json`'s `trend` (up to the last `trend_runs` runs) and `score_trend` (last 12 months, from the per-tenant SQLite store) back the report's trend table and exposure/secure-score sparkline. Each product row's `patched_7d` counts Critical/High CVEs Defender marked Fixed in the last 7 days (from `dva mde changes`); `findings.json`'s `summary.patched_7d_critical` is the estate-wide total. Mention SLA breaches (`summary.sla_breaches`), end-of-support products (`summary.eos_products`), the patched-in-7-days total and the score trend in your reply whenever they are present.

## Tuning

`config/scoring.yaml` controls scoring: `threat_weights` (cvss/epss/kev/exploit/ransomware), `asset_bonus` and `asset_cap`, `criticality_tags`, `enrich_top_per_product` and `enrich_max_cves` (how many CVEs `enrich --list` selects), `report_threshold`, `top_n`, `cache_ttl_days`, `bands` (critical/high/medium score cutoffs), `sla_days` and `overdue_boost`, `long_standing_days`, `mitigation_configs`, `exception_components`, `trend_runs`, `score_weights` (threat / asset context / reach, so widespread products can be made to climb faster), `severity_floor` (a product with an open critical CVE never scores below it), `embedded_discount` (bundled libraries and runtimes are discounted, flagged `Embedded`, exempt from the floor, and patched through their parent product). Edit this file, then re-run only `dva score` and `dva report --all` — no need to re-collect.

## Gotchas

- Never paste raw CVE server results into a reply and never read the `cve-*.txt` files; `dva enrich --fetch` does the calls and the merge.
- `enrich --fetch` (and `--list`) exclude CVEs already cached within `cache_ttl_days`; `fetched 0 results` means nothing new needed enrichment. Expired entries are re-triaged for fresh EPSS/KEV/PoC signals but keep their description, vector, CWE and advisories, so `lookup_cve`/`get_vendor_advisory` run once per CVE, ever.
- `enrich --fetch` exits 1 with `CVE server could not be started` when `uvx` is missing or the server fails to boot; scoring still works without intel.
- Never `cat` `enrichment.json` or `findings.json`; read `report.md` instead.
- Exceptions are never shared across tenants and are never edited by hand — always go through `dva exception`.
