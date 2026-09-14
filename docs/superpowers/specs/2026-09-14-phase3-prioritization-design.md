# Phase 3: prioritization, remediation, tracking and coverage — design

Date: 2026-09-14. Extends `2026-09-14-defender-vuln-agent-design.md`; everything there still holds
(read-only, file-based runs, per-tenant isolation, one-line `DvaError` failures, raw data never in
the model's context).

## 1. Exceptions (accepted risk)

- File: `tenants/<name>/exceptions.yaml` when a tenant is active, else `config/exceptions.yaml`
  (gitignored in both places; `config/exceptions.example.yaml` is committed). Shape:
  ```yaml
  exceptions:
    - product: openssl/openssl        # product key, or
      cve: CVE-2023-0286              # a CVE id (one of the two)
      reason: Bundled OpenSSL in vendor appliances; vendor patches on their cadence
      until: 2026-12-31               # ISO date; required
      owner: frode
      added: 2026-09-14T10:00:00+00:00
      source: user                    # user | suggested
  ```
- `dva/exceptions.py`: `load(path) -> list[Exception]`, `save(path, items)`, `active(items, today) -> (active, expired)`, `path_for_tenant()`. Matching: product exceptions match `Product.key` exactly; CVE exceptions remove that CVE from every product before scoring (a product whose remaining CVEs still score is still listed).
- Scoring (`score_cmd.compute`): products under an active product exception are excluded from `products`, the top list and `products_action`, and listed under `accepted_risks` with reason, until, owner, and their would-be score. Expired exceptions re-enter ranking; the product row carries `flags.exception_expired = true` and the appendix lists them under "expired".
- CLI: `dva exception list|add|remove|suggest`. `add --product KEY | --cve ID --reason TEXT --until DATE [--owner NAME]` (validates the key exists in the latest run when a run exists, warns otherwise); `remove --product KEY | --cve ID`.
- Suggestions (`dva exception suggest`): for each product the report would list, score reasons:
  - **embedded component**: vendor/name matches `exception_components` in scoring config (default list: openssl, zlib, libcurl/curl, libxml2, libxslt, sqlite, log4j, jre/jdk/java runtime, python runtime, node.js runtime, .net runtime, vc redistributable, msxml, expat, libpng, openssh client library) — case-insensitive substring on `name`;
  - **bundled across products**: evidence paths (from `hunt-evidence.json`) under 3 or more distinct top-level product folders (the segment after `%ProgramFiles%\`, `%ProgramFiles(x86)%\`, `%LOCALAPPDATA%\`, `/opt/`, `/usr/lib/`);
  - **no vendor fix**: no Defender recommendation for the product, or `remediation_type` is `Uninstall`/`ConfigurationChange`;
  - **end of support**: product flagged EOS (section 6).
  Output: JSON lines `{"product": key, "name": ..., "reasons": [...], "suggested_until": <today + 90 days>}` plus a one-line summary; writes `exception-suggestions.json` in the run. Products already excepted are skipped.
- Agent: after `dva report`, runs `dva exception suggest`, includes the suggestions in its reply, and adds one only when the user confirms (via `dva exception add ... --owner <user>`); manages the list on request through the CLI only, never by editing the file. Exceptions are per tenant, never shared.

## 2. Exploit maturity and ransomware

- `CveIntel` gains `exploit_maturity: float | None` and keeps `ransomware`. Parsed from the CVE server text:
  - triage `PoC:` line label: `PUBLIC_EXPLOIT`/`WEAPONIZED`/`HIGH` → 1.0; `MEDIUM` → 0.85; `LOW`/`POC` → 0.7; `NONE` → 0; plus "— N public source(s)" with N ≥ 5 raises to at least 0.85;
  - triage `KEV:` line `ransomware: Known` and `check_kev` `Ransomware Use: Known` → `ransomware = True`;
  - `check_poc_exists` `Confidence:` label maps the same way; `check_exploit_availability` "Public PoCs found: N" → N>0 gives at least 0.7.
- Threat score: `exploit_term = intel.exploit_maturity if set else Defender's level`; add `w.ransomware * [ransomware]` with default weight 0.10 (weights now sum to 1.10 before the `min(1, …)` cap on the product score).

## 3. SLA age

- `scoring.yaml`: `sla_days: {critical: 14, high: 30, medium: 90, low: 180}`, `overdue_boost: 1.10`.
- Rollup keeps the earliest `first_seen` per CVE (already). `score_cmd` computes per product: `oldest_days` (max age over its CVEs), `overdue_cves` (count whose age exceeds the SLA for their severity), `overdue_by_days` (max excess). Product score is multiplied by `overdue_boost` when `overdue_cves > 0` (before the cap). Summary gains `sla_breaches` (products with any overdue CVE) and `overdue_cves_total`. Reports show an "Overdue by N days" pill and a tile.

## 4. Attack paths (cloud tenants)

- `dva cloud attack-paths`: Resource Graph `securityresources | where type == "microsoft.security/attackpaths"` projecting `id, subscriptionId, displayName = tostring(properties.displayName), riskCategories = properties.riskCategories, entities = tostring(properties.graphComponent.entities)`; written to `cloud-attackpaths.json`. Asset match: an asset is "on an attack path" when its Azure resource id (case-insensitive) occurs in that path's `entities` text. This avoids depending on undocumented entity field names.
- Asset bonus `attack_path: 0.6`; asset `why` includes "On attack path: <displayName>". Runs only when `cloud: true`.

## 5. Identity context and compensating controls

- Hunting `privileged-logons`: `DeviceInfo | where Timestamp > ago(7d) | mv-expand LoggedOnUsers | extend AccountName = tostring(LoggedOnUsers.UserName), AccountDomain = tostring(LoggedOnUsers.DomainName) | join kind=inner (IdentityInfo | where array_length(AssignedRoles) > 0 or CriticalityLevel <= 1 | distinct AccountName, AccountDomain, AssignedRoles, CriticalityLevel) on AccountName, AccountDomain | summarize Roles = make_set(AssignedRoles, 10), Users = dcount(AccountName) by DeviceId, DeviceName | take 10000`. Asset bonus `privileged_user: 0.4`; why: "Privileged user signs in".
  `CriticalityLevel` semantics in Defender: lower is more critical (0 = very high); the filter is documented in the query file and `IdentityInfo` requires Defender for Identity or MDE P2. A failed query is tolerated.
- Hunting `mitigations`: `DeviceTvmSecureConfigurationAssessment | where ConfigurationId in~ (<mitigation_configs>) and IsApplicable == true | summarize Compliant = countif(IsCompliant == true), Total = count() by DeviceId, DeviceName | where Compliant > 0`. `scoring.yaml: mitigation_configs: []` by default and `mitigated: -0.2` bonus applied when `Compliant == Total`. Helper query `mitigation-catalog`: `DeviceTvmSecureConfigurationAssessmentKB | where ConfigurationCategory in~ ("Security controls", "Application") | project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact | order by ConfigurationImpact desc | take 200` so the user can pick ids for their tenant. With an empty list the `mitigations` query is skipped with a note.
- Asset `why` shows "Mitigated: <n> controls".

## 6. End of support, fix-version rollups, advisories

- `product-versions` already returns `EndOfSupportStatus` and now also `EndOfSupportDate`. Rollup marks `Product.eos = True` when any of its versions has a status other than empty/"None"/"NotApplicable" and records `eos_versions` and `eos_date`. Reports: "End of support" pill, summary count `eos_products`, and under the product the high-value/critical devices running it. Exception suggestion reason "end of support" (section 1).
- Fix-version rollups: from `vulns.jsonl` `security_update` per row, `Product.fixes = {update_label: set(cve ids)}`; `findings.json` product gets `fixes: [{update, cves, share}]` sorted by cves desc; the report line "Upgrading to <update> fixes N of M CVEs" for the top entry when it exists.
- Advisories: the agent calls `get_vendor_advisory(cve_id)` for the describe ids and saves `cve-advisory-<id>.txt`; parser reads the section headers (`<Source>  (N entries):`) and entry lines `[Severity] <label>  <ID>  <date>` into `CveIntel.advisories: [{source, severity, label, id, date}]` (first 5 per CVE). Product row gets `advisories` from its driving CVE; reports list them (link to the advisory id when the source is Red Hat: `https://access.redhat.com/errata/<ID>`, MSRC: `https://msrc.microsoft.com/update-guide/vulnerability/<CVE>`, Ubuntu: `https://ubuntu.com/security/<CVE>`; other sources plain text).

## 7. Trend

- `score_cmd` reads up to the last 8 previous runs' `findings.json` (same tenant runs dir) and writes `trend: [{run_id, generated_at, exposure_score, products_action, kev_cves, sla_breaches, cves_by_severity}]` oldest first, ending with the current run. `cves_by_severity` = counts over all listed products' `all_cves`. `diff_from_previous` gains `new_cves` and `fixed_cves` per severity computed from (product, cve) sets of the current vs previous listed products.
- Reports: Markdown trend table; HTML: the same table plus an inline SVG sparkline of `exposure_score` and `products_action` (no external assets).

## 8. Ticket export

- `dva report --tickets` writes `tickets.json`: `[{key, title, priority, labels, description, product, tenant, run_id}]`, one per listed product not under exception. `title` = "Patch <product> (<vendor>): <label>, <n> devices"; `priority` maps label Critical→1, High→2, Medium→3, Low→4; `labels` = ["vuln", label lower, "kev" if kev, "internet-facing" if so]; `description` is Markdown with the risk summary, remediation, top fix, driving CVEs, top assets, paths. Also included in `--all`. No API calls.

## 9. Posture appendix

- Hunting `certificates`: `DeviceTvmCertificateInfo | extend Exp = todatetime(ExpirationDate) | where Exp between (now() .. now() + 30d) | summarize Devices = dcount(DeviceId), Sample = any(Path) by Thumbprint, FriendlyName, tostring(IssuedTo), Exp | order by Exp asc | take 200`.
- Hunting `config-findings`: `DeviceTvmSecureConfigurationAssessment | where IsApplicable == true and IsCompliant == false | summarize Devices = dcount(DeviceId) by ConfigurationId, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact | order by ConfigurationImpact desc, Devices desc | take 200`.
- `findings.json` gains `posture: {certificates_expiring: [...], config_findings: [...], config_by_impact: {high: n, medium: n, low: n}}` (impact ≥ 7 high, ≥ 4 medium). Both reports get a "Posture" appendix; nothing is scored.

## Config additions (`scoring.yaml`)

```yaml
threat_weights: { cvss: 0.35, epss: 0.25, kev: 0.25, exploit: 0.15, ransomware: 0.10 }
asset_bonus: { ..., privileged_user: 0.4, attack_path: 0.6, mitigated: -0.2 }
sla_days: { critical: 14, high: 30, medium: 90, low: 180 }
overdue_boost: 1.10
mitigation_configs: []
exception_components: [openssl, zlib, curl, libxml2, libxslt, sqlite, log4j, jre, jdk, java, python, node, ".net runtime", redistributable, msxml, expat, libpng]
trend_runs: 8
```

`sources.yaml` `hunting_queries` gains `evidence`, `privileged-logons`, `mitigations`, `certificates`, `config-findings`.

## Agent workflow changes

Step 3 hunts: `internet-facing exploited-cves device-tags product-versions evidence privileged-logons mitigations certificates config-findings`; cloud tenants also `dva cloud attack-paths`. Step 4: also `get_vendor_advisory` for describe ids saved to `cve-advisory-<id>.txt`. Step 6: `dva report --all` (includes tickets). New step 7: `dva exception suggest`, report suggestions, act only on confirmation. New rule: exceptions are managed only through `dva exception` commands.

## Testing

Unit tests with fixtures for every parser and query builder; captured CVE-server texts for KEV/PoC/advisory (`tests/fixtures/cve/triage-kev.txt`, `kev-yes.txt`, `poc-yes.txt`, `advisory.txt`, `exploit-availability.txt`); score tests for exceptions, SLA, EOS, fixes, trend, tickets; the sample fixture and golden extended; e2e extended with an exception and a trend of two runs.
