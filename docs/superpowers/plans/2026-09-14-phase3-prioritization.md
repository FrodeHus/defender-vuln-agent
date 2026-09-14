# Phase 3 Prioritization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add accepted-risk exceptions with agent suggestions, exploit maturity and ransomware signals, SLA ageing, end-of-support and fix-version rollups with advisory links, identity and mitigation context, cloud attack paths, trend, ticket export and a posture appendix to the existing `dva` pipeline and its reports.

**Architecture:** Every feature is file-based and read-only, follows the existing collector → run files → rollup → score → `findings.json` → renderers flow, and lands as new fields on `findings.json` that both renderers read. Parsers are written against captured CVE-server text fixtures. Exceptions live per tenant and are edited only through the CLI.

**Tech Stack:** Python 3.11+, existing deps only (`msal`, `requests`, `pyyaml`), pytest.

**Spec:** `docs/superpowers/specs/2026-09-14-phase3-prioritization-design.md` (binding). Base design: `docs/superpowers/specs/2026-09-14-defender-vuln-agent-design.md`.

## Global Constraints

- Read-only; no new runtime dependencies; every failure is a one-line `DvaError`; raw records never printed; tenant isolation (`tenants/<name>/` holds everything a tenant produces, including `exceptions.yaml`).
- `findings.json` keys added by this plan (renderers read them verbatim): product `flags.exception_expired`, `sla` (`oldest_days`, `overdue_cves`, `overdue_by_days`), `eos` (`{status, date, versions}` or null), `fixes` (list of `{update, cves, share}`), `advisories` (list of `{source, severity, label, id, date, url}`), `asset why` strings; document `accepted_risks` (`{active: [...], expired: [...]}`), `summary.sla_breaches`, `summary.overdue_cves_total`, `summary.eos_products`, `trend` (list), `diff_from_previous.new_cves` / `fixed_cves` (per severity), `posture` (`{certificates_expiring, config_findings, config_by_impact}`).
- Config defaults exactly as the spec's "Config additions" block; missing keys must fail loudly at startup (existing `Scoring(**data)` behaviour) so add every new key to `config/scoring.yaml` and to the `Scoring` dataclass in the same task.
- Hunting queries end with `| take 10000` or a smaller `take`; source names `hunting.<name>`.
- Golden files: `DVA_UPDATE_GOLDEN=1 pytest tests/test_report_md.py`; review the diff every time.
- Commit per task with conventional messages; run `pytest -q` (currently 112 passing) before each commit.

---

### Task 1: Intel fields, CVE-server parsers, exploit maturity and ransomware in scoring

**Files:**
- Modify: `dva/scoring.py` (`CveIntel` fields, `threat_score`), `dva/enrich.py` (`_parse_triage_block`, `parse_text`, `_merge_intel`), `dva/cache.py` (no change expected; `CveIntel.__dataclass_fields__` drives it), `config/scoring.yaml`, `dva/config.py`
- Test: `tests/test_enrich.py`, `tests/test_scoring.py`, `tests/test_config.py`
- Fixtures already captured: `tests/fixtures/cve/triage-kev.txt`, `kev-yes.txt`, `poc-yes.txt`, `advisory.txt`, `exploit-availability.txt`

**Interfaces:**
- `CveIntel` gains `exploit_maturity: float | None = None`, `advisories: list[dict] = field(default_factory=list)`. `ransomware` exists.
- `Scoring` gains `sla_days: dict[str,int]`, `overdue_boost: float`, `mitigation_configs: list[str]`, `exception_components: list[str]`, `trend_runs: int`; `threat_weights` gains `ransomware`; `asset_bonus` gains `privileged_user`, `attack_path`, `mitigated` (values per spec).
- `threat_score(ref, intel, cfg)`: `exploit = intel.exploit_maturity if intel and intel.exploit_maturity is not None else (1.0 if intel and intel.exploit_public else _EXPLOIT_TERM[ref.exploitability])`; `+ w["ransomware"] * (1 if intel and intel.ransomware else 0)`.
- `parse_text` additions: triage `PoC:` label → maturity (`PUBLIC_EXPLOIT|WEAPONIZED|HIGH` 1.0, `MEDIUM` 0.85, `LOW|POC` 0.7, `NONE` 0.0; `— N public source(s)` with N ≥ 5 → max(current, 0.85)); triage `KEV:` line containing `ransomware: Known` → ransomware; `check_kev` `Ransomware Use: Known` → ransomware, `Date Added: <date>` → `kev_added`; `check_poc_exists` `Confidence: <LABEL>` same mapping; `check_exploit_availability` `Public PoCs found: N` (N>0 → ≥ 0.7); `get_vendor_advisory` blocks: header `=== Vendor Advisories: CVE-x ===`, sections `<Source>  (N entries):`, entries `  [Severity] <label>  <ID>  <date>` → `advisories` (first 5, in file order) with `url` per spec §6. `_merge_intel` merges `exploit_maturity` by max and `advisories` by union on `id`.

- [ ] **Step 1: Failing tests** in `tests/test_enrich.py`:

```python
def test_parse_triage_kev_maturity_and_ransomware():
    i = parse_file(_FX / "triage-kev.txt")["CVE-2021-44228"]
    assert i.kev and i.ransomware and i.exploit_maturity == 1.0 and i.exploit_public and i.kev_added == "2021-12-10"

def test_parse_kev_yes_and_poc_yes_and_exploit_availability():
    out = parse_text("\n".join((_FX / n).read_text() for n in ["kev-yes.txt", "poc-yes.txt", "exploit-availability.txt"]))["CVE-2021-44228"]
    assert out.kev and out.ransomware and out.kev_added == "2021-12-10" and out.exploit_maturity == 1.0

def test_parse_advisories():
    adv = parse_file(_FX / "advisory.txt")["CVE-2021-44228"].advisories
    assert adv[0]["source"] == "Microsoft MSRC" and adv[0]["url"] == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-44228"
    rh = [a for a in adv if a["source"] == "Red Hat Security"][0]
    assert rh["id"].startswith("RHSA-2021:") and rh["url"] == f"https://access.redhat.com/errata/{rh['id']}" and rh["severity"] == "Critical" and rh["date"] == "2021-12-14"
    assert len(adv) <= 5
```
and in `tests/test_scoring.py`:
```python
def test_threat_uses_maturity_and_ransomware():
    i = CveIntel(cvss=10.0, epss_percentile=1.0, kev=True, ransomware=True, exploit_public=True, exploit_maturity=0.85)
    assert abs(threat_score(ref(cvss=10.0), i, cfg) - (0.35 + 0.25 + 0.25 + 0.15 * 0.85 + 0.10)) < 1e-9
```
and `tests/test_config.py` asserting the new keys and defaults.

- [ ] **Step 2: Run, see them fail.** `pytest tests/test_enrich.py tests/test_scoring.py tests/test_config.py -q`
- [ ] **Step 3: Implement** the fields, config, parsers and scoring change. Keep regexes anchored (`re.M`) and case-insensitive where labels vary.
- [ ] **Step 4: Full suite green; commit** `feat: exploit maturity, ransomware and vendor advisories from CVE-server text`.

---

### Task 2: Exceptions (accepted risk)

**Files:**
- Create: `dva/exceptions.py`, `config/exceptions.example.yaml`, `tests/test_exceptions.py`
- Modify: `dva/__main__.py` (`COMMAND_MODULES` add `dva.exceptions`), `dva/score_cmd.py`, `dva/report_md.py`, `dva/report_template.html`, `.gitignore` (`config/exceptions.yaml`)

**Interfaces:**
```python
@dataclass class Exception_: product: str | None; cve: str | None; reason: str; until: str; owner: str | None; added: str; source: str
def path_for_current() -> Path            # tenants/<name>/exceptions.yaml when DVA_TENANT_DIR set, else config/exceptions.yaml
def load(path: Path) -> list[Exception_]  # missing file → []; malformed → DvaError
def save(path: Path, items: list[Exception_]) -> None   # atomic write, mode 600
def split(items, today: date) -> tuple[list, list]      # (active, expired); until < today is expired
def apply(products: dict[str, Product], items_active) -> tuple[dict[str, Product], dict[str, Exception_]]
    # removes excepted CVEs from products, drops products with a product exception; returns remaining products and {key: exception} for dropped
```
CLI: `dva exception list` (table: kind, key, until, owner, status), `add`, `remove` (per spec §1), `suggest` is Task 7. `score_cmd.compute(...)`: after `build`, load exceptions, `apply`, score remaining; `accepted_risks = {"active": [{key, product, vendor, reason, until, owner, would_be_score}], "expired": [{key, product, reason, until, owner}]}`; expired product exceptions do not remove anything and set `flags.exception_expired` on the row. Renderers: Markdown `## Accepted risks` (active table, then expired list) before `## Method`; HTML appendix section "Accepted risks" and a pill `Exception expired` on rows.

- [ ] **Step 1: Failing tests** (`tests/test_exceptions.py`): load/save round trip with mode 600; `split` on dates; `apply` drops a product and removes a CVE from another; `compute` on the `seed()` run with an active product exception for `ivanti/connect-secure` → not in `products`, present in `accepted_risks.active` with `would_be_score` ≥ 40; expired one → row has `flags.exception_expired` and appears in `accepted_risks.expired`; CLI `add` then `list` via `main([...])` with `DVA_TENANTS_DIR` set and a tenant selected writes `tenants/<n>/exceptions.yaml`; `add` with neither `--product` nor `--cve` → exit 1; Markdown golden updated with an `## Accepted risks` section (add one active and one expired entry to `tests/fixtures/sample-run/findings.json` under `accepted_risks`).
- [ ] **Step 2: Run, fail.** **Step 3: Implement.** **Step 4: Suite green, regenerate golden, commit** `feat: accepted-risk exceptions per tenant`.

---

### Task 3: SLA age, end of support, fix-version rollups

**Files:**
- Modify: `dva/queries/product-versions.kql` (add `EndOfSupportDate = max(EndOfSupportDate)` to the summarize), `dva/model.py` (`Product.eos: dict | None`, `Product.fixes: dict[str, set[str]]`), `dva/rollup.py`, `dva/scoring.py` (`overdue_boost` in `product_score` given `overdue` flag), `dva/score_cmd.py`, `dva/report_md.py`, `dva/report_template.html`
- Test: `tests/test_rollup.py`, `tests/test_score_cmd.py`, `tests/test_scoring.py`

**Interfaces:**
- Rollup: reads `hunt-product-versions.json` if present; for each row with `EndOfSupportStatus` not in (`""`, `None`, `"None"`, `"NotApplicable"`) marks the product `eos = {"status": ..., "date": EndOfSupportDate or None, "versions": [...]}`. From each vuln row with `security_update`, `fixes[security_update].add(cve_id)`.
- `product_score(p, assets, intel, cfg, estate_size, overdue: bool = False)`: multiply `raw` by `cfg.overdue_boost` when `overdue`.
- `score_cmd`: `age_days(first_seen, now)`; per product `sla = {"oldest_days": int|None, "overdue_cves": int, "overdue_by_days": int}` using `cfg.sla_days[severity.lower()]`; `overdue = sla["overdue_cves"] > 0` passed to `product_score`; row `fixes = [{"update": u, "cves": len(ids), "share": round(len(ids)/total, 2)}]` sorted by cves desc, top 5; row `eos`; summary `sla_breaches`, `overdue_cves_total`, `eos_products`.
- Renderers: pills `Overdue by N days` and `End of support`; "Upgrading to X fixes N of M CVEs" line under Remediation when `fixes` non-empty; tiles for SLA breaches and EOS in the HTML header (keep four tiles: fold SLA into "Emergency" tile line and EOS into "Products needing action" line rather than adding tiles).

- [ ] **Step 1: Failing tests**: rollup marks EOS from a `hunt-product-versions.json` fixture with two versions, one EOS; `fixes` groups two CVEs under one update; `product_score(..., overdue=True)` scores higher than without; `compute` with `first_seen` 60 days ago on a High CVE → `sla.overdue_cves == 1`, `overdue_by_days == 30`, `summary.sla_breaches == 1`; row `fixes[0]["update"]` and `share`; Markdown golden shows the pills and fixes line (extend the sample fixture: give rank 1 `sla`, `eos: null`, `fixes`; give rank 4 `eos`).
- [ ] **Step 2–4**: implement, suite green, regenerate golden, commit `feat: SLA ageing, end-of-support flags and fix-version rollups`.

---

### Task 4: Identity, mitigations and posture hunting queries

**Files:**
- Create: `dva/queries/privileged-logons.kql`, `dva/queries/mitigations.kql` (template with `__CONFIG_IDS__` placeholder rendered by `hunting.py`), `dva/queries/mitigation-catalog.kql`, `dva/queries/certificates.kql`, `dva/queries/config-findings.kql` (KQL exactly as spec §5 and §9)
- Modify: `dva/hunting.py` (`mitigations` renders the id list from `cfg.mitigation_configs`; empty list → write an empty result, source `ok`, summary "skipped: no mitigation_configs configured"), `dva/model.py` (`Asset.privileged_user: bool`, `Asset.mitigations: int`), `dva/rollup.py`, `dva/scoring.py` (`asset_signals`: "Privileged user signs in" +`privileged_user`; "Mitigated: n controls" + `mitigated` when `Compliant == Total`), `dva/score_cmd.py` (`posture` block), both renderers ("Posture" appendix), `config/sources.yaml` (`hunting_queries` list extended)
- Test: `tests/test_hunting.py`, `tests/test_rollup.py`, `tests/test_scoring.py`, `tests/test_score_cmd.py`, `tests/test_report_md.py`

**Interfaces:** rollup reads `hunt-privileged-logons.json` (`DeviceId`, `Roles`, `Users`) → `asset.privileged_user = True`; `hunt-mitigations.json` (`DeviceId`, `Compliant`, `Total`) → `asset.mitigations = Compliant if Compliant == Total else 0`. `posture = {"certificates_expiring": [{thumbprint, name, issued_to, expires, devices}], "config_findings": [{id, category, subcategory, impact, devices}], "config_by_impact": {"high": n, "medium": n, "low": n}}` from `hunt-certificates.json` and `hunt-config-findings.json` (absent files → empty lists).

- [ ] **Step 1: Failing tests**: `load_query` for the four new names; `run_named` with `mitigations` and empty config skips with `ok`; with configured ids the posted Query contains them; rollup sets `privileged_user` and `mitigations`; `asset_multiplier` reflects +0.4 and −0.2; `compute` produces `posture` from fixtures; golden extended with a Posture appendix (sample fixture gets a small `posture` block).
- [ ] **Step 2–4**: implement, suite green, regenerate golden, commit `feat: identity, mitigation and posture context from Advanced Hunting`.

---

### Task 5: Cloud attack paths

**Files:**
- Modify: `dva/cloud.py` (`collect_attack_paths(client, run, subscriptions)`, CLI `dva cloud attack-paths`), `dva/rollup.py` (asset `attack_paths: list[str]` matched by resource-id substring over `entities`, case-insensitive), `dva/scoring.py` (`asset_signals`: "On attack path: <name>" + `attack_path`), `dva/model.py`, `.claude/skills/defender-cloud/SKILL.md`
- Test: `tests/test_cloud.py`

**Interfaces:** query `securityresources | where type == "microsoft.security/attackpaths" | project id, subscriptionId, displayName = tostring(properties.displayName), riskCategories = properties.riskCategories, entities = tostring(properties.graphComponent.entities)`; output `cloud-attackpaths.json` (list of rows). Same paging as `collect_vulns`.

- [ ] **Step 1: Failing tests**: paging/posting with a FakeSession; rollup marks an asset whose `azure_resource_id` appears (any case) inside `entities`; multiplier gains 0.6; `why` contains the path name.
- [ ] **Step 2–4**: implement, suite green, commit `feat: Defender for Cloud attack paths as asset context`.

---

### Task 6: Trend, new/fixed diff, ticket export

**Files:**
- Create: `dva/report_tickets.py`, `tests/test_trend_tickets.py`
- Modify: `dva/score_cmd.py` (`trend`, `diff_from_previous.new_cves/fixed_cves`), `dva/report_cmd.py` (`--tickets`, included in `--all`), `dva/report_md.py` (trend table before the top 10), `dva/report_template.html` (trend table + inline SVG sparkline; no external assets)

**Interfaces:** `previous_runs(run, n) -> list[Run]` (same runs dir, ids < current, having `findings.json`, newest n, corrupt ones skipped with a log line); `trend` rows per spec §7 with `cves_by_severity` from listed products' `all_cves` counted by severity via `driving_cves`/counts (use `counts` summed over listed products); `new_cves`/`fixed_cves` per severity from `(key, cve)` sets of listed products between the previous and current documents, severity taken from the current doc's product `counts` is not per CVE, so compute from the product's `all_cves` plus the rollup's `CveRef.severity` for current CVEs and the previous doc's `driving_cves`/`all_cves` (severity unknown for previous-only CVEs → count under `"unknown"`). `report_tickets.render(doc) -> str` producing the JSON per spec §8.

- [ ] **Step 1: Failing tests**: two seeded runs → trend has two rows oldest first, `new_cves`/`fixed_cves` reflect an added and a removed CVE; `render` tickets: one per listed non-excepted product, priority mapping, labels, description contains the risk summary; `dva report --all` writes `tickets.json`; golden shows the trend table.
- [ ] **Step 2–4**: implement, suite green, regenerate golden, commit `feat: trend across runs, new/fixed CVE diff and ticket export`.

---

### Task 7: Exception suggestions, agent workflow, docs, e2e

**Files:**
- Modify: `dva/exceptions.py` (`suggest(run, cfg) -> list[dict]`, CLI `suggest`), `.claude/agents/vuln-assessor.md`, `.claude/skills/vuln-prioritize-report/SKILL.md`, `.claude/skills/defender-hunting/SKILL.md`, `docs/usage.md`, `docs/configuration.md`, `docs/architecture.md`, `README.md`, `CHANGELOG.md`, `tests/test_e2e.py`, `tests/test_exceptions.py`, `tests/test_agent_files.py`

**Interfaces:** `suggest` per spec §1 (component list, bundled-across-products from evidence paths, no vendor fix, EOS); writes `exception-suggestions.json`; prints JSON lines and a summary; skips excepted products. Agent: hunts list extended, advisory calls, `dva report --all`, then `dva exception suggest`, suggestions reported, `dva exception add` only on user confirmation with `--owner` set to the user, and exception management on request via the CLI only. `test_agent_files.py` asserts `exception suggest`, `exception add`, `get_vendor_advisory`, `privileged-logons`, `certificates` appear.

- [ ] **Step 1: Failing tests**: `suggest` on a run containing an `openssl/openssl` product with evidence under three parent folders → reasons include "embedded component" and "bundled across 3 products"; an EOS product → "end of support"; excepted products skipped; e2e extended: add an exception via CLI before `score`, assert it is absent from products and present in `accepted_risks`, run `report --all` and assert `tickets.json` exists, run `exception suggest` and assert exit 0.
- [ ] **Step 2–4**: implement, docs, suite green, commit `feat: exception suggestions, agent workflow and docs for phase 3`.

## Self-review

Spec §1 → Tasks 2 and 7; §2 → Task 1; §3 → Task 3; §4 → Task 5; §5 → Task 4; §6 → Tasks 1 (advisory parse) and 3; §7 and §8 → Task 6; §9 → Task 4; config additions → Task 1 (all keys added at once so later tasks find them); agent and docs → Task 7. Interfaces named consistently: `Product.eos`, `Product.fixes`, `Asset.privileged_user`, `Asset.mitigations`, `Asset.attack_paths`, `CveIntel.exploit_maturity`, `CveIntel.advisories`, `accepted_risks`, `trend`, `posture`.
