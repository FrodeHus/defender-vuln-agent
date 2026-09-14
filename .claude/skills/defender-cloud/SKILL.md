---
name: defender-cloud
description: Collect vulnerability findings and attack paths for VMs, container registries and container images from Defender for Cloud (Azure Resource Graph subassessments and attack paths) into a run directory, de-duplicated against Defender for Endpoint.
---

## When to use

After `dva run new` and `dva mde all` (or with `--run` pointed at an existing run that already has `machines.json`), when `config/sources.yaml` has `cloud: true`, to add Defender for Cloud's server and container image findings, and attack path context, alongside the MDE inventory.

## Commands

```
python3 -m dva cloud vulns [--run RUN] [--subscriptions SUB [SUB ...]] [--fixture FILE]
python3 -m dva cloud attack-paths [--run RUN] [--subscriptions SUB [SUB ...]] [--fixture FILE]
```

`--subscriptions` defaults to `config/sources.yaml`'s `subscriptions` list. `--run` defaults to `$DVA_RUN` or the latest run under `runs/`. `--fixture` replaces the live Resource Graph call with a canned JSON response file, for offline runs and tests.

## Outputs

Written under the run directory: `cloud-vulns.jsonl`, one row per resource/CVE pair with `resource_id, resource_type, subscription, resource_group, cve_id, severity, cvss, patchable, image_repo, image_digest, display_name, assessment_key, duplicate_of`. `cloud-attackpaths.json`, a JSON list of rows with `id, subscription, display_name, risk_categories, entities`. A one-line summary is printed to stdout for each — read that, not the raw files.

`dva score` (via `rollup.build`) reads `cloud-vulns.jsonl` after the MDE rows and de-duplicates: a cloud row whose `resource_id` matches an MDE machine's `azure_resource_id` (case-insensitive) is always dropped as a duplicate. For a server row only (not a container image row), if no `azure_resource_id` matched, its resource name is also checked against the hostname label of MDE machines that have *no* `azure_resource_id` recorded — a match there is dropped too. Remaining server rows become `device` assets; container image rows become `image` assets and a product keyed by `<registry host>/<repository path>`. Cloud CVEs found in the `exploited-cves` hunting result get the same `ExploitIsPublic` upgrade as MDE rows.

`dva score` also reads `cloud-attackpaths.json` when present. An asset is considered "on an attack path" when its Azure resource id (case-insensitive) occurs as a substring of that path's `entities` text — matching is deliberately loose since the entity payload's field names aren't documented. An asset can be on several paths; `Asset.attack_paths` holds the matched paths' display names in the order encountered. Scoring applies the `attack_path` asset bonus (0.6 by default, see `config/scoring.yaml`) once per asset regardless of how many paths it is on, with `why` text "On attack path: <first name>" plus "(+N more)" when there is more than one.

## Gotchas

- The vulnerability Resource Graph query returns findings for VMs, container registries and container images together; only rows starting with `CVE-` are kept.
- Paging follows the response's `$skipToken` in `options.$skipToken` on the next request; it stops as soon as a response has no `$skipToken`. Both `cloud vulns` and `cloud attack-paths` page the same way against the same Resource Graph endpoint, just with different queries.
- `cloud: false` by default in `config/sources.yaml`; set it to `true` and populate `subscriptions` before either collector is useful. `dva doctor` only checks ARM permissions for subscriptions listed there when `cloud: true`.
- `--fixture` is a single canned Resource Graph response page (see `tests/fixtures/cloud/subassessments.json`), not a whole run.
- Never `cat` `cloud-vulns.jsonl` directly — use the printed summary or downstream `report.md`.
- The hostname-label dedup fallback is intentionally narrow: it never applies to image rows, and it never overrides a resource-id match — an MDE machine that already has an `azure_resource_id` is only ever matched by that id, even if a same-named but unrelated cloud VM exists.
- Surviving (non-duplicate) server rows are cloud-only VM findings with no vendor/product info, so they are grouped into a product keyed by finding name (`display_name`, falling back to the CVE id) rather than by installed software — expect one product per distinct finding name, not per package.
- Attack paths need Defender CSPM (Cloud Security Posture Management) enabled on the subscription — the plan-only "foundational" tier of Defender for Cloud does not compute them. Even with CSPM on, paths only appear once Defender for Cloud has finished a scan and computed them for the environment; a freshly onboarded subscription can return zero rows for a while. `microsoft.security/attackpaths` resources are Cloud-only and have no MDE equivalent, so there is no dedup step for them — every returned path is matched against every asset with a known `azure_resource_id`.
