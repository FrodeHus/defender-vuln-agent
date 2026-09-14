---
name: defender-auth
description: Configure and verify credentials for Microsoft Defender for Endpoint and Graph, and interpret dva doctor output.
---

## When to use

Before the first `dva` run in a new environment, when `dva doctor` reports a failure, or when deciding which permission a feature needs.

## Commands

```
python3 -m dva doctor
```
Checks the configured credential and every required permission, printing one line per check in the format `<API> <permission> ok|FAIL <detail>`, e.g.:
- Success: `MDE   Machine.Read.All                  ok   GET /machines`
- Failure: `MDE   Machine.Read.All                  FAIL GET https://api.securitycenter.microsoft.com/api/machines failed with HTTP 403: Insufficient privileges to complete the operation.`

## Environment variables

Credential (pick one set):
- `DVA_TENANT_ID`, `DVA_CLIENT_ID`, `DVA_CLIENT_SECRET` (client secret auth), or
- `DVA_TENANT_ID`, `DVA_CLIENT_ID`, `DVA_CLIENT_CERT_PATH`, `DVA_CLIENT_CERT_THUMBPRINT` (client certificate auth)

Optional: `DVA_RUNS_DIR` (default `runs/`), `DVA_CACHE_DIR` (default `.cache/`), `DVA_RUN` (pins the active run directory for `--run`-accepting commands).

## Outputs

`dva doctor` prints to stdout only; it writes no files. Tokens are cached under `DVA_CACHE_DIR` until their own expiry (not the `cache_ttl_days` setting in `config/scoring.yaml`, which governs CVE intel freshness only).

## What each permission unlocks

- `Machine.Read.All` — device inventory, tags, exposure level, device value.
- `Vulnerability.Read.All` — per-machine software vulnerabilities.
- `Software.Read.All` — software inventory and version distribution.
- `SecurityRecommendation.Read.All` — remediation text per product.
- `Score.Read.All` — organization exposure score.
- `ThreatHunting.Read.All` (Microsoft Graph) — Advanced Hunting queries via `dva hunt`.
- Azure RBAC Reader (phase 2) — Resource Graph reads for Defender for Cloud.

Full detail, including the doctor check text for each permission and how to grant admin consent: see `setup/permissions.md`.

## Gotchas

- `dva doctor` failing on one permission does not mean every command fails — only the feature that permission backs (e.g. missing `ThreatHunting.Read.All` only breaks `dva hunt`).
- The app registration is read-only by design; there is no write scope to lose. Never add write permissions to satisfy a doctor failure.
- Client secret and client certificate variables are mutually exclusive; do not set both.
