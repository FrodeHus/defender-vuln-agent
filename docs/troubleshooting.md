# Troubleshooting

**`dva: missing environment: DVA_TENANT_ID, ...`**
No credentials found. Single tenant: fill in `.env` in the repo root or export the variables. Multi tenant: pass `--tenant NAME` (or set `DVA_TENANT`) and check `tenants/NAME/.env`; a lone tenant is selected automatically. `dva doctor` prints on its first line which `.env` it used.

**`dva: unknown tenant 'x'; known tenants: ...`**
The name matches no directory under `tenants/`. `dva tenant list` shows the names; `dva tenant init x` creates one.

**`doctor` prints `FAIL ... HTTP 401`**
The token was rejected: wrong `DVA_CLIENT_SECRET`, expired secret, or wrong `DVA_TENANT_ID`. Reset the secret with `az ad app credential reset --id <app-id>`.

**`doctor` prints `FAIL ... HTTP 403`**
The permission exists on the app but admin consent was not granted, or the permission is missing. Run `az ad app permission admin-consent --id <app-id>` as a Global or Privileged Role Administrator, wait a few minutes, retry. `setup/permissions.md` maps each check to its permission.

**`doctor` prints `FAIL` for `Reader (<subscription>)`**
Assign the role: `az role assignment create --assignee <app-id> --role Reader --scope /subscriptions/<id>`. Only needed when `cloud: true`.

**Claude Code shows no `cve-mcp` tools / the agent says the CVE server is unreachable**
Run `claude mcp list` in the repo. If `cve-mcp` is missing, start `claude` from the repository root and accept the server prompt. If it shows an error, run `.venv/bin/python3 -m cve_mcp.server` by hand: `No module named cve_mcp` means the server is not installed in the venv (`pip install -e ../cve-mcp-server`).

**CVE server logs `NVD_API_KEY not set`**
The key must be in `../cve-mcp-server/.env`. An empty `NVD_API_KEY=` line there blocks any value from elsewhere.

**`enrich --store` prints `stored 0` or `no CVE data recognized`**
The saved file is not in a format the parser knows. It expects the text output of `triage_cve` (or `compare_cves`, `get_epss_score`, `lookup_cve`, `check_kev`, `check_poc_exists`). If the server changed its format, compare with `tests/fixtures/cve/triage-standard.txt` and open an issue with a sample.

**`Hunting <name>: 10000 rows (CAPPED ...)`**
The query returned more rows than the cap; the source is marked partial. Narrow it with a `where` clause or `summarize`. The shipped named queries are scoped to stay well under the cap.

**`0 of N products need action` but the estate has vulnerabilities**
Without enrichment (EPSS, KEV), scores are lower by design. Check that the enrich step ran (`stored N` with N > 0). If the estate has no internet-facing or tagged devices, consider lowering `report_threshold` in `config/scoring.yaml` (or a tenant override) and re-running `dva score` and `dva report --all`. The top 10 products are listed regardless.

**`dva: missing vulns.jsonl in run ...`**
`dva mde vulns` did not complete. Check `log.txt` in the run directory; the bulk export endpoint is rate-limited to 30 calls a minute and large estates take a few minutes.

**Two runs created within the same second**
Run ids get a `-001` suffix; `dva run latest` still returns the newest.

**Reports show `unknown` as the tenant**
Set `DVA_TENANT_NAME` in the tenant's `.env` (multi tenant defaults to the directory name).
