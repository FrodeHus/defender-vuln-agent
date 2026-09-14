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
Run `claude mcp list` in the repo. If `cve-mcp` is missing, start `claude` from the repository root and accept the server prompt. If it shows an error, run `scripts/cve-mcp.sh` by hand and read its stderr: `'uvx' ... is required` means uv is not installed or not on the PATH Claude Code sees; a download error means the first `uvx` run could not reach GitHub or PyPI (run `scripts/cve-mcp.sh --warm` once with network, after which the server starts from the uv cache). A start that takes longer than Claude Code's MCP timeout on the very first run is fixed the same way.

**CVE server logs `NVD_API_KEY not set`**
Put `NVD_API_KEY=...` in this repo's `.env` (or export it before starting `claude`). For a marketplace install the plugin directory has no `.env`, so export it.

**`enrich --fetch` prints `CVE server could not be started` or `exited before answering initialize`**
The server command failed to boot. Run `scripts/cve-mcp.sh --warm` by hand to see the real error (usually a missing `uvx` or no network for the first download). `DVA_CVE_MCP` or `--server CMD` overrides the command. Per-CVE `warning:` lines mean one lookup failed; those CVEs stay in `enrichment.json`'s `missing` list and scoring falls back to Defender's own signals for them.

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
