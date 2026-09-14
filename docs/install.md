# Installation

## Requirements

- Python 3.11 or newer, `git`, and `bash`.
- [Claude Code](https://docs.claude.com/en/docs/claude-code) if you want the agent (the CLI works without it).
- The [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) to create the app registration with the provided script (you can also create it by hand).
- A Microsoft Entra tenant with Defender for Endpoint, and an account that can grant admin consent for application permissions.
- A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (optional but strongly recommended: without it CVE lookups are limited to 5 requests per 30 seconds).

## 1. Install

```bash
git clone https://github.com/frodehus/defender-vuln-agent
cd defender-vuln-agent
scripts/install.sh
```

The script creates `.venv`, installs this package, clones and installs the [`cve-mcp-server`](https://github.com/mukul975/cve-mcp-server) next to the repo (into the same venv, which is how `.mcp.json` starts it), copies `.env.example` to `.env`, and runs the test suite. Pass `--cve-server-dir DIR` if you already have a clone elsewhere.

Manual equivalent:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
git clone https://github.com/mukul975/cve-mcp-server ../cve-mcp-server
pip install -e ../cve-mcp-server
```

## 2. NVD API key

Put the key in the CVE server's own env file, not this repo's:

```
# ../cve-mcp-server/.env
NVD_API_KEY=your-key
```

The server loads the `.env` next to its own source first, and an empty `NVD_API_KEY=` line there blocks any other value. Optional: `GITHUB_TOKEN` for PoC searches on GitHub.

## 3. App registration and credentials

Each tenant needs one Entra app registration with these **application** permissions:

| API | Permission | Used for |
|---|---|---|
| WindowsDefenderATP | `Machine.Read.All` | device inventory, tags, exposure level, device value |
| WindowsDefenderATP | `Vulnerability.Read.All` | software vulnerabilities per device |
| WindowsDefenderATP | `Software.Read.All` | software inventory |
| WindowsDefenderATP | `SecurityRecommendation.Read.All` | remediation text per product |
| WindowsDefenderATP | `Score.Read.All` | organization exposure score |
| Microsoft Graph | `ThreatHunting.Read.All` | Advanced Hunting queries |
| Microsoft Graph | `CrossTenantInformation.ReadBasic.All` (optional) | Tenant display name in report headers; otherwise set `DVA_TENANT_NAME` |
| Azure RBAC | `Reader` on each subscription | Defender for Cloud findings (optional) |

Create it with the script (needs `az login` as someone who can create apps):

```bash
setup/create-app.sh --tenant contoso      # multi-tenant: writes tenants/contoso/.env
setup/create-app.sh                       # single tenant: prints values for .env
```

The script creates the app and service principal, adds the permissions, resets a client secret, and prints the two steps it cannot do for you: granting admin consent and assigning the Azure Reader role. `--dry-run` shows the `az` commands without running them. See [setup/permissions.md](../setup/permissions.md) for what each permission unlocks and what `dva doctor` prints when one is missing.

## 4. Credentials on disk

**Single tenant:** fill in `.env` in the repository root:

```
DVA_TENANT_ID=...
DVA_CLIENT_ID=...
DVA_CLIENT_SECRET=...
```

**Several tenants:** one directory per tenant, each with its own credentials, runs and caches:

```bash
python3 -m dva tenant init contoso        # creates tenants/contoso/{.env,runs,.cache}
$EDITOR tenants/contoso/.env
python3 -m dva tenant list
```

A certificate can replace the secret: set `DVA_CLIENT_CERT_PATH` (PEM private key) and `DVA_CLIENT_CERT_THUMBPRINT`. Both `.env` locations are gitignored and created with mode 600. Values exported in the shell override the single-tenant `.env`; a tenant's `.env` overrides everything while that tenant is selected.

## 5. Verify

```bash
source .venv/bin/activate
python3 -m dva doctor                     # single tenant
python3 -m dva --tenant contoso doctor    # or DVA_TENANT=contoso
```

Every line must read `ok`. `FAIL ... HTTP 401` means the token was rejected (wrong secret or tenant id); `HTTP 403` means the permission or admin consent is missing. See [troubleshooting.md](troubleshooting.md).

## 6. Claude Code

The repository is also a Claude Code plugin (`.claude-plugin/plugin.json`). Pick one of these two ways to load the `vuln-assessor` agent and its skills:

**a. From the checkout (recommended).** Start `claude --plugin-dir .` in the repository (a plain `claude` also works: project-scoped `.mcp.json` is picked up either way). On first start it asks to approve the project's `cve-mcp` server from `.mcp.json`; accept it. `claude mcp list` should then show `cve-mcp ... Connected`. The `vuln-assessor` agent and the `skills/` under the repo root are picked up automatically.

**b. From the marketplace, into another project.** Run `/plugin marketplace add FrodeHus/defender-vuln-agent` then `/plugin install defender-vuln-agent` in any project. The agent and skills install, but the plugin's own `.mcp.json` resolves `cve-mcp`'s interpreter relative to wherever `claude` is started, which is not this checkout for a marketplace install — the CVE server needs `dva`'s venv. Point at it one of two ways:
   - set `DVA_HOME` to this checkout's absolute path before starting `claude` (the agent runs `cd "${DVA_HOME:-.}"` and activates the venv before every `dva` command), and set `CVE_MCP_PYTHON=$DVA_HOME/.venv/bin/python3` so `.mcp.json`'s `${CVE_MCP_PYTHON:-.venv/bin/python3}` resolves to it; or
   - register the server directly with `claude mcp add cve-mcp -- "$DVA_HOME/.venv/bin/python3" -m cve_mcp.server`, bypassing the bundled `.mcp.json`.

Continue with [usage.md](usage.md).

## Upgrading

`git pull`, then `pip install -e ".[dev]"` again if `pyproject.toml` changed. Run directories, caches and tenant folders are untouched by upgrades. Check `CHANGELOG.md` for changes to `config/scoring.yaml` keys; a missing key fails loudly at startup.
