# Installation

## Requirements

- [uv](https://docs.astral.sh/uv/): `uv sync` installs the right Python and the locked dependencies, and `uvx` runs the CVE server. (`dva` alone also works with Python 3.11+ and `pip`.) Plus `git` and `bash`.
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

The script runs `uv sync --locked` (creates `.venv` from `uv.lock`, exact reproducible versions), copies `.env.example` to `.env`, runs the test suite, and pre-downloads the [`cve-mcp-server`](https://github.com/mukul975/cve-mcp-server) so Claude Code's first start is fast. Without `uv` it installs `dva` with `python3 -m venv` and `pip`, but the CVE server still needs `uvx`.

Manual equivalent:

```bash
uv sync --locked            # or: python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
scripts/cve-mcp.sh --warm   # optional: cache the CVE server now instead of on first use
```

The environment lives in `.venv`; run commands as `uv run dva ...` or activate it (`source .venv/bin/activate`) and use `python3 -m dva ...`. The docs show the activated form.

**How the CVE server is run.** Nothing is cloned. `.mcp.json` starts `scripts/cve-mcp.sh`, which runs the server with `uvx` from a pinned upstream commit (`CVE_MCP_REF` in the script) and pins the MCP SDK below 2.0, which upstream needs but does not declare. The parsers in this repo are tested against that commit's output, so the pin only moves together with the fixtures. The command in `.mcp.json` is `${CLAUDE_PLUGIN_ROOT:-.}/scripts/cve-mcp.sh`, so the same file works for a marketplace install and for `claude` started in the checkout.

## 2. NVD API key

Put the key in this repo's `.env` (the wrapper exports it to the server; an exported shell variable wins over the file):

```
NVD_API_KEY=your-key
```

Optional: `GITHUB_TOKEN` in the same file for PoC searches on GitHub. The key is tenant-independent, so it lives in the repo `.env` even on a multi-tenant install.

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

**a. From the checkout (recommended).** Start `claude --plugin-dir .` in the repository (a plain `claude` also works: project-scoped `.mcp.json` is picked up either way). On first start it may ask to approve the project's `cve-mcp` server from `.mcp.json`; accepting it makes the CVE tools available for ad hoc questions, but the assessment itself does not need it: `dva enrich --fetch` starts the same `scripts/cve-mcp.sh` on its own. The `vuln-assessor` agent and the `skills/` under the repo root are picked up automatically.

**b. From the marketplace, into another project.** Run `/plugin marketplace add FrodeHus/defender-vuln-agent` then `/plugin install defender-vuln-agent` in any project. The plugin's `.mcp.json` starts the CVE server from the plugin's own directory through `uvx`, so it needs no configuration; the NVD key then comes from an exported `NVD_API_KEY` (the plugin directory has no `.env`). The `dva` CLI, tenants and run data still live in this checkout: set `DVA_HOME` to its absolute path before starting `claude` (the agent runs `cd "${DVA_HOME:-.}"` and activates the venv before every `dva` command).

### Running the agent on a local model with Ollama

Claude Code talks to any Anthropic-compatible endpoint, and [Ollama](https://docs.ollama.com/api/anthropic-compatibility) serves one at `/v1/messages` since version 0.14. Nothing in this repository changes: the CVE server is still started by `dva enrich --fetch`, and the agent only sequences `dva` commands and reads their short summaries, which is work a local model can do.

**Context length first.** Ollama's default context window is far too small for Claude Code; 64K tokens is the documented minimum for comfortable use. Either raise it for the whole server before starting Ollama:

```bash
OLLAMA_CONTEXT_LENGTH=65536 ollama serve
```

or bake it into a model alias you then use everywhere below:

```bash
ollama pull qwen3-coder
printf 'FROM qwen3-coder\nPARAMETER num_ctx 65536\n' > /tmp/Modelfile && ollama create qwen3-coder-64k -f /tmp/Modelfile
```

**a. `ollama launch claude` (recommended).** Ollama's launcher sets the endpoint and auth variables for you, pulls the model if needed and starts Claude Code. Run it in this checkout; arguments after `--` go to Claude Code unchanged, which is how the plugin directory is passed:

```bash
export ANTHROPIC_DEFAULT_SONNET_MODEL=qwen3-coder-64k
ollama launch claude --model qwen3-coder-64k -- --plugin-dir .
```

Without `--model` the launcher shows a model picker; `--yes` skips the picker (and then requires `--model`), which is what you want in scripts or a scheduled job. The `ANTHROPIC_DEFAULT_SONNET_MODEL` export is the one thing the launcher does not do for you: `agents/vuln-assessor.md` pins `model: sonnet`, and that alias has to resolve to your local model or the agent will try to reach Anthropic. A one-shot assessment from a script looks like:

```bash
ollama launch claude --model qwen3-coder-64k --yes -- --plugin-dir . -p "assess vulnerabilities for contoso"
```

**b. By hand.** The launcher only sets three variables; set them yourself if you prefer or if you run an older Ollama without `launch`:

```bash
ANTHROPIC_BASE_URL=http://localhost:11434 ANTHROPIC_AUTH_TOKEN=ollama ANTHROPIC_API_KEY= ANTHROPIC_DEFAULT_SONNET_MODEL=qwen3-coder-64k claude --plugin-dir . --model qwen3-coder-64k
```

`ANTHROPIC_AUTH_TOKEN` (any non-empty value) is what bypasses the claude.ai login; the base URL alone keeps your existing login active.

**What to expect.**

- Ollama's docs recommend `qwen3-coder`, `glm-4.7` or `minimax-m2.1` for Claude Code; the useful sizes want a 24 GB or larger GPU. Cloud-hosted variants (`:cloud` tags) work through the same launcher.
- Prompt caching is not available, so every turn resends the context, which costs time rather than money.
- A smaller model follows instructions less reliably: check its reply against `python3 -m dva report --brief` the first few runs, and treat the tenant-selection and exception-add rules in the agent as the places it is most likely to slip.
- Ollama Cloud endpoints currently reject the `x-api-key` header Claude Code sends ([ollama/ollama#16922](https://github.com/ollama/ollama/issues/16922)); a local Ollama is fine.

Continue with [usage.md](usage.md).

## Upgrading

`git pull`, then `uv sync --locked` (or `pip install -e ".[dev]"` without uv) if `pyproject.toml` or `uv.lock` changed. Run directories, caches and tenant folders are untouched by upgrades. Check `CHANGELOG.md` for changes to `config/scoring.yaml` keys; a missing key fails loudly at startup.
