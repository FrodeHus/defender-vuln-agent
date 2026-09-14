# CLAUDE.md

## What this is

A read-only vulnerability assessment tool for Microsoft Defender estates. `dva` (Python CLI) collects device/software inventory and Advanced Hunting results, enriches the CVEs that matter through a local `cve-mcp` MCP server, scores **software products**, and writes Markdown/HTML/JSON reports. A Claude Code agent (`agents/vuln-assessor.md`) sequences the CLI and calls the CVE server. This repository is also a Claude Code plugin — see `.claude-plugin/plugin.json`.

## Build and test

```bash
uv sync --locked            # creates .venv from uv.lock (pip fallback: pip install -e ".[dev]")
uv run pytest -q -W error   # ~200 tests, no credentials or network needed; CI runs the same
```

`scripts/install.sh` runs `uv sync --locked` (falls back to venv + pip), installs `cve-mcp-server` next to the repo into the same `.venv`, and runs the suite. Commands in docs assume an activated `.venv` (`source .venv/bin/activate`); `uv run ...` works without activating. The whole pipeline also runs offline with `--fixture` inputs (`tests/test_e2e.py`).

Golden report files regenerate with `DVA_UPDATE_GOLDEN=1 python3 -m pytest tests/test_report_md.py`; review the diff before committing.

## Layout

- `dva/` — the CLI and pipeline (auth, collectors, hunting, scoring, reports). Read `docs/architecture.md` for the pipeline and data model.
- `agents/vuln-assessor.md` — the Claude Code agent definition (plugin default `agents/` dir).
- `skills/*/SKILL.md` — one skill per command group (auth, inventory, hunting, cloud, prioritize/report), used by the agent (plugin default `skills/` dir).
- `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` — plugin and marketplace manifests.
- `.mcp.json` — declares the `cve-mcp` server; works from a plain clone (`.venv/bin/python3`).
- `config/` — `scoring.yaml` (weights), `sources.yaml` (which hunting sources run).
- `tenants/<name>/` — per-tenant credentials, runs, cache; nothing tenant-specific lives elsewhere.
- `tests/` — fixtures under `tests/fixtures/`; `tests/test_agent_files.py` pins the agent/skill text to the real CLI.
- `docs/` — install, usage, configuration, architecture, troubleshooting.

## Running the agent

From this checkout: `claude --plugin-dir .` (or plain `claude`, which also picks up the project `.mcp.json`). From a marketplace install in another project, set `DVA_HOME` to this checkout's path first — see `docs/install.md` step 6.

## Rules

- **Read-only.** No writes to Defender, Graph or Azure beyond `GET` and the Advanced Hunting/Resource Graph query POSTs. The app registration has no write permissions.
- **Tenant isolation.** Everything a tenant produces or needs lives under `tenants/<name>/`; never add shared state keyed by tenant, never read one tenant's `.env` or data while reporting on another.
- **Raw run files stay unread by the agent.** It reads only command summaries and `report.md`, never `vulns.jsonl`, `machines.json`, `hunt-*.json`, `enrichment.json`, `findings.json`.

## Conventions

- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), one logical change per PR, a `CHANGELOG.md` line under *Unreleased*.
- Test-driven: a failing test first, then the code.
- No new runtime dependencies without discussion (today: `msal`, `requests`, `pyyaml`).
- Docs and skills must match the CLI: update `README.md`, `docs/`, `agents/vuln-assessor.md` and `skills/*/SKILL.md` together with any flag or output-file change, and the tests in `tests/test_agent_files.py` that pin them.

## Gotchas

- Always `python3`, never `python`.
- The CVE server's NVD key lives in `../cve-mcp-server/.env`, not this repo's `.env`; an empty `NVD_API_KEY=` line there blocks any other value.
- Select a tenant with `DVA_TENANT=<name>` (or `--tenant`); required whenever `dva tenant list` prints more than one name.
- `dva enrich --store` and `dva exception add|remove` are the only supported ways to write `enrichment` intel and `exceptions.yaml`; never hand-edit either.
