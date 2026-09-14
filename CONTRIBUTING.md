# Contributing

Thanks for helping. This project is small and test-driven; the bar for a change is a failing test first, then the code.

## Set up

```bash
scripts/install.sh          # venv, package, cve-mcp-server, runs the tests
source .venv/bin/activate
python3 -m pytest -q        # 90+ tests, no credentials or network needed
```

The whole pipeline runs offline with `--fixture` inputs (see [docs/usage.md](docs/usage.md#offline-demo)); `tests/test_e2e.py` exercises it end to end.

## Ground rules

- **Read-only.** Nothing may write to Defender, Graph or Azure. Only `GET` requests, plus `POST` to the Advanced Hunting and Resource Graph query endpoints. The app registration the setup script creates has no write permissions; keep it that way.
- **Raw data stays in files.** Collectors write to the run directory and print one-line summaries. Never print records to stdout; the Claude Code agent reads stdout.
- **Every failure is a one-line `DvaError`.** Wrap library exceptions at the boundary so `python3 -m dva ...` always exits 1 with `dva: <reason>` on stderr, never a traceback.
- **Tenant isolation.** Anything a tenant produces or needs lives under `tenants/<name>/`. Do not add shared state keyed by tenant.
- **No new runtime dependencies** without discussion. Today: `msal`, `requests`, `pyyaml`.
- **Docs and skills must match the CLI.** If you change a flag or an output file, update `README.md`, `docs/`, the agent definition in `.claude/agents/` and the relevant `.claude/skills/*/SKILL.md`, and the tests in `tests/test_agent_files.py` that pin them.

## Tests

- Unit tests use recorded JSON fixtures under `tests/fixtures/`; the CVE-server text fixtures under `tests/fixtures/cve/` are captured from the real server. If you change a parser, re-capture rather than hand-edit.
- Golden files regenerate with `DVA_UPDATE_GOLDEN=1 python3 -m pytest tests/test_report_md.py`. Review the diff.
- Never add a test that hits a live API.

## Pull requests

- One logical change per PR, with a conventional commit message (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- CI runs the suite on Python 3.11, 3.12 and 3.13; keep it green.
- Add a line to `CHANGELOG.md` under *Unreleased*.
