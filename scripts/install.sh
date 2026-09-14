#!/usr/bin/env bash
# One-shot local install: virtualenv + this package (uv sync, or python3 -m venv + pip without uv),
# then pre-downloads the cve-mcp-server that .mcp.json starts through `uvx` (scripts/cve-mcp.sh).
# Usage: scripts/install.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 0 ]] || { echo "usage: scripts/install.sh (no arguments)" >&2; exit 2; }
cd "$HERE"

if command -v uv >/dev/null; then
  echo "Installing with uv (locked)"
  uv sync --locked
  PY="uv run python3"
else
  echo "uv not found; installing dva with python3 -m venv + pip (the CVE server still needs uv: https://docs.astral.sh/uv/)"
  command -v python3 >/dev/null || { echo "python3 is required (3.11+)" >&2; exit 1; }
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "python3 3.11 or newer is required" >&2; exit 1; }
  [[ -d .venv ]] || python3 -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python3 -m pip install -q --upgrade pip
  python3 -m pip install -q -e ".[dev]"
  PY="python3"
fi

[[ -f .env ]] || cp .env.example .env

$PY -m pytest -q -W error >/dev/null && echo "Tests pass." || { echo "Tests failed; run '$PY -m pytest' to see why." >&2; exit 1; }

if command -v uvx >/dev/null; then
  echo "Caching the CVE server (first download takes a moment)"
  "$HERE/scripts/cve-mcp.sh" --warm
else
  echo "Skipped caching the CVE server: install uv, then run scripts/cve-mcp.sh --warm" >&2
fi

cat <<EOT

Installed. Next steps:
  1. Put your NVD API key in .env:  NVD_API_KEY=...   (free at https://nvd.nist.gov/developers/request-an-api-key)
  2. Create an app registration and credentials:  setup/create-app.sh [--tenant NAME]
     (or fill in .env for a single tenant / tenants/NAME/.env per tenant)
  3. Verify:  uv run dva doctor  [--tenant NAME]   (or: source .venv/bin/activate && python3 -m dva doctor)
  4. Start Claude Code here with:  claude --plugin-dir .   and ask:
       "Use the vuln-assessor agent to run a vulnerability assessment for NAME"
Docs: docs/install.md, docs/usage.md
EOT
