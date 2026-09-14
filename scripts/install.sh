#!/usr/bin/env bash
# One-shot local install: venv, this package, and the cve-mcp-server the agent uses for CVE intel.
# Usage: scripts/install.sh [--cve-server-dir DIR]   (default: ../cve-mcp-server next to this repo)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CVE_DIR="$HERE/../cve-mcp-server"
while [[ $# -gt 0 ]]; do case "$1" in --cve-server-dir) CVE_DIR="$2"; shift 2;; *) echo "unknown arg $1" >&2; exit 2;; esac; done

command -v python3 >/dev/null || { echo "python3 is required (3.11+)" >&2; exit 1; }
PYV=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "python3 $PYV found; 3.11 or newer is required" >&2; exit 1; }

cd "$HERE"
[[ -d .venv ]] || python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python3 -m pip install -q --upgrade pip
python3 -m pip install -q -e ".[dev]"

if [[ ! -d "$CVE_DIR" ]]; then
  echo "Cloning cve-mcp-server into $CVE_DIR"
  git clone -q https://github.com/mukul975/cve-mcp-server "$CVE_DIR"
fi
python3 -m pip install -q -e "$CVE_DIR"
if [[ ! -f "$CVE_DIR/.env" ]]; then
  cp "$CVE_DIR/.env.example" "$CVE_DIR/.env" 2>/dev/null || touch "$CVE_DIR/.env"
fi
[[ -f .env ]] || cp .env.example .env

python3 -m pytest -q >/dev/null && echo "Tests pass." || { echo "Tests failed; run 'python3 -m pytest' to see why." >&2; exit 1; }

cat <<EOT

Installed. Next steps:
  1. Put your NVD API key in $CVE_DIR/.env   (NVD_API_KEY=...; free at https://nvd.nist.gov/developers/request-an-api-key)
  2. Create an app registration and credentials:  setup/create-app.sh [--tenant NAME]
     (or fill in .env for a single tenant / tenants/NAME/.env per tenant)
  3. Verify:  source .venv/bin/activate && python3 -m dva doctor  [--tenant NAME]
  4. Start Claude Code in this directory, approve the cve-mcp server, and ask:
       "Use the vuln-assessor agent to run a vulnerability assessment for NAME"
Docs: docs/install.md, docs/usage.md
EOT
