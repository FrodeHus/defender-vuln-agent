# Security

## What this tool touches

- **Reads only.** Defender for Endpoint, Microsoft Graph Advanced Hunting and Azure Resource Graph are called with `GET` or read-only query `POST`s. The app registration created by `setup/create-app.sh` holds only `*.Read.All` application permissions and, optionally, the Azure `Reader` role.
- **Credentials** live in `.env` (single tenant) or `tenants/<name>/.env` (multi tenant), both gitignored, created with mode `600`. Tokens are cached under `.cache/tokens.json` with mode `600` in a `700` directory. Secrets are never logged, printed or written to run directories.
- **Tenant data** (inventory, vulnerabilities, reports) is written to the run directory only. In multi-tenant mode each tenant has its own runs and caches; nothing is shared between tenants except code.
- **Outbound data.** The only third-party service contacted is the `cve-mcp` server you run locally, which in turn queries public sources (NVD, EPSS, CISA KEV, Exploit-DB and others) with CVE identifiers only. No device names, tenant ids or inventory leave your machine.
- **Reports** are self-contained HTML. Every value from Defender is HTML-escaped before rendering; the embedded JSON cannot break out of its script tag.

## Reporting a vulnerability

Please do not open a public issue for security problems. Email the maintainer at the address in the git history, or use GitHub's private vulnerability reporting on this repository. You will get an acknowledgement within a week.
