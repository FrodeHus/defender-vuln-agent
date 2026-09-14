# Defender Vulnerability Agent

A read-only vulnerability assessment tool for Microsoft Defender estates, with a Claude Code agent that runs it end to end.

It pulls device inventory and per-device vulnerabilities from Defender for Endpoint, runs Advanced Hunting queries for exposure context (internet-facing, exploited CVEs, privileged logons, compensating controls, installation evidence, certificates, configuration findings), optionally adds Defender for Cloud findings and attack paths, enriches the CVEs that matter with CVSS, EPSS, CISA KEV, exploit maturity/ransomware, and public-exploit intelligence through a local [CVE MCP server](https://github.com/mukul975/cve-mcp-server), scores **software products** (one patch action each) rather than individual CVEs, and writes Markdown, HTML and JSON reports that say what to patch first and where.

- **Read-only by construction.** The app registration holds only read permissions.
- **Multi-tenant.** Each tenant has its own credentials, runs, caches, per-tenant SQLite store and config; ask for an assessment by tenant name.
- **Nothing sensitive leaves your machine** except CVE identifiers sent to the CVE server you run locally.
- **Works without the agent.** Every step is a `dva` command; the whole pipeline also runs offline on fixtures.
- **Prioritized, not just listed.** SLA-age boosts, end-of-support and attack-path flags, fix-version rollups and a 12-month exposure/secure-score trend surface what actually needs attention first.
- **Accepted risk, tracked.** `dva exception` records known, accepted risks (bundled components, EOS software on a deprecation plan) so they stop competing for attention while staying visible in the report; `dva exception suggest` proposes candidates.
- **Ticket-ready.** `dva report --tickets` exports one ticket per action item, ready to hand to a ticketing system.

## Quick start

```bash
git clone https://github.com/frodehus/defender-vuln-agent
cd defender-vuln-agent
scripts/install.sh                                   # uv sync, tests, caches the CVE server
echo "NVD_API_KEY=<your key>" >> .env
az login
setup/create-app.sh --tenant contoso                 # app registration + tenants/contoso/.env
# grant admin consent as the script instructs, then:
source .venv/bin/activate
python3 -m dva --tenant contoso doctor               # every line must say ok
claude --plugin-dir .                                # approve the cve-mcp server when asked
```

This repository is also a Claude Code plugin. To use the agent and skills from another project instead of this checkout, run `/plugin marketplace add FrodeHus/defender-vuln-agent` then `/plugin install defender-vuln-agent`, and see [docs/install.md](docs/install.md#6-claude-code) for pointing the agent at this checkout with `DVA_HOME`.

Then, in Claude Code:

```
Use the vuln-assessor agent to run a vulnerability assessment for contoso
```

The agent replies with the top products, how many need action and any source that was incomplete. Full reports land in `tenants/contoso/runs/<run id>/report.md`, `report.html` and `report.json`.

## What the report looks like

An executive summary with the estate's exposure score and what changed since the last run, then the top 10 products to patch. Each product gets a plain-language risk summary of its most critical vulnerability, its score, the three CVEs driving it, CVE counts by severity, Defender's remediation guidance, and the most critical affected devices with a count of the rest. The HTML version has filters and expandable rows and is a single self-contained file.

## Documentation

| | |
|---|---|
| [docs/install.md](docs/install.md) | Requirements, installer, NVD key, app registration, credentials, tenants, verifying |
| [docs/usage.md](docs/usage.md) | Using the agent, the command line, hunting queries, reading reports, offline demo, run files |
| [docs/configuration.md](docs/configuration.md) | Environment variables, `scoring.yaml`, `sources.yaml`, tenant overrides |
| [docs/architecture.md](docs/architecture.md) | Pipeline, modules, data model, scoring formulas, failure model |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common errors and fixes |
| [setup/permissions.md](setup/permissions.md) | Every permission, why it is needed, what `doctor` prints without it |
| [CLAUDE.md](CLAUDE.md) | Orientation for Claude Code working in this repository |
| [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md) | |

## Manual pipeline

```bash
export DVA_TENANT=contoso
export DVA_RUN=$(python3 -m dva run new)
python3 -m dva mde all
python3 -m dva hunt internet-facing exploited-cves device-tags product-versions evidence privileged-logons mitigations certificates config-findings
python3 -m dva enrich --fetch                                 # calls the CVE server per selected CVE and stores the results
python3 -m dva score
python3 -m dva report --all                                   # includes tickets.json
python3 -m dva exception suggest                               # suggested accepted-risk exceptions
```

## Requirements

[uv](https://docs.astral.sh/uv/), a Defender for Endpoint tenant, an Entra app registration with read permissions (the setup script creates it), and Claude Code for the agent. See [docs/install.md](docs/install.md).

## Acknowledgements

CVE intelligence comes from [cve-mcp-server](https://github.com/mukul975/cve-mcp-server) by Mahipal Jangra (Apache License 2.0), an MCP server that fans out to NVD, EPSS, CISA KEV, Exploit-DB, GitHub, vendor advisories and more. This project does not bundle it; `scripts/cve-mcp.sh` runs a pinned upstream commit through `uvx` and `dva enrich --fetch` talks to it over MCP (stdio) with a small stdlib client, so no CVE text passes through the agent's context. Its `triage_cve`, `lookup_cve` and `get_vendor_advisory` tools are what make the enrichment step possible.

## License

MIT. See [LICENSE](LICENSE).
