# Vulnerability assessment — Contoso

Run 20260914T080000Z · generated 2026-09-14T08:00:00+00:00 · previous run 20260907T080000Z

## Executive summary

6 of 42 software products across 4200 devices need action. 3 of the top 10 carry KEV-listed CVEs on internet-facing hosts and should be treated as emergency changes. 6 KEV-listed CVEs are present; 23 internet-facing devices have at least one critical CVE. Exposure score is 61.0.

Since run 20260907T080000Z: entered the top 10: Zoom Workplace; left the top 10: oracle/java-runtime-8; newly KEV-listed products: Acrobat Reader DC. Exposure score moved from 54.0 to 61.0.

## Top 10 products to patch

| # | Product | Vendor | Score | Devices | Crit | High | Med | Low | Flags |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Connect Secure | Ivanti | 97 Critical | 6 | 4 | 7 | 12 | 3 | KEV, exploit, internet-facing |
| 2 | FortiClient EMS | Fortinet | 91 Critical | 3 | 2 | 3 | 5 | 1 | KEV, exploit, internet-facing |
| 3 | Exchange Server 2019 | Microsoft | 88 Critical | 4 | 3 | 5 | 9 | 4 | KEV, exploit, internet-facing |
| 4 | Windows Server 2019 | Microsoft | 79 High | 312 | 5 | 22 | 61 | 40 | KEV, exploit |
| 5 | Acrobat Reader DC | Adobe | 66 High | 1140 | 3 | 11 | 24 | 8 | KEV |
| 6 | Zoom Workplace | Zoom | 18 Low | 690 | 0 | 0 | 4 | 2 | - |

### 1. Connect Secure (Ivanti) — 97 Critical

Why: VPN gateways, all internet-facing, two KEV entries added this week

Risk: The most critical issue is CVE-2026-21887 (critical, CVSS 9.8): it is in CISA's Known Exploited Vulnerabilities catalog, so it is being used in real attacks; public exploit code is available; EPSS puts the chance of exploitation in the next 30 days at 94%. An unauthenticated attacker can send a crafted request to the web component to execute arbitrary code on the appliance. An attacker could run their own code on the affected device and take control of it over the network without any credentials. 6 devices run Connect Secure, 6 of them internet-facing and 6 tagged as critical; leaving it unpatched risks full compromise on systems reachable from the internet.

Remediation: Upgrade to 22.7R2.5. Apply Ivanti mitigation XML until the change window.

Driving vulnerabilities (26 open CVEs in total):
- CVE-2026-21887 · CVSS 9.8 · EPSS 0.94 · KEV · Exploit · Unauthenticated remote code execution in web component
- CVE-2026-20124 · CVSS 9.1 · EPSS 0.71 · KEV · Authentication bypass in SAML endpoint
- CVE-2025-46512 · CVSS 8.2 · EPSS 0.33 · Exploit · Path traversal allowing config read

Affected assets (6): All 6 internet-facing · 6 Tier0 · exposure High
- vpn-gw-01 — Internet-facing · Tier0 · High
- vpn-gw-02 — Internet-facing · Tier0 · High
- vpn-gw-03 — Internet-facing · Tier0
- vpn-gw-04 — Internet-facing · Tier0
- vpn-gw-05 — Internet-facing · Tier0
+ 1 more in findings.json

### 2. FortiClient EMS (Fortinet) — 91 Critical

Why: Management server reachable from the internet, KEV-listed SQL injection

Risk: The most critical issue is CVE-2026-24471 (critical, CVSS 9.8): it is in CISA's Known Exploited Vulnerabilities catalog, so it is being used in real attacks; public exploit code is available; EPSS puts the chance of exploitation in the next 30 days at 89%. A SQL injection in the DAS component allows an unauthenticated attacker to execute arbitrary SQL commands. An attacker could read or change the application's database over the network without any credentials. 3 devices run FortiClient EMS, 3 of them internet-facing; leaving it unpatched risks data theft or tampering on systems reachable from the internet.

Remediation: Upgrade to 7.4.3. Restrict admin interface to the management VLAN.

Driving vulnerabilities (11 open CVEs in total):
- CVE-2026-24471 · CVSS 9.8 · EPSS 0.89 · KEV · Exploit · SQL injection in DAS component
- CVE-2025-52970 · CVSS 9.1 · EPSS 0.42 · Improper access control on API
- CVE-2025-49202 · CVSS 7.5 · EPSS 0.12 · Information disclosure via log endpoint

Affected assets (3): 3 internet-facing · 3 Prod · Azure VMs
- ems-prod-01 — Internet-facing · Prod · High
- ems-prod-02 — Internet-facing · Prod · High
- ems-dr-01 — Internet-facing · DR

### 3. Exchange Server 2019 (Microsoft) — 88 Critical

Why: OWA published externally, KEV entry with public proof of concept

Risk: The most critical issue is CVE-2026-21410 (critical, CVSS 9.8): it is in CISA's Known Exploited Vulnerabilities catalog, so it is being used in real attacks; public exploit code is available; EPSS puts the chance of exploitation in the next 30 days at 82%. An elevation of privilege vulnerability allows remote code execution through NTLM relay against the Exchange server. An attacker could run their own code on the affected device and take control of it over the network without any credentials. 4 devices run Exchange Server 2019, 4 of them internet-facing and 4 tagged as critical; leaving it unpatched risks full compromise on systems reachable from the internet.

Remediation: Install September 2026 SU (KB5052xxx). Enable Extended Protection.

Driving vulnerabilities (21 open CVEs in total):
- CVE-2026-21410 · CVSS 9.8 · EPSS 0.82 · KEV · Exploit · Remote code execution via NTLM relay
- CVE-2026-21334 · CVSS 8.8 · EPSS 0.55 · Exploit · Privilege escalation in PowerShell backend
- CVE-2025-53786 · CVSS 8.0 · EPSS 0.19 · Hybrid configuration elevation of privilege

Affected assets (4): 4 internet-facing · 4 Tier0 · device group Messaging
- exch-01 — Internet-facing · Tier0 · High
- exch-02 — Internet-facing · Tier0 · High
- exch-03 — Internet-facing · Tier0
- exch-04 — Internet-facing · Tier0

### 4. Windows Server 2019 (Microsoft) — 79 High

Why: Largest fleet, one KEV-listed kernel CVE, 40 hosts marked High value

Risk: The most critical issue is CVE-2026-21335 (critical, CVSS 8.8): it is in CISA's Known Exploited Vulnerabilities catalog, so it is being used in real attacks; public exploit code is available; EPSS puts the chance of exploitation in the next 30 days at 61%. A use after free in the Win32k kernel driver allows a local attacker to elevate privileges to SYSTEM. An attacker could turn a foothold into administrator-level control with local access to the device. 312 devices run Windows Server 2019, 9 of them internet-facing and 40 tagged as critical; leaving it unpatched risks privilege escalation on systems reachable from the internet.

Remediation: Deploy September 2026 cumulative update via ring 2. Reboot required.

Driving vulnerabilities (128 open CVEs in total):
- CVE-2026-21335 · CVSS 8.8 · EPSS 0.61 · KEV · Exploit · Win32k elevation of privilege
- CVE-2026-21290 · CVSS 9.0 · EPSS 0.27 · LDAP remote code execution
- CVE-2026-21250 · CVSS 7.8 · EPSS 0.14 · Kerberos elevation of privilege

Affected assets (312): 40 Tier0 · 9 internet-facing · 118 exposure High · 9 device groups
- dc-01 — Domain controller · Tier0 · High
- dc-02 — Domain controller · Tier0 · High
- adfs-01 — Internet-facing · Tier0
- web-frontend-03 — Internet-facing · Prod
- sccm-01 — Tier0 · High
+ 307 more in findings.json

### 5. Acrobat Reader DC (Adobe) — 66 High

Why: Installed on most workstations, one KEV-listed CVE, no exposed hosts

Risk: The most critical issue is CVE-2026-24433 (critical, CVSS 8.6): it is in CISA's Known Exploited Vulnerabilities catalog, so it is being used in real attacks; EPSS puts the chance of exploitation in the next 30 days at 45%. A use after free when parsing a crafted PDF could lead to arbitrary code execution when a user opens the file. An attacker could run their own code on the affected device and take control of it with local access to the device without any credentials if a user opens a crafted file or link. 1140 devices run Acrobat Reader DC, 62 marked high value; leaving it unpatched risks full compromise.

Remediation: Push 24.003.20xxx via Intune. Auto-update policy currently disabled.

Driving vulnerabilities (46 open CVEs in total):
- CVE-2026-24433 · CVSS 8.6 · EPSS 0.45 · KEV · Use after free leading to code execution
- CVE-2026-24432 · CVSS 7.8 · EPSS 0.11 · Out of bounds write in font parser
- CVE-2025-47172 · CVSS 7.8 · EPSS 0.06 · Integer overflow in JavaScript engine

Affected assets (1140): 1,140 workstations · 0 internet-facing · 62 High value
- ws-finance-114 — High value · CFO office
- ws-legal-021 — High value
- ws-hr-007 — High value · PII
- ws-exec-003 — High value
- ws-finance-102 — High value
+ 1135 more in findings.json

### 6. Zoom Workplace (Zoom) — 18 Low

Why: Medium severity only, auto-update enabled

Risk: The most critical issue is CVE-2025-30663 (medium, CVSS 6.6). A time-of-check time-of-use race condition allows a local authenticated user to escalate privileges. An attacker could turn a foothold into administrator-level control with local access to the device. 690 devices run Zoom Workplace, 41 marked high value; leaving it unpatched risks privilege escalation.

Remediation: No action; auto-update will resolve within 14 days.

Driving vulnerabilities (6 open CVEs in total):
- CVE-2025-30663 · CVSS 6.6 · EPSS 0.01 · Time-of-check time-of-use race
- CVE-2025-30664 · CVSS 6.6 · EPSS 0.01 · Improper neutralization of special elements
- CVE-2025-30665 · CVSS 3.3 · EPSS 0.0 · Null pointer dereference

Affected assets (690): 690 workstations · 0 internet-facing · 41 High value
- ws-exec-003 — High value
- ws-exec-004 — High value
- ws-finance-114 — High value
+ 687 more in findings.json

## Method

Each product's score (0 to 100) combines threat signals for its CVEs (CVSS, EPSS, CISA KEV listing, public exploit availability), the context of the affected assets (internet exposure, Defender exposure level, device value, criticality tags) and the number of affected devices. Findings are grouped by software product so one row maps to one patch action; only the three CVEs contributing most to a product's score and its most critical assets are shown. Weights live in scoring.yaml.

## Sources

- hunting.internet-facing: ok (187 records)
- mde.machines: ok (4200 records)
