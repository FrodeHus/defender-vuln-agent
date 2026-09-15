import json, os
from pathlib import Path
from dva.report_md import render

FX = Path(__file__).parent / "fixtures" / "sample-run" / "findings.json"
GOLD = Path(__file__).parent / "golden" / "report.md"

def test_markdown_matches_golden():
    out = render(json.loads(FX.read_text()))
    if os.environ.get("DVA_UPDATE_GOLDEN"):
        GOLD.parent.mkdir(exist_ok=True); GOLD.write_text(out)
    assert out == GOLD.read_text()

def test_markdown_structure():
    out = render(json.loads(FX.read_text()))
    assert out.startswith("# Vulnerability assessment")
    assert "## Top 10 products to patch" in out and "### 1. Connect Secure" in out
    assert "CVE-2026-21887" in out and "+ 1 more in findings.json" in out


def test_markdown_shows_patched_7d_and_score_trend_lines():
    out = render(json.loads(FX.read_text()))
    assert "Patched in the last 7 days: 2 critical, 1 high." in out
    assert "Score trend (12 months): exposure score 54.0/61.0/61.0 (min/max/now); secure score 62.0/68.5/68.5 (min/max/now)." in out


def test_markdown_method_mentions_ransomware_maturity_sla_and_asset_signals():
    out = render(json.loads(FX.read_text()))
    for marker in ["known ransomware use", "exploit maturity", "SLA overdue multiplier",
                   "privileged-user sign-ins", "cloud attack-path membership", "applied mitigations"]:
        assert marker in out


def test_markdown_shows_vendor_advisories_with_link():
    out = render(json.loads(FX.read_text()))
    assert "Vendor advisories:" in out
    assert "- [RHSA-2026:1234](https://access.redhat.com/errata/RHSA-2026:1234) — Red Hat, ivanti-connect-secure security update (2026-09-05)" in out
    assert "- advisory — MSRC" in out


def test_markdown_lists_long_standing_products():
    out = render(json.loads(FX.read_text()))
    assert "## Long-standing vulnerabilities (open for more than 90 days)" in out
    assert "| 7-Zip | 7-Zip | 12 Low | 880 | 3 of 3 | 233 | 0 / 1 / 2 / 0 |" in out
    assert out.index("## Long-standing") < out.index("## Method")


def test_markdown_tolerates_findings_without_long_standing():
    doc = json.loads(FX.read_text()); doc.pop("long_standing"); doc["summary"].pop("long_standing_products")
    assert "Long-standing" not in render(doc)


def test_markdown_shows_a_description_under_each_described_driving_cve():
    out = render(json.loads(FX.read_text()))
    assert "- CVE-2026-21887 · CVSS 9.8 · EPSS 0.94 · KEV · Exploit · Unauthenticated remote code execution in web component\n  An unauthenticated attacker can send a crafted request to the web component to execute arbitrary code on the appliance." in out
    assert "  A path traversal in the admin interface lets an authenticated user read arbitrary files." in out
