"""`dva report --brief` prints the few lines the agent needs for its reply, so it never has to read report.md."""
import json
from pathlib import Path

from dva.report_brief import render

FX = Path(__file__).parent / "fixtures" / "sample-run" / "findings.json"


def _doc():
    return json.loads(FX.read_text())


def test_brief_has_the_reply_ingredients():
    out = render(_doc(), suggestions=None, run_dir="/runs/20260914T080000Z")
    lines = out.splitlines()
    assert lines[0] == "Tenant: Contoso · run 20260914T080000Z · /runs/20260914T080000Z"
    assert "1. Connect Secure (Ivanti) 97 Critical — VPN gateways, all internet-facing, two KEV entries added this week" in out
    assert "3. Exchange Server 2019 (Microsoft) 88 Critical" in out
    assert "4. Windows Server" not in out
    assert "Needing action: 6 of 42 products across 4200 devices" in out
    assert "SLA breaches: 1 product(s): Connect Secure (overdue by 7 days)" in out
    assert "End of support: 1 product(s): Windows Server 2019" in out
    assert "Long-standing (>90 days): 2 product(s): Windows Server 2019 (41 CVEs, oldest 402 days), 7-Zip (3 CVEs, oldest 233 days)" in out
    assert "Patched in the last 7 days: 2 critical CVEs" in out
    assert "Exposure score: 61.0 (previous 54.0); secure score 68.5" in out
    assert "Since run 20260907T080000Z: entered top 10: Zoom Workplace; left: oracle/java-runtime-8; newly KEV-listed: Acrobat Reader DC" in out
    assert "Accepted risks: 1 active" in out
    assert "Exception suggestions: none (run dva exception suggest first)" in out
    assert len(out) < 2000


def test_brief_names_partial_and_failed_sources_and_suggestions():
    doc = _doc()
    doc["run"]["sources"]["hunt-config-findings"] = {"status": "failed", "count": None, "error": "boom"}
    doc["run"]["sources"]["mde-vulns"] = {"status": "partial", "count": 10000, "error": None}
    sugg = [{"product": "openssl/openssl", "reasons": ["embedded component"], "suggested_until": "2026-12-13"}]
    out = render(doc, suggestions=sugg, run_dir="/r")
    assert "Sources not ok: hunt-config-findings failed (boom); mde-vulns partial (10000 records)" in out
    assert "Exception suggestions: 1 — openssl/openssl: embedded component (until 2026-12-13)" in out


def test_brief_says_all_sources_ok_when_nothing_is_wrong():
    assert "Sources: all ok" in render(_doc(), suggestions=[], run_dir="/r")


def test_report_brief_cli_prints_and_writes_nothing(tmp_path, capsys):
    from dva.__main__ import main
    from dva.run import Run
    run = Run.create(tmp_path / "runs")
    run.write_json("findings.json", _doc())
    run.write_json("exception-suggestions.json", [{"product": "a/b", "reasons": ["no vendor fix"], "suggested_until": "2027-01-01"}])
    assert main(["report", "--brief", "--run", str(run.dir)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Tenant: Contoso") and "a/b: no vendor fix" in out
    assert not run.path("report.md").exists() and not run.path("report.html").exists()


def test_brief_carries_a_risk_line_per_top_product():
    out = render(_doc(), suggestions=None, run_dir="/r")
    assert "     Risk: The most critical issue is CVE-2026-21887 (critical, CVSS 9.8): it is in CISA's Known Exploited Vulnerabilities catalog" in out
    assert out.count("     Risk: ") == 3
