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
