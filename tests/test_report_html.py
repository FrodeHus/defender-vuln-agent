import json
from pathlib import Path
from dva.report_html import render

FX = Path(__file__).parent / "fixtures" / "sample-run" / "findings.json"


def test_html_is_self_contained_and_embeds_data():
    doc = json.loads(FX.read_text())
    out = render(doc)
    assert out.startswith("<!doctype html>")
    assert "http://" not in out.replace("http://www.w3.org", "") and "https://" not in out
    assert "__FINDINGS_JSON__" not in out and '"Connect Secure"' in out
    assert "<\\/" in out or "</script>" not in json.dumps(doc)  # embedded JSON never closes the script tag
    for marker in ["Top 10 products to patch", "All prioritized products", "How scores are computed", "Expand all", "Internet-facing"]:
        assert marker in out


def test_html_renders_trend_table_and_sparkline():
    doc = json.loads(FX.read_text())
    assert len(doc.get("trend") or []) >= 2
    out = render(doc)
    assert "id=\"trend\"" in out
    assert "function trend(" in out and "function sparkline(" in out
    assert "no external assets" not in out  # sanity: not just a comment stub
    assert "<svg" not in out.split("<script")[0]  # sparkline is built client-side, not server-rendered


def test_html_escapes_script_close():
    doc = json.loads(FX.read_text()); doc["products"][0]["reason"] = "x</script><b>y"
    out = render(doc)
    assert "x</script>" not in out
