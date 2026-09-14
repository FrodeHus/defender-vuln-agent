import json
import re
from pathlib import Path
from dva.report_html import render

FX = Path(__file__).parent / "fixtures" / "sample-run" / "findings.json"


def test_html_is_self_contained_and_embeds_data():
    doc = json.loads(FX.read_text())
    out = render(doc)
    assert out.startswith("<!doctype html>")
    # the embedded findings JSON may legitimately carry http(s) URLs (e.g. vendor advisory links);
    # only the surrounding static template must load no external assets.
    without_data = re.sub(r'<script id="data".*?</script>', "", out, flags=re.S)
    assert "http://" not in without_data.replace("http://www.w3.org", "") and "https://" not in without_data
    assert "__FINDINGS_JSON__" not in out and '"Connect Secure"' in out
    assert "<\\/" in out or "</script>" not in json.dumps(doc)  # embedded JSON never closes the script tag
    for marker in ["Top 10 products to patch", "All prioritized products", "How scores are computed", "Expand all", "Internet-facing"]:
        assert marker in out


def test_html_renders_advisories_block():
    doc = json.loads(FX.read_text())
    assert doc["products"][0].get("advisories")
    out = render(doc)
    assert "function advisories(" in out
    assert "Vendor advisories" in out
    assert "RHSA-2026:1234" in out and "https://access.redhat.com/errata/RHSA-2026:1234" in out


def test_html_renders_trend_table_and_sparkline():
    doc = json.loads(FX.read_text())
    assert len(doc.get("trend") or []) >= 2
    out = render(doc)
    assert "id=\"trend\"" in out
    assert "function trend(" in out and "function sparkline(" in out
    assert "no external assets" not in out  # sanity: not just a comment stub
    assert "<svg" not in out.split("<script")[0]  # sparkline is built client-side, not server-rendered


def test_html_has_score_trend_chart_container():
    doc = json.loads(FX.read_text())
    assert len(doc.get("score_trend") or []) >= 2
    out = render(doc)
    assert 'id="score-trend"' in out
    assert "function scoreTrendChart(" in out
    assert '<svg id="score-trend"' not in out.split("<script")[0]  # built client-side, not server-rendered


def test_html_sparkline_filters_null_exposure_scores_instead_of_mapping_to_zero():
    doc = json.loads(FX.read_text())
    out = render(doc)
    assert "exposure_score == null ? 0" not in out
    assert "function segments(" in out


def test_html_renders_without_exception_when_trend_has_null_exposure_score():
    doc = json.loads(FX.read_text())
    doc["trend"][0]["exposure_score"] = None
    out = render(doc)  # must not raise
    assert out.startswith("<!doctype html>")


def test_html_appendix_mentions_ransomware_maturity_sla_and_asset_signals():
    doc = json.loads(FX.read_text())
    out = render(doc)
    for marker in ["known ransomware use", "exploit maturity", "SLA overdue multiplier",
                   "privileged-user sign-ins", "cloud attack-path membership", "applied mitigations"]:
        assert marker in out


def test_html_renders_patched_7d_in_card_body():
    doc = json.loads(FX.read_text())
    assert doc["products"][0].get("patched_7d")
    out = render(doc)
    assert "Patched in the last 7 days" in out
    assert "p7.cves.map" in out  # built client-side from patched_7d.cves, not server-rendered


def test_html_escapes_script_close():
    doc = json.loads(FX.read_text()); doc["products"][0]["reason"] = "x</script><b>y"
    out = render(doc)
    assert "x</script>" not in out
