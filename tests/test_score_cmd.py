from datetime import datetime, timezone
from tests.test_rollup import seed
from dva.run import Run
from dva.score_cmd import compute
from dva.config import load_scoring
from dva.cache import IntelCache
from dva.scoring import CveIntel


def test_findings_document(tmp_path):
    run = seed(tmp_path / "runs")
    cache = IntelCache(tmp_path / "cache", 7)
    cache.put("CVE-2026-21887", CveIntel(cvss=9.8, epss=0.94, epss_percentile=0.99, kev=True, exploit_public=True, title="Unauthenticated RCE"))
    run.write_json("exposure.json", {"score": 54.0, "by_group": {}})
    doc = compute(run, load_scoring(), cache)
    top = doc["products"][0]
    assert top["product"] == "Connect Secure" and top["rank"] == 1 and top["label"] == "Critical"
    assert top["driving_cves"][0] == {"id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "epss": 0.94, "kev": True, "poc": True, "title": "Unauthenticated RCE"}
    assert top["assets"]["count"] == 2 and top["assets"]["top"][0]["name"] == "vpn-gw-01"
    assert "1 internet-facing" in top["assets"]["breakdown"] and "1 Tier0" in top["assets"]["breakdown"]
    assert top["partial_intel"] is True  # CVE-2025-46512 has no intel
    assert doc["summary"]["devices"] == 2 and doc["summary"]["kev_cves"] == 1 and doc["summary"]["internet_facing_at_risk"] == 1
    assert doc["summary"]["exposure_score"] == 54.0 and doc["diff_from_previous"]["previous_run_id"] is None


def test_diff_against_previous(tmp_path):
    run = seed(tmp_path / "runs")
    (tmp_path / "runs" / "20200101T000000Z").mkdir()
    prev_dir = tmp_path / "runs" / "20200101T000000Z"
    prev_dir.joinpath("manifest.json").write_text('{"run_id": "20200101T000000Z", "sources": {}}')
    prev_dir.joinpath("findings.json").write_text('{"summary": {"exposure_score": 61.0}, "products": [{"key": "old/thing", "rank": 1, "flags": {"kev": false}}, {"key": "adobe/acrobat-reader-dc", "rank": 2, "flags": {"kev": false}}]}')
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "c", 7))
    d = doc["diff_from_previous"]
    assert d["previous_run_id"] == "20200101T000000Z" and "old/thing" in d["left_top10"] and "ivanti/connect-secure" in d["entered_top10"]
    assert doc["summary"]["previous_exposure_score"] == 61.0


def test_scores_without_machines_json(tmp_path):
    from dva.run import Run

    run = Run.create(tmp_path / "runs")
    run.write_jsonl("vulns.jsonl", [
        {"device_id": "m1", "device_name": "vpn-gw-01", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.1", "cve_id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "exploitability": "ExploitIsInKit", "first_seen": "2026-09-08", "recommendation_ref": None},
    ])
    run.write_json("recommendations.json", [])
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    assert doc["summary"]["devices"] == 1
    assert doc["products"][0]["product"] == "Connect Secure"


def test_corrupt_previous_findings_treated_as_no_previous_run(tmp_path):
    run = seed(tmp_path / "runs")
    prev_dir = tmp_path / "runs" / "20200101T000000Z"
    prev_dir.mkdir()
    prev_dir.joinpath("manifest.json").write_text('{"run_id": "20200101T000000Z", "sources": {}}')
    prev_dir.joinpath("findings.json").write_text("{not valid json")
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "c", 7))
    d = doc["diff_from_previous"]
    assert d["previous_run_id"] is None
    assert d["left_top10"] == []
    assert doc["summary"]["previous_exposure_score"] is None


def test_sla_overdue_by_days_and_summary(tmp_path):
    run = Run.create(tmp_path / "runs")
    run.write_jsonl("vulns.jsonl", [
        {"device_id": "m1", "device_name": "d1", "vendor": "x", "product": "y", "version": "1.0", "cve_id": "CVE-2026-1", "severity": "High", "cvss": 7.5, "exploitability": "NoExploit", "first_seen": "2026-07-16", "recommendation_ref": None},
    ])
    run.write_json("recommendations.json", [])
    now = datetime(2026, 9, 14, tzinfo=timezone.utc)  # 60 days after first_seen
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7), now=now)
    row = doc["products"][0]
    assert row["sla"] == {"oldest_days": 60, "overdue_cves": 1, "overdue_by_days": 30}
    assert doc["summary"]["sla_breaches"] == 1
    assert doc["summary"]["overdue_cves_total"] == 1


def test_sla_not_overdue_when_within_window(tmp_path):
    run = Run.create(tmp_path / "runs")
    run.write_jsonl("vulns.jsonl", [
        {"device_id": "m1", "device_name": "d1", "vendor": "x", "product": "y", "version": "1.0", "cve_id": "CVE-2026-1", "severity": "High", "cvss": 7.5, "exploitability": "NoExploit", "first_seen": "2026-09-01", "recommendation_ref": None},
    ])
    run.write_json("recommendations.json", [])
    now = datetime(2026, 9, 14, tzinfo=timezone.utc)  # 13 days after first_seen; High SLA is 30 days
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7), now=now)
    row = doc["products"][0]
    assert row["sla"]["overdue_cves"] == 0 and row["sla"]["overdue_by_days"] == 0
    assert doc["summary"]["sla_breaches"] == 0


def test_fix_rollup_in_row(tmp_path):
    run = seed(tmp_path / "runs")
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    top = doc["products"][0]
    assert top["product"] == "Connect Secure"
    assert top["fixes"][0]["update"] == "22.7R2.5"
    assert top["fixes"][0]["cves"] == 2
    assert top["fixes"][0]["share"] == 1.0


def test_eos_in_row_and_summary(tmp_path):
    run = seed(tmp_path / "runs")
    run.write_json("hunt-product-versions.json", {"results": [
        {"SoftwareVendor": "ivanti", "SoftwareName": "connect_secure", "SoftwareVersion": "22.7R2.0", "EndOfSupportStatus": "EndOfSupportSoftware", "EndOfSupportDate": "2025-01-01", "Devices": 1},
    ]})
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    top = doc["products"][0]
    assert top["eos"] == {"status": "EndOfSupportSoftware", "date": "2025-01-01", "versions": ["22.7R2.0"]}
    assert doc["summary"]["eos_products"] == 1


def test_top_n_listed_even_below_threshold(tmp_path):
    from dva.config import Scoring, load_scoring
    run = seed(tmp_path / "runs")
    cfg = load_scoring()
    cfg.report_threshold = 95  # nothing clears this
    doc = compute(run, cfg, IntelCache(tmp_path / "cache", 7))
    assert doc["summary"]["products_action"] == 0
    assert len(doc["products"]) == 2 and doc["products"][0]["rank"] == 1
