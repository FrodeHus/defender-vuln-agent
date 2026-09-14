import json
from datetime import datetime, timezone
from tests.test_rollup import seed
from dva.run import Run
from dva.score_cmd import compute, score_trend
from dva.config import load_scoring
from dva.cache import IntelCache
from dva.scoring import CveIntel
from dva import exceptions as exceptions_mod


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


def test_advisories_carried_from_intel_for_top_driving_cve(tmp_path):
    run = seed(tmp_path / "runs")
    cache = IntelCache(tmp_path / "cache", 7)
    advisories = [{"source": "Red Hat", "severity": "Important", "label": "update", "id": "RHSA-2026:1234",
                   "date": "2026-09-05", "url": "https://access.redhat.com/errata/RHSA-2026:1234"}]
    cache.put("CVE-2026-21887", CveIntel(cvss=9.8, kev=True, exploit_public=True, advisories=advisories))
    run.write_json("exposure.json", {"score": 54.0, "by_group": {}})
    doc = compute(run, load_scoring(), cache)
    top = doc["products"][0]
    assert top["advisories"] == advisories


def test_advisories_empty_when_top_driving_cve_has_no_intel(tmp_path):
    run = seed(tmp_path / "runs")
    cache = IntelCache(tmp_path / "cache", 7)
    run.write_json("exposure.json", {"score": 54.0, "by_group": {}})
    doc = compute(run, load_scoring(), cache)
    assert doc["products"][0]["advisories"] == []


def test_fixed_cves_excludes_ones_removed_by_active_exception(tmp_path, monkeypatch):
    run = seed(tmp_path / "runs")
    prev_dir = tmp_path / "runs" / "20200101T000000Z"
    prev_dir.mkdir()
    prev_dir.joinpath("manifest.json").write_text('{"run_id": "20200101T000000Z", "sources": {}}')
    prev_dir.joinpath("findings.json").write_text(json.dumps({
        "summary": {"exposure_score": 61.0},
        "products": [{
            "key": "ivanti/connect-secure", "rank": 1, "flags": {"kev": False},
            "all_cves": ["CVE-2026-21887", "CVE-2099-99999"],
            "driving_cves": [{"id": "CVE-2026-21887", "severity": "Critical"}, {"id": "CVE-2099-99999", "severity": "High"}],
        }],
    }))
    monkeypatch.setenv("DVA_TENANT_DIR", str(tmp_path / "tenant"))
    exceptions_mod.save(exceptions_mod.path_for_current(), [
        exceptions_mod.Exception_(product=None, cve="CVE-2026-21887", reason="accepted", until="2099-01-01",
                                   owner="me", added="2026-01-01", source="user"),
    ])
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    fixed = doc["diff_from_previous"]["fixed_cves"]
    # CVE-2026-21887 is gone from the current run only because it's excepted, not patched.
    assert fixed["critical"] == 0
    # CVE-2099-99999 is genuinely absent (not on this product at all): a real fix.
    assert fixed["high"] == 1


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


def test_posture_from_certificates_and_config_findings(tmp_path):
    run = seed(tmp_path / "runs")
    run.write_json("hunt-certificates.json", {"results": [
        {"Thumbprint": "ABC123", "FriendlyName": "vpn-gw-01 cert", "IssuedTo": "vpn-gw-01.contoso.com", "Exp": "2026-09-20T00:00:00Z", "Devices": 1},
    ]})
    run.write_json("hunt-config-findings.json", {"results": [
        {"ConfigurationId": "scid-1", "ConfigurationCategory": "Security controls", "ConfigurationSubcategory": "Firewall", "ConfigurationImpact": 8, "Devices": 5},
        {"ConfigurationId": "scid-2", "ConfigurationCategory": "Application", "ConfigurationSubcategory": "Browser", "ConfigurationImpact": 5, "Devices": 2},
        {"ConfigurationId": "scid-3", "ConfigurationCategory": "Application", "ConfigurationSubcategory": "Browser", "ConfigurationImpact": 1, "Devices": 1},
    ]})
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    posture = doc["posture"]
    assert posture["certificates_expiring"] == [{"thumbprint": "ABC123", "name": "vpn-gw-01 cert", "issued_to": "vpn-gw-01.contoso.com", "expires": "2026-09-20T00:00:00Z", "devices": 1}]
    assert posture["config_findings"][0] == {"id": "scid-1", "category": "Security controls", "subcategory": "Firewall", "impact": 8, "devices": 5}
    assert posture["config_by_impact"] == {"high": 1, "medium": 1, "low": 1}


def test_posture_defaults_to_empty_lists_when_no_hunt_files(tmp_path):
    run = seed(tmp_path / "runs")
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    assert doc["posture"] == {"certificates_expiring": [], "config_findings": [], "config_by_impact": {"high": 0, "medium": 0, "low": 0}}


def test_patched_7d_grouped_by_product_from_vuln_changes(tmp_path):
    run = seed(tmp_path / "runs")
    run.write_jsonl("vuln-changes.jsonl", [
        {"device_id": "m1", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.5", "cve_id": "CVE-2026-21887", "severity": "Critical", "status": "Fixed", "event_time": "2026-09-13T00:00:00Z"},
        {"device_id": "m2", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.5", "cve_id": "CVE-2026-20124", "severity": "Critical", "status": "Fixed", "event_time": "2026-09-13T00:00:00Z"},
        {"device_id": "m1", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.5", "cve_id": "CVE-2025-46512", "severity": "High", "status": "Fixed", "event_time": "2026-09-13T00:00:00Z"},
        {"device_id": "m2", "vendor": "adobe", "product": "acrobat_reader_dc", "version": "24.003", "cve_id": "CVE-2026-99999", "severity": "Medium", "status": "New", "event_time": "2026-09-13T00:00:00Z"},
    ])
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    ics = next(r for r in doc["products"] if r["key"] == "ivanti/connect-secure")
    assert ics["patched_7d"] == {"critical": 2, "high": 1, "cves": ["CVE-2026-21887", "CVE-2026-20124"]}
    adobe = next(r for r in doc["products"] if r["key"] == "adobe/acrobat-reader-dc")
    assert adobe["patched_7d"] is None  # only a "New" row, not Fixed
    assert doc["summary"]["patched_7d_critical"] == 2


def test_score_trend_from_two_runs_file_based(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    prev_dir = runs_dir / "20200101T000000Z"
    prev_dir.mkdir()
    prev_dir.joinpath("manifest.json").write_text('{"run_id": "20200101T000000Z", "sources": {}}')
    prev_dir.joinpath("findings.json").write_text(
        '{"summary": {"generated_at": "2026-01-01T00:00:00+00:00", "exposure_score": 40.0, "secure_score": 55.0}, "products": []}'
    )
    run.write_json("exposure.json", {"score": 54.0, "by_group": {}, "secure_score": 70.0})
    now = datetime(2026, 9, 14, tzinfo=timezone.utc)
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7), now=now)
    st = doc["score_trend"]
    assert len(st) == 2
    assert st[0] == {"run_id": "20200101T000000Z", "generated_at": "2026-01-01T00:00:00+00:00", "exposure_score": 40.0, "secure_score": 55.0}
    assert st[1]["run_id"] == run.id and st[1]["exposure_score"] == 54.0 and st[1]["secure_score"] == 70.0


def test_score_trend_excludes_rows_older_than_365_days(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    old_dir = runs_dir / "20200101T000000Z"
    old_dir.mkdir()
    old_dir.joinpath("manifest.json").write_text('{"run_id": "20200101T000000Z", "sources": {}}')
    old_dir.joinpath("findings.json").write_text(
        '{"summary": {"generated_at": "2020-01-01T00:00:00+00:00", "exposure_score": 10.0, "secure_score": 10.0}, "products": []}'
    )
    now = datetime(2026, 9, 14, tzinfo=timezone.utc)
    current_row = {"run_id": run.id, "generated_at": now.isoformat(), "exposure_score": 54.0, "secure_score": 70.0}
    st = score_trend(run, current_row, store=None, now=now)
    assert len(st) == 1 and st[0]["run_id"] == run.id
