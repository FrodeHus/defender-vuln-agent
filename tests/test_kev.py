"""CISA KEV catalogue: fetched once, cached per tenant, matched against every CVE in the estate."""
import json
import os
from pathlib import Path

from dva import kev
from dva.scoring import CveIntel

FX = Path(__file__).parent / "fixtures" / "kev" / "catalog.json"


def test_parse_keeps_dates_and_ransomware_flag():
    cat = kev.parse(json.loads(FX.read_text()))
    assert set(cat) == {"CVE-2026-21887", "CVE-2026-24433", "CVE-2020-0001"}
    assert cat["CVE-2026-21887"] == {"date_added": "2026-09-08", "due_date": "2026-09-29", "ransomware": True, "name": "Ivanti Connect Secure Unauthenticated RCE"}
    assert cat["CVE-2026-24433"]["ransomware"] is False


def test_refresh_from_fixture_writes_the_cache_and_load_reads_it(tmp_path, monkeypatch):
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))
    cat = kev.refresh(fixture=FX)
    assert len(cat) == 3 and (tmp_path / "cache" / "kev.json").exists()
    assert kev.load() == cat
    assert kev.age_hours() is not None and kev.age_hours() < 1


def test_load_is_empty_without_a_cache_or_when_sources_disable_it(tmp_path, monkeypatch):
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))
    assert kev.load() == {}
    kev.refresh(fixture=FX)
    tenant_dir = tmp_path / "tenant"; tenant_dir.mkdir()
    (tenant_dir / "sources.yaml").write_text("kev: false\n")
    monkeypatch.setenv("DVA_TENANT_DIR", str(tenant_dir))
    assert kev.load() == {}


def test_apply_marks_every_estate_cve_in_the_catalogue():
    cat = kev.parse(json.loads(FX.read_text()))
    intel = {"CVE-2026-21887": CveIntel(cvss=9.8, epss=0.9)}
    n = kev.apply(intel, cat, {"CVE-2026-21887", "CVE-2026-24433", "CVE-2025-46512"})
    assert n == 2
    assert intel["CVE-2026-21887"].kev and intel["CVE-2026-21887"].ransomware and intel["CVE-2026-21887"].epss == 0.9
    assert intel["CVE-2026-24433"].kev and intel["CVE-2026-24433"].kev_added == "2026-09-10" and not intel["CVE-2026-24433"].ransomware
    assert "CVE-2025-46512" not in intel and "CVE-2020-0001" not in intel


def test_kev_cli_with_fixture_records_the_source_on_the_run(tmp_path, monkeypatch, capsys):
    from dva.__main__ import main
    from dva.run import Run
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))
    run = Run.create(tmp_path / "runs")
    run.write_jsonl("vulns.jsonl", [{"device_id": "m1", "device_name": "d", "vendor": "ivanti", "product": "connect_secure", "version": "1", "cve_id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "exploitability": "NoExploit", "first_seen": "2026-09-08", "recommendation_ref": None}])
    assert main(["kev", "--fixture", str(FX), "--run", str(run.dir)]) == 0
    out = capsys.readouterr().out
    assert "KEV catalogue: 3 entries (released 2026-09-14); 1 CVE in this estate is listed" in out
    assert Run.open(run.dir).manifest["sources"]["kev"] == {"status": "ok", "count": 1, "error": None}
