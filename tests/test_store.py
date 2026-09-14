from __future__ import annotations
import json
import stat

from dva.store import Store, open_store, open_intel_store
from dva.cache import IntelCache
from dva.config import Sources
from dva.run import Run
from dva.score_cmd import compute
from dva.config import load_scoring
from tests.test_rollup import seed


def test_store_creates_file_mode_600_in_dir(tmp_path):
    p = tmp_path / "sub" / "dva.sqlite"
    Store(p)
    assert p.exists()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700


def test_store_round_trip_intel_with_ttl(tmp_path):
    store = Store(tmp_path / "dva.sqlite")
    assert store.get_intel("CVE-2026-1") is None
    store.put_intel("CVE-2026-1", {"cvss": 9.8, "kev": True}, "2026-01-01T00:00:00+00:00")
    fields, fetched_at = store.get_intel("CVE-2026-1")
    assert fields == {"cvss": 9.8, "kev": True}
    assert fetched_at == "2026-01-01T00:00:00+00:00"
    # case-insensitive lookup
    fields2, _ = store.get_intel("cve-2026-1")
    assert fields2["cvss"] == 9.8


def test_touch_intel_rewrites_fetched_at_only(tmp_path):
    store = Store(tmp_path / "dva.sqlite")
    store.put_intel("CVE-2026-3", {"cvss": 4.0}, "2026-01-01T00:00:00+00:00")
    store.touch_intel("CVE-2026-3", "2020-01-01T00:00:00+00:00")
    fields, fetched_at = store.get_intel("CVE-2026-3")
    assert fields == {"cvss": 4.0}
    assert fetched_at == "2020-01-01T00:00:00+00:00"


def test_record_run_twice_upserts(tmp_path):
    store = Store(tmp_path / "dva.sqlite")
    store.record_run("r1", "tenant-x", {"generated_at": "2026-01-01T00:00:00Z", "exposure_score": 10.0}, [
        {"key": "a/b", "score": 50, "label": "high"},
    ])
    store.record_run("r1", "tenant-x", {"generated_at": "2026-01-02T00:00:00Z", "exposure_score": 20.0}, [
        {"key": "a/b", "score": 60, "label": "critical"},
    ])
    runs = store.recent_runs(5)
    assert len(runs) == 1
    assert runs[0]["run_id"] == "r1"
    assert runs[0]["exposure_score"] == 20.0
    history = store.product_history("a/b", 5)
    assert len(history) == 1
    assert history[0]["score"] == 60
    assert history[0]["label"] == "critical"


def test_recent_runs_oldest_first_newest_n(tmp_path):
    store = Store(tmp_path / "dva.sqlite")
    for i in range(1, 4):
        store.record_run(f"r{i}", "t", {"generated_at": f"2026-01-0{i}T00:00:00Z", "exposure_score": float(i)}, [])
    runs = store.recent_runs(2)
    assert [r["run_id"] for r in runs] == ["r2", "r3"]


def test_product_history_oldest_first_newest_n(tmp_path):
    store = Store(tmp_path / "dva.sqlite")
    for i in range(1, 4):
        store.record_run(f"r{i}", "t", {"generated_at": "x"}, [{"key": "a/b", "score": i * 10, "label": "l"}])
    history = store.product_history("a/b", 2)
    assert [h["run_id"] for h in history] == ["r2", "r3"]
    assert [h["score"] for h in history] == [20, 30]


def test_intel_cache_imports_legacy_json_once(tmp_path):
    d = tmp_path / "cve"
    d.mkdir()
    (d / "CVE-2026-1.json").write_text(json.dumps({"cvss": 7.5, "fetched_at": "2026-01-01T00:00:00+00:00"}))
    cache = IntelCache(d, 7)
    fields, fetched_at = cache.store.get_intel("CVE-2026-1")
    assert fields["cvss"] == 7.5
    assert fetched_at == "2026-01-01T00:00:00+00:00"


def test_intel_cache_import_skips_corrupt_legacy_file(tmp_path):
    d = tmp_path / "cve"
    d.mkdir()
    (d / "CVE-2026-2.json").write_text("{not valid json")
    cache = IntelCache(d, 7)
    assert cache.store.get_intel("CVE-2026-2") is None


def test_intel_cache_ignores_json_dropped_after_first_open(tmp_path):
    d = tmp_path / "cve"
    d.mkdir()
    cache = IntelCache(d, 7)  # first open: nothing to import yet
    (d / "CVE-2026-9.json").write_text(json.dumps({"cvss": 3.0, "fetched_at": "2026-01-01T00:00:00+00:00"}))
    # get()/put()/all_fresh() never read the filesystem: the store is the sole source of truth.
    assert cache.get("CVE-2026-9") is None
    assert cache.store.get_intel("CVE-2026-9") is None
    assert cache.all_fresh(["CVE-2026-9"]) == {}


def test_intel_cache_api_unchanged_for_existing_callers(tmp_path):
    from dva.scoring import CveIntel
    c = IntelCache(tmp_path, ttl_days=7)
    assert c.get("CVE-1") is None
    c.put("CVE-1", CveIntel(cvss=9.0, kev=True))
    assert c.get("CVE-1").kev is True
    assert c.all_fresh(["CVE-1", "CVE-2"]) .keys() == {"CVE-1"}


def test_shared_cve_cache_routes_intel_to_repo_level_file(tmp_path, monkeypatch):
    import dva.store as store_mod
    monkeypatch.setattr(store_mod, "ROOT", tmp_path / "repo")
    monkeypatch.setattr(store_mod, "load_sources", lambda: Sources(shared_cve_cache=True))
    tenant_a_dir = tmp_path / "tenants" / "a" / "cache" / "cve"
    tenant_b_dir = tmp_path / "tenants" / "b" / "cache" / "cve"
    store_a = open_intel_store(tenant_a_dir)
    store_a.put_intel("CVE-2026-5", {"cvss": 5.0}, "2026-01-01T00:00:00+00:00")
    store_b = open_intel_store(tenant_b_dir)
    fields, _ = store_b.get_intel("CVE-2026-5")
    assert fields["cvss"] == 5.0
    assert store_a.path == tmp_path / "repo" / ".cache" / "cve.sqlite"


def test_shared_cve_cache_false_keeps_intel_per_directory(tmp_path, monkeypatch):
    import dva.store as store_mod
    monkeypatch.setattr(store_mod, "load_sources", lambda: Sources(shared_cve_cache=False))
    store = open_intel_store(tmp_path / "cve")
    assert store.path == tmp_path / "cve" / "dva.sqlite"


def test_malformed_sources_yaml_routes_to_per_tenant_store_and_warns(tmp_path, monkeypatch, capsys):
    import dva.store as store_mod

    def _boom():
        raise TypeError("unexpected keyword argument 'bogus'")

    monkeypatch.setattr(store_mod, "load_sources", _boom)
    store = open_intel_store(tmp_path / "cve")
    assert store.path == tmp_path / "cve" / "dva.sqlite"
    err = capsys.readouterr().err
    assert "dva: sources.yaml unreadable" in err
    assert "using per-tenant intel store" in err


def test_open_store_runs_always_per_tenant_cache_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))
    store = open_store()
    assert store.path == tmp_path / "cache" / "dva.sqlite"


def _seed_previous(runs_dir, rid, exposure_score, products):
    d = runs_dir / rid
    d.mkdir(parents=True)
    d.joinpath("manifest.json").write_text(json.dumps({"run_id": rid, "sources": {}}))
    d.joinpath("findings.json").write_text(json.dumps({
        "summary": {"generated_at": "2026-01-01T00:00:00+00:00", "exposure_score": exposure_score,
                    "products_action": len(products), "kev_cves": 0, "sla_breaches": 0},
        "products": products,
    }))
    return Run(d)


def test_compute_trend_from_store_matches_file_scan(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    _seed_previous(runs_dir, "20200101T000000Z", 40.0, [
        {"key": "ivanti/connect-secure", "rank": 1, "flags": {"kev": False}, "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
         "all_cves": ["CVE-2026-21887", "CVE-2099-99999"],
         "driving_cves": [{"id": "CVE-2026-21887", "severity": "Critical"}, {"id": "CVE-2099-99999", "severity": "High"}]},
    ])
    run.write_json("exposure.json", {"score": 54.0, "by_group": {}})
    cache = IntelCache(tmp_path / "cache", 7)
    file_doc = compute(run, load_scoring(), cache)

    store = Store(tmp_path / "store.sqlite")
    store.record_run("20200101T000000Z", "tenant-x", {
        "generated_at": "2026-01-01T00:00:00+00:00", "exposure_score": 40.0,
        "products_action": 1, "kev_cves": 0, "sla_breaches": 0,
        "cves_by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0},
    }, [])
    store_doc = compute(run, load_scoring(), cache, store=store)
    # generated_at on the current (last) row is a live timestamp set independently by each
    # compute() call, so compare the stable previous-run rows and the rest of the current row.
    assert store_doc["trend"][:-1] == file_doc["trend"][:-1]
    assert {k: v for k, v in store_doc["trend"][-1].items() if k != "generated_at"} == \
           {k: v for k, v in file_doc["trend"][-1].items() if k != "generated_at"}


def test_compute_trend_falls_back_to_file_scan_when_store_has_no_rows(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    _seed_previous(runs_dir, "20200101T000000Z", 40.0, [])
    run.write_json("exposure.json", {"score": 54.0, "by_group": {}})
    cache = IntelCache(tmp_path / "cache", 7)
    file_doc = compute(run, load_scoring(), cache)
    empty_store = Store(tmp_path / "empty.sqlite")
    store_doc = compute(run, load_scoring(), cache, store=empty_store)
    assert store_doc["trend"][:-1] == file_doc["trend"][:-1]
    assert {k: v for k, v in store_doc["trend"][-1].items() if k != "generated_at"} == \
           {k: v for k, v in file_doc["trend"][-1].items() if k != "generated_at"}


def test_intel_rows_written_before_newer_fields_load_with_defaults(tmp_path):
    from datetime import datetime, timezone
    d = tmp_path / "cve"
    cache = IntelCache(d, 7)
    # A row from an older release lacks list-valued fields such as advisories/exploit_sources.
    cache.store.put_intel("CVE-2023-0286", {"cvss": 7.4, "kev": False}, datetime.now(timezone.utc).isoformat())
    intel = cache.get("CVE-2023-0286")
    assert intel is not None and intel.cvss == 7.4
    assert intel.advisories == [] and intel.exploit_sources == [] and intel.description is None
    cache.close()
