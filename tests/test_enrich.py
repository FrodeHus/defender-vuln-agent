from __future__ import annotations
import json
import pytest
from dva.cache import IntelCache
from dva.config import load_scoring
from dva.enrich import select_candidates, parse_store
from dva.errors import DvaError
from dva.model import Asset, CveRef, Product
from dva.scoring import CveIntel

cfg = load_scoring()


def ref(i, cvss, expl="NoExploit", fs="2026-01-01"):
    return CveRef(id=f"CVE-{i}", severity="High", cvss=cvss, exploitability=expl, first_seen=fs)


def test_cache_ttl(tmp_path):
    c = IntelCache(tmp_path, ttl_days=7)
    assert c.get("CVE-1") is None
    c.put("CVE-1", CveIntel(cvss=9.0, kev=True))
    assert c.get("CVE-1").kev is True
    stale = json.loads((tmp_path / "CVE-1.json").read_text())
    stale["fetched_at"] = "2020-01-01T00:00:00+00:00"
    (tmp_path / "CVE-1.json").write_text(json.dumps(stale))
    assert c.get("CVE-1") is None


def test_select_top_per_product_and_caps(tmp_path):
    cache = IntelCache(tmp_path, 7)
    # Controller ruling: all six CVEs on the hot product carry ExploitIsInKit so the
    # product's preliminary score clears report_threshold (NoExploit scores ~27, below 40).
    hot = Product(
        key="a/b", vendor="a", name="b", asset_ids={"x"},
        cves={f"CVE-{i}": ref(i, 9.0 - i * 0.1, "ExploitIsInKit") for i in range(6)},
    )
    cold = Product(key="c/d", vendor="c", name="d", asset_ids={"y"}, cves={"CVE-99": ref(99, 2.0)})
    assets = {"x": Asset(id="x", name="x", internet_facing=True, tags=["Tier0"]), "y": Asset(id="y", name="y")}
    cache.put("CVE-0", CveIntel(cvss=9.0))
    ids = select_candidates({"a/b": hot, "c/d": cold}, assets, cache, cfg, estate_size=10)
    # top 3 by cvss: CVE-0 (cached, skipped), CVE-1, CVE-2 ; cold product below threshold is excluded
    assert ids == ["CVE-1", "CVE-2"]


def test_cache_get_corrupt_entry_is_a_miss(tmp_path):
    c = IntelCache(tmp_path, ttl_days=7)
    (tmp_path / "CVE-9.json").write_text("{not valid json")
    assert c.get("CVE-9") is None


def test_cache_get_bad_fetched_at_is_a_miss(tmp_path):
    c = IntelCache(tmp_path, ttl_days=7)
    (tmp_path / "CVE-9.json").write_text(json.dumps({"cvss": 9.0, "fetched_at": "not-a-date"}))
    assert c.get("CVE-9") is None


def test_store_non_json_file_exits_cleanly(tmp_path, monkeypatch, capsys):
    from dva.__main__ import main
    from dva.run import Run

    runs_dir = tmp_path / "runs"
    run = Run.create(runs_dir)
    run.write_json("machines.json", [])
    run.write_jsonl("vulns.jsonl", [])
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))

    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    rc = main(["enrich", "--run", str(run.dir), "--store", str(bad)])
    assert rc == 1
    err = capsys.readouterr().err
    assert err.startswith("dva:") and "not valid JSON" in err


def test_parse_store_rejects_unrecognized_shape():
    with pytest.raises(DvaError):
        parse_store(42)


def test_parse_store_normalizes_bulk_shape():
    payload = {
        "results": [
            {
                "cve_id": "CVE-2026-1",
                "cvss_v3_score": 9.8,
                "epss_score": 0.9,
                "epss_percentile": 0.99,
                "in_kev": True,
                "exploits": [{"source": "exploit-db"}],
                "description": "Remote code execution in thing",
            }
        ]
    }
    out = parse_store(payload)
    i = out["CVE-2026-1"]
    assert i.cvss == 9.8 and i.kev and i.exploit_public and i.exploit_sources == ["exploit-db"] and i.title.startswith("Remote code")
