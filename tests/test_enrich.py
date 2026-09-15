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
    c.store.touch_intel("CVE-1", "2020-01-01T00:00:00+00:00")
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


def test_select_candidates_uses_enrich_threshold_not_report_threshold(tmp_path):
    # Five NoExploit CVSS 9.8 CVEs on a plain (non-tagged, non-internet-facing) device: the
    # preliminary (no-intel) score lands well below report_threshold (40) but above
    # enrich_threshold (20), so the product must still be selected for enrichment.
    cache = IntelCache(tmp_path, 7)
    plain = Product(
        key="a/b", vendor="a", name="b", asset_ids={"x"},
        cves={f"CVE-{i}": ref(i, 9.8, "NoExploit") for i in range(5)},
    )
    assets = {"x": Asset(id="x", name="x")}
    ids = select_candidates({"a/b": plain}, assets, cache, cfg, estate_size=10)
    assert set(ids) == {"CVE-0", "CVE-1", "CVE-2"}


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


def test_parse_store_coerces_untyped_numeric_fields():
    payload = {
        "results": [
            {
                "cve_id": "CVE-2026-2",
                "cvss_v3_score": "9.8",
                "epss_score": "0.91",
                "epss_percentile": "not-a-number",
            }
        ]
    }
    out = parse_store(payload)
    i = out["CVE-2026-2"]
    assert i.cvss == 9.8 and isinstance(i.cvss, float)
    assert i.epss == 0.91 and isinstance(i.epss, float)
    assert i.epss_percentile is None

    from dva.model import Asset, Product
    from dva.scoring import product_score

    p = Product(key="a/b", vendor="a", name="b", asset_ids={"x"}, cves={"CVE-2026-2": ref(0, 9.8)})
    assets = {"x": Asset(id="x", name="x")}
    product_score(p, assets, {"CVE-2026-2": i}, cfg, estate_size=10)


# --- cve-mcp text formats (fixtures captured from the real server) ---
from pathlib import Path as _P
from dva.enrich import parse_text, parse_file
_FX = _P(__file__).parent / "fixtures" / "cve"


def test_parse_triage_standard_text():
    intel = parse_file(_FX / "triage-standard.txt")["CVE-2024-6345"]
    assert intel.cvss == 8.8 and abs(intel.epss - 0.0194) < 1e-9 and abs(intel.epss_percentile - 0.79) < 1e-9
    assert intel.kev is False and intel.exploit_public is False


def test_parse_triage_with_kev_and_poc():
    text = (_FX / "triage-standard.txt").read_text().replace("KEV:    NO", "KEV:    YES").replace(
        "PoC:    NONE (No public PoC found) — 0 public source(s)", "PoC:    HIGH (Exploit-DB) — 2 public source(s)")
    intel = parse_text(text)["CVE-2024-6345"]
    assert intel.kev is True and intel.exploit_public is True and intel.exploit_sources == ["poc"]


def test_parse_compare_epss_lookup_kev_poc_and_merge():
    text = "\n".join((_FX / n).read_text() for n in ["compare.txt", "epss.txt", "lookup.txt", "kev.txt", "poc.txt"])
    out = parse_text(text)
    a = out["CVE-2023-0286"]
    assert a.cvss == 7.4 and abs(a.epss - 0.595) < 1e-9 and abs(a.epss_percentile - 0.991) < 1e-9
    assert a.kev is False and a.exploit_public is False and a.cwe == "CWE-843" and a.title.startswith("There is a type confusion")
    assert "CVE-2024-6345" in out


def test_parse_file_rejects_unrecognized_text(tmp_path):
    p = tmp_path / "x.txt"; p.write_text("nothing useful here\n")
    with pytest.raises(DvaError, match="no CVE data recognized"):
        parse_file(p)


def test_store_accepts_multiple_text_files(tmp_path, monkeypatch, capsys):
    from dva.__main__ import main
    from dva.run import Run
    run = Run.create(tmp_path / "runs")
    run.write_json("machines.json", [{"id": "m1", "name": "h", "tags": [], "exposure_level": None, "device_value": None, "group": None, "is_internet_facing": None, "azure_resource_id": None}])
    run.write_jsonl("vulns.jsonl", [{"device_id": "m1", "device_name": "h", "vendor": "v", "product": "p", "version": "1", "cve_id": "CVE-2024-6345", "severity": "High", "cvss": 8.8, "exploitability": "NoExploit", "first_seen": None, "recommendation_ref": None}])
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))
    rc = main(["enrich", "--store", str(_FX / "triage-standard.txt"), str(_FX / "epss.txt"), "--run", str(run.dir)])
    assert rc == 0 and "stored 2" in capsys.readouterr().out


def test_lookup_text_yields_description_and_vector():
    out = parse_file(_FX / "lookup.txt")["CVE-2023-0286"]
    assert out.description.startswith("There is a type confusion vulnerability") and len(out.description) <= 600
    assert "X.400" in out.description and out.vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H"
    tri = parse_file(_FX / "triage-standard.txt")["CVE-2024-6345"]
    assert tri.vector == "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"


def test_parse_triage_kev_maturity_and_ransomware():
    i = parse_file(_FX / "triage-kev.txt")["CVE-2021-44228"]
    assert i.kev and i.ransomware and i.exploit_maturity == 1.0 and i.exploit_public and i.kev_added == "2021-12-10"


def test_parse_kev_yes_and_poc_yes_and_exploit_availability():
    out = parse_text("\n".join((_FX / n).read_text() for n in ["kev-yes.txt", "poc-yes.txt", "exploit-availability.txt"]))["CVE-2021-44228"]
    assert out.kev and out.ransomware and out.kev_added == "2021-12-10" and out.exploit_maturity == 1.0


def test_parse_advisories():
    adv = parse_file(_FX / "advisory.txt")["CVE-2021-44228"].advisories
    assert adv[0]["source"] == "Microsoft MSRC" and adv[0]["url"] == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-44228"
    rh = [a for a in adv if a["source"] == "Red Hat Security"][0]
    assert rh["id"].startswith("RHSA-2021:") and rh["url"] == f"https://access.redhat.com/errata/{rh['id']}" and rh["severity"] == "Critical" and rh["date"] == "2021-12-14"
    assert len(adv) <= 5


def test_store_merges_with_existing_cache_entry_instead_of_replacing_it(tmp_path, monkeypatch, capsys):
    """A later --store of a partial result (e.g. advisories only) must not wipe out CVSS/EPSS/KEV
    already cached for the same CVE from an earlier --store call."""
    from dva.__main__ import main
    from dva.run import Run
    from dva.cache import IntelCache

    run = Run.create(tmp_path / "runs")
    run.write_json("machines.json", [])
    run.write_jsonl("vulns.jsonl", [])
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))

    rc = main(["enrich", "--store", str(_FX / "triage-kev.txt"), "--run", str(run.dir)])
    assert rc == 0
    cache = IntelCache(tmp_path / "cache" / "cve", 7)
    before = cache.get("CVE-2021-44228")
    assert before.cvss is not None and before.kev is True

    capsys.readouterr()
    rc = main(["enrich", "--store", str(_FX / "advisory.txt"), "--run", str(run.dir)])
    assert rc == 0
    cache = IntelCache(tmp_path / "cache" / "cve", 7)
    after = cache.get("CVE-2021-44228")
    assert after.advisories  # newly stored
    assert after.cvss == before.cvss and after.kev is True and after.ransomware is True  # preserved


def test_list_prints_describe_ids(tmp_path, monkeypatch, capsys):
    from dva.__main__ import main
    from dva.run import Run
    run = Run.create(tmp_path / "runs")
    run.write_json("machines.json", [{"id": "m1", "name": "h", "tags": ["Tier0"], "exposure_level": "High", "device_value": "High", "group": None, "is_internet_facing": True, "azure_resource_id": None}])
    run.write_jsonl("vulns.jsonl", [
        {"device_id": "m1", "device_name": "h", "vendor": "v", "product": "p", "version": "1", "cve_id": "CVE-2024-0001", "severity": "Critical", "cvss": 9.8, "exploitability": "ExploitIsInKit", "first_seen": None, "recommendation_ref": None},
        {"device_id": "m1", "device_name": "h", "vendor": "v", "product": "p", "version": "1", "cve_id": "CVE-2024-0002", "severity": "High", "cvss": 7.0, "exploitability": "NoExploit", "first_seen": None, "recommendation_ref": None}])
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))
    assert main(["enrich", "--list", "--run", str(run.dir)]) == 0
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]
    assert any("describe" in l and l["describe"] == ["CVE-2024-0001", "CVE-2024-0002"] for l in lines)
    assert run.read_json("enrich-describe.json") == ["CVE-2024-0001", "CVE-2024-0002"]


def test_cache_get_stale_ok_returns_an_expired_entry(tmp_path):
    c = IntelCache(tmp_path, ttl_days=7)
    c.put("CVE-1", CveIntel(cvss=9.0, description="old but still true"))
    c.store.touch_intel("CVE-1", "2020-01-01T00:00:00+00:00")
    assert c.get("CVE-1") is None
    assert c.get("CVE-1", stale_ok=True).description == "old but still true"


def test_select_describe_trusts_a_stale_description(tmp_path):
    """Descriptions never change, so an expired cache entry that has one still spares the lookup_cve call."""
    from dva.enrich import select_describe
    cache = IntelCache(tmp_path, 7)
    p = Product(key="a/b", vendor="a", name="b", asset_ids={"x"}, cves={"CVE-5": ref(5, 9.8, "ExploitIsInKit")})
    assets = {"x": Asset(id="x", name="x", internet_facing=True)}
    cache.put("CVE-5", CveIntel(cvss=9.8, description="desc"))
    cache.store.touch_intel("CVE-5", "2020-01-01T00:00:00+00:00")
    assert select_describe({"a/b": p}, assets, cache, cfg, estate_size=1) == []
    cache.put("CVE-5", CveIntel(cvss=9.8))  # fresh, but without a description: still needs one
    assert select_describe({"a/b": p}, assets, cache, cfg, estate_size=1) == ["CVE-5"]


def test_store_refreshes_volatile_signals_but_keeps_stable_fields_of_a_stale_entry(tmp_path, monkeypatch, capsys):
    """Re-triaging an expired CVE must take the new EPSS/KEV/PoC signals and keep the description,
    vector, CWE and advisories that were fetched once and never change."""
    from dva.__main__ import main
    from dva.run import Run
    run = Run.create(tmp_path / "runs")
    run.write_json("machines.json", [])
    run.write_jsonl("vulns.jsonl", [])
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))
    cache = IntelCache(tmp_path / "cache" / "cve", 7)
    cache.put("CVE-2024-6345", CveIntel(cvss=8.8, epss=0.5, kev=True, ransomware=True, exploit_public=True, exploit_sources=["poc"],
                                        description="Stable description", cwe="CWE-94", advisories=[{"source": "MSRC", "id": "x"}]))
    cache.store.touch_intel("CVE-2024-6345", "2020-01-01T00:00:00+00:00")
    cache.close()
    assert main(["enrich", "--store", str(_FX / "triage-standard.txt"), "--run", str(run.dir)]) == 0
    after = IntelCache(tmp_path / "cache" / "cve", 7).get("CVE-2024-6345")
    assert after is not None  # fresh again
    assert after.epss == 0.0194 and after.kev is False and after.ransomware is False and after.exploit_public is False
    assert after.description == "Stable description" and after.cwe == "CWE-94" and after.advisories == [{"source": "MSRC", "id": "x"}]
    assert after.vector == "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"


def test_select_describe_covers_every_driving_cve_of_a_product(tmp_path):
    """All enrich_top_per_product (3) CVEs that drive a product's score get a description, not just the top one."""
    from dva.enrich import select_describe
    cache = IntelCache(tmp_path, 7)
    p = Product(key="a/b", vendor="a", name="b", asset_ids={"x"},
                cves={f"CVE-{i}": ref(i, 9.8 - i * 0.1, "ExploitIsInKit") for i in range(5)})
    assets = {"x": Asset(id="x", name="x", internet_facing=True)}
    cache.put("CVE-1", CveIntel(cvss=9.7, description="already described"))
    assert select_describe({"a/b": p}, assets, cache, cfg, estate_size=1) == ["CVE-0", "CVE-2"]
