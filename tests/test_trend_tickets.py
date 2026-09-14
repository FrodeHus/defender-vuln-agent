import json
from pathlib import Path

from tests.test_rollup import seed
from dva.run import Run
from dva.score_cmd import compute, previous_runs
from dva.config import load_scoring
from dva.cache import IntelCache
from dva import report_tickets

FX = Path(__file__).parent / "fixtures" / "sample-run" / "findings.json"


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


def test_previous_runs_returns_newest_first_skips_corrupt(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    _seed_previous(runs_dir, "20200101T000000Z", 10.0, [])
    _seed_previous(runs_dir, "20200102T000000Z", 20.0, [])
    corrupt = runs_dir / "20200103T000000Z"
    corrupt.mkdir()
    corrupt.joinpath("manifest.json").write_text('{"run_id": "20200103T000000Z", "sources": {}}')
    corrupt.joinpath("findings.json").write_text("{not valid json")
    prevs = previous_runs(run, 8)
    ids = [r.id for r in prevs]
    assert ids == ["20200102T000000Z", "20200101T000000Z"]


def test_previous_runs_respects_n(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    for i in range(1, 5):
        _seed_previous(runs_dir, f"2020010{i}T000000Z", float(i), [])
    prevs = previous_runs(run, 2)
    assert [r.id for r in prevs] == ["20200104T000000Z", "20200103T000000Z"]


def test_trend_has_two_rows_oldest_first(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    _seed_previous(runs_dir, "20200101T000000Z", 40.0, [
        {"key": "ivanti/connect-secure", "rank": 1, "flags": {"kev": False}, "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
         "all_cves": ["CVE-2026-21887", "CVE-2099-99999"],
         "driving_cves": [{"id": "CVE-2026-21887", "severity": "Critical"}, {"id": "CVE-2099-99999", "severity": "High"}]},
    ])
    run.write_json("exposure.json", {"score": 54.0, "by_group": {}})
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    trend = doc["trend"]
    assert len(trend) == 2
    assert trend[0]["run_id"] == "20200101T000000Z"
    assert trend[1]["run_id"] == run.id
    assert trend[0]["exposure_score"] == 40.0
    assert trend[1]["exposure_score"] == 54.0
    for row in trend:
        for key in ("run_id", "generated_at", "exposure_score", "products_action", "kev_cves", "sla_breaches", "cves_by_severity"):
            assert key in row


def test_new_and_fixed_cves_by_severity(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    # previous run: has CVE-2099-99999 (High, fixed now) on connect-secure; missing CVE-2026-21887 (new now, Critical)
    _seed_previous(runs_dir, "20200101T000000Z", 40.0, [
        {"key": "ivanti/connect-secure", "rank": 1, "flags": {"kev": False}, "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
         "all_cves": ["CVE-2099-99999"],
         "driving_cves": [{"id": "CVE-2099-99999", "severity": "High"}]},
    ])
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    d = doc["diff_from_previous"]
    assert d["new_cves"]["critical"] >= 1  # CVE-2026-21887 is critical and newly seen for this product
    assert d["fixed_cves"]["high"] == 1  # CVE-2099-99999 no longer present, known High from previous driving_cves


def test_corrupt_previous_still_skipped_for_trend(tmp_path):
    runs_dir = tmp_path / "runs"
    run = seed(runs_dir)
    corrupt = runs_dir / "20200101T000000Z"
    corrupt.mkdir()
    corrupt.joinpath("manifest.json").write_text('{"run_id": "20200101T000000Z", "sources": {}}')
    corrupt.joinpath("findings.json").write_text("{not valid json")
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    assert len(doc["trend"]) == 1
    assert doc["trend"][0]["run_id"] == run.id


def test_tickets_render_one_per_listed_product_not_excepted():
    doc = json.loads(FX.read_text())
    out = report_tickets.render(doc)
    tickets = json.loads(out)
    assert len(tickets) == len(doc["products"])
    keys = {t["key"] for t in tickets}
    assert keys == {r["key"] for r in doc["products"]}
    top = next(t for t in tickets if t["key"] == "ivanti/connect-secure")
    assert top["priority"] == 1
    assert top["title"] == "Patch Connect Secure (Ivanti): Critical, 6 devices"
    assert "vuln" in top["labels"] and "critical" in top["labels"] and "kev" in top["labels"] and "internet-facing" in top["labels"]
    assert "CVE-2026-21887" in top["description"]
    assert top["product"] == "Connect Secure"
    assert top["tenant"] == "Contoso"
    assert top["run_id"] == "20260914T080000Z"


def test_tickets_render_is_sorted_keys_json():
    doc = json.loads(FX.read_text())
    out = report_tickets.render(doc)
    assert out == json.dumps(json.loads(out), indent=2, sort_keys=True)


def test_report_all_writes_tickets_json(tmp_path):
    run = seed(tmp_path / "runs")
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    run.write_json("findings.json", doc)
    from dva import report_cmd
    import argparse
    args = argparse.Namespace(run=str(run.dir), all=True, md=False, html=False, json=False, tickets=False)
    report_cmd._run(args)
    assert (run.dir / "tickets.json").exists()
    tickets = json.loads((run.dir / "tickets.json").read_text())
    assert isinstance(tickets, list) and len(tickets) >= 1
