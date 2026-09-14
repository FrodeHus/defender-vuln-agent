import json
from dva.run import Run

def test_create_and_manifest(tmp_path):
    r = Run.create(tmp_path)
    assert r.dir.exists() and r.manifest["run_id"] == r.id
    r.set_source("mde.machines", "ok", count=3)
    r.write_json("a.json", {"x": 1})
    n = r.write_jsonl("b.jsonl", [{"i": 1}, {"i": 2}])
    assert n == 2 and list(r.read_jsonl("b.jsonl")) == [{"i": 1}, {"i": 2}]
    m = json.loads((r.dir / "manifest.json").read_text())
    assert m["sources"]["mde.machines"] == {"status": "ok", "count": 3, "error": None}

def test_latest_and_previous(tmp_path):
    a = Run.create(tmp_path)
    (tmp_path / "20260101T000000Z").mkdir(); (tmp_path / "20260101T000000Z" / "manifest.json").write_text('{"run_id": "20260101T000000Z", "sources": {}}')
    latest = Run.latest(tmp_path)
    assert latest.id == a.id  # a was created now, which sorts after 2026-01-01
    prev = Run.latest(tmp_path, before=a.id)
    assert prev.id == "20260101T000000Z"

def test_summary_prints_and_records(tmp_path, capsys):
    r = Run.create(tmp_path)
    r.summary("machines: 3 collected")
    assert "machines: 3" in capsys.readouterr().out
    assert "machines: 3" in (r.dir / "summary.txt").read_text()

def test_rapid_creation_retries(tmp_path):
    runs = [Run.create(tmp_path) for _ in range(20)]
    ids = [r.id for r in runs]
    assert len(ids) == len(set(ids)), "all ids should be unique"
    assert all(r.dir.exists() for r in runs), "all directories should exist"

def test_open_corrupt_manifest(tmp_path):
    from dva.errors import DvaError
    import pytest
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text("{invalid json")
    with pytest.raises(DvaError, match="corrupt manifest"):
        Run.open(run_dir)

def test_latest_skips_corrupt_manifest(tmp_path):
    # Create a valid run
    valid_run = Run.create(tmp_path)
    # Create a corrupt manifest in another directory
    corrupt_dir = tmp_path / "20260101T000000Z"
    corrupt_dir.mkdir()
    (corrupt_dir / "manifest.json").write_text("{invalid json")
    # latest should return the valid run, not fail
    latest = Run.latest(tmp_path)
    assert latest.id == valid_run.id
