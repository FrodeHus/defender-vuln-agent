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
    latest = Run.latest(tmp_path)
    assert latest.id == runs[-1].id, "latest should be the last created run"

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

def test_read_json_corrupt_raises_dva_error(tmp_path):
    from dva.errors import DvaError
    import pytest
    r = Run.create(tmp_path)
    (r.dir / "findings.json").write_text("{not valid json")
    with pytest.raises(DvaError, match="corrupt findings.json"):
        r.read_json("findings.json")

def test_runs_dir_option(tmp_path, capsys):
    from dva.__main__ import main
    result = main(["run", "new", "--runs-dir", str(tmp_path)])
    output = capsys.readouterr().out.strip()
    assert result == 0
    assert output.startswith(str(tmp_path)), f"output {output} should be under {tmp_path}"


def _mk(runs_dir, rid, manifest=True):
    d = runs_dir / rid; d.mkdir(parents=True)
    if manifest:
        (d / "manifest.json").write_text('{"run_id": "%s", "sources": {}}' % rid)
    return d


def test_prune_keeps_the_latest_run_per_day(tmp_path):
    from dva.run import prune
    for rid in ("20260910T080000000Z", "20260910T120000000Z", "20260911T070000000Z", "20260912T060000000Z", "20260912T090000000Z"):
        _mk(tmp_path, rid)
    _mk(tmp_path, "notes", manifest=False)
    kept, pruned = prune(tmp_path)
    assert kept == ["20260910T120000000Z", "20260911T070000000Z", "20260912T090000000Z"]
    assert pruned == ["20260910T080000000Z", "20260912T060000000Z"]


def test_prune_older_than_removes_whole_days_and_spares_the_active_run(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from dva.run import prune
    for rid in ("20260801T080000000Z", "20260910T080000000Z", "20260910T120000000Z"):
        _mk(tmp_path, rid)
    monkeypatch.setenv("DVA_RUN", str(tmp_path / "20260910T080000000Z"))
    kept, pruned = prune(tmp_path, older_than_days=30, now=datetime(2026, 9, 15, tzinfo=timezone.utc))
    assert pruned == ["20260801T080000000Z"] and kept == ["20260910T080000000Z", "20260910T120000000Z"]


def test_run_prune_cli_dry_run_then_delete(tmp_path, monkeypatch, capsys):
    from dva.__main__ import main
    from dva.store import Store
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("DVA_RUN", raising=False)
    runs = tmp_path / "runs"
    for rid in ("20260910T080000000Z", "20260910T120000000Z"):
        _mk(runs, rid)
        (runs / rid / "findings.json").write_text("{}")
    store = Store(tmp_path / "cache" / "dva.sqlite")
    for rid in ("20260910T080000000Z", "20260910T120000000Z"):
        store.record_run(rid, "t", {}, [])
    store.close()
    assert main(["run", "prune", "--runs-dir", str(runs), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would prune 1 run(s), keeping 1: 20260910T080000000Z" in out
    assert (runs / "20260910T080000000Z").exists()
    assert main(["run", "prune", "--runs-dir", str(runs)]) == 0
    out = capsys.readouterr().out
    assert "pruned 1 run(s), keeping 1: 20260910T080000000Z" in out
    assert not (runs / "20260910T080000000Z").exists() and (runs / "20260910T120000000Z" / "findings.json").exists()
    assert [r["run_id"] for r in Store(tmp_path / "cache" / "dva.sqlite").recent_runs(10)] == ["20260910T120000000Z"]
