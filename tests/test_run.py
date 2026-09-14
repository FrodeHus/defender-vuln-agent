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
