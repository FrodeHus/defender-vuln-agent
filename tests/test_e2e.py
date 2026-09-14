import json, os, subprocess, sys
from pathlib import Path

FX = Path(__file__).parent / "fixtures"


def dva(*args, env):
    r = subprocess.run([sys.executable, "-m", "dva", *args], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr + r.stdout
    return r.stdout


def test_offline_pipeline(tmp_path):
    env = dict(os.environ, DVA_RUNS_DIR=str(tmp_path / "runs"), DVA_CACHE_DIR=str(tmp_path / "cache"))
    run_dir = dva("run", "new", env=env).strip(); env["DVA_RUN"] = run_dir
    dva("mde", "all", "--fixture", str(FX / "mde" / "all.json"), env=env)
    dva("hunt", "internet-facing", "--fixture", str(FX / "hunting" / "internet-facing.json"), env=env)
    listing = dva("enrich", "--list", env=env)
    chunks = [json.loads(l) for l in listing.splitlines() if l.startswith("{")]
    assert chunks and "CVE-2026-21887" in chunks[0]["cve_ids"]
    dva("enrich", "--store", str(FX / "cve" / "bulk.json"), env=env)
    out = dva("score", env=env)
    assert "Connect Secure" in out
    dva("report", "--all", env=env)
    for f in ["findings.json", "report.md", "report.html", "report.json"]:
        assert (Path(run_dir) / f).exists()
    doc = json.loads((Path(run_dir) / "findings.json").read_text())
    assert doc["products"][0]["driving_cves"][0]["kev"] is True
