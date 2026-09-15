"""`dva enrich --fetch` selects the candidate CVEs and calls the CVE server itself, so no CVE text passes through the agent."""
import json
import os
import subprocess
import sys
from pathlib import Path

FX = Path(__file__).parent / "fixtures"
FAKE = f"{sys.executable} {Path(__file__).parent / 'fake_mcp_server.py'}"


def dva(*args, env, ok=True):
    r = subprocess.run([sys.executable, "-m", "dva", *args], capture_output=True, text=True, env=env)
    if ok:
        assert r.returncode == 0, r.stderr + r.stdout
    return r


def _collected_run(tmp_path, **extra):
    tenant_dir = tmp_path / "tenant"; tenant_dir.mkdir()
    env = dict(os.environ, DVA_RUNS_DIR=str(tmp_path / "runs"), DVA_CACHE_DIR=str(tmp_path / "cache"),
               DVA_TENANT_DIR=str(tenant_dir), DVA_CVE_MCP=FAKE)
    env.update(extra)
    run_dir = dva("run", "new", env=env).stdout.strip(); env["DVA_RUN"] = run_dir
    dva("mde", "all", "--fixture", str(FX / "mde" / "all.json"), env=env)
    dva("hunt", "internet-facing", "--fixture", str(FX / "hunting" / "internet-facing.json"), env=env)
    return Path(run_dir), env


def test_fetch_calls_the_server_and_stores_the_results(tmp_path):
    run_dir, env = _collected_run(tmp_path)
    r = dva("enrich", "--fetch", env=env)
    candidates = json.loads((run_dir / "enrich-candidates.json").read_text())
    describe = json.loads((run_dir / "enrich-describe.json").read_text())
    assert candidates and describe
    for cid in candidates:
        assert (run_dir / f"cve-triage-{cid}.txt").read_text().startswith(f"=== CVE Triage: {cid} ===")
    for cid in describe:
        assert (run_dir / f"cve-lookup-{cid}.txt").exists() and (run_dir / f"cve-advisory-{cid}.txt").exists()
    assert f"fetched {len(candidates) + 2 * len(describe)} results, 0 failed" in r.stdout
    assert f"stored {len(candidates)}" in r.stdout
    doc = json.loads((run_dir / "enrichment.json").read_text())
    assert set(candidates) <= set(doc["cves"]) and doc["missing"] == []
    assert doc["cves"]["CVE-2026-21887"]["cvss"] == 8.8
    # a second fetch finds everything cached and calls nothing
    r2 = dva("enrich", "--fetch", env=env)
    assert "fetched 0 results" in r2.stdout


def test_fetch_skips_a_failed_id_and_continues(tmp_path):
    run_dir, env = _collected_run(tmp_path, FAKE_MCP_FAIL_IDS="CVE-2026-21887")
    r = dva("enrich", "--fetch", env=env)
    assert not (run_dir / "cve-triage-CVE-2026-21887.txt").exists()
    assert "warning: triage_cve CVE-2026-21887" in r.stdout
    assert "3 failed" in r.stdout  # it is also the described CVE, so lookup_cve and get_vendor_advisory fail too
    doc = json.loads((run_dir / "enrichment.json").read_text())
    assert "CVE-2026-21887" in doc["missing"]


def test_fetch_fails_clearly_when_the_server_cannot_start(tmp_path):
    run_dir, env = _collected_run(tmp_path, DVA_CVE_MCP=str(tmp_path / "no-such-server"))
    r = dva("enrich", "--fetch", env=env, ok=False)
    assert r.returncode == 1 and "CVE server" in r.stderr


def test_server_flag_overrides_the_environment(tmp_path):
    run_dir, env = _collected_run(tmp_path, DVA_CVE_MCP=str(tmp_path / "no-such-server"))
    r = dva("enrich", "--fetch", "--server", FAKE, env=env)
    assert "0 failed" in r.stdout


def test_fetch_describes_every_driving_cve_the_report_shows(tmp_path):
    """Descriptions are looked up after triage, for the CVEs that drive each listed product once intel is in."""
    run_dir, env = _collected_run(tmp_path)
    dva("enrich", "--fetch", env=env)
    dva("score", env=env)
    doc = json.loads((run_dir / "findings.json").read_text())
    for row in doc["products"]:
        for c in row["driving_cves"]:
            assert c["description"], f"{row['key']} {c['id']} has no description"
