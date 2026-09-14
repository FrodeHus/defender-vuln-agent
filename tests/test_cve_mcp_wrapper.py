"""scripts/cve-mcp.sh starts the pinned upstream cve-mcp-server through uvx, passing the NVD key from this repo's .env."""
import os
import shutil
import subprocess
from pathlib import Path

WRAPPER = Path("scripts/cve-mcp.sh")


def _sandbox(tmp_path, env_text: str | None):
    root = tmp_path / "plugin"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(WRAPPER, root / "scripts" / "cve-mcp.sh")
    if env_text is not None:
        (root / ".env").write_text(env_text)
    fake_bin = tmp_path / "bin"; fake_bin.mkdir()
    (fake_bin / "uvx").write_text('#!/usr/bin/env bash\necho "ARGS: $*"\necho "NVD: ${NVD_API_KEY-<unset>}"\n')
    (fake_bin / "uvx").chmod(0o755)
    return root, fake_bin


def _run(root, fake_bin, **extra):
    env = {k: v for k, v in os.environ.items() if k != "NVD_API_KEY"}
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env.update(extra)
    return subprocess.run(["bash", str(root / "scripts" / "cve-mcp.sh")], capture_output=True, text=True, env=env, cwd=root.parent)


def test_wrapper_runs_pinned_server_via_uvx_with_key_from_dotenv(tmp_path):
    root, fake_bin = _sandbox(tmp_path, "DVA_TENANT_ID=x\nNVD_API_KEY='abc123'  # comment\n")
    r = _run(root, fake_bin)
    assert r.returncode == 0, r.stderr
    assert "ARGS: --from git+https://github.com/mukul975/cve-mcp-server@" in r.stdout
    assert "--with mcp[cli]<2 cve-mcp" in r.stdout
    assert "NVD: abc123" in r.stdout


def test_wrapper_prefers_exported_key_and_tolerates_missing_dotenv(tmp_path):
    root, fake_bin = _sandbox(tmp_path, None)
    r = _run(root, fake_bin, NVD_API_KEY="from-shell")
    assert r.returncode == 0 and "NVD: from-shell" in r.stdout
    root2, fake_bin2 = _sandbox(tmp_path / "second", "NVD_API_KEY=from-file\n")
    r = _run(root2, fake_bin2, NVD_API_KEY="from-shell")
    assert "NVD: from-shell" in r.stdout  # an exported variable wins, as everywhere else in dva


def test_wrapper_fails_clearly_without_uv(tmp_path):
    root, _ = _sandbox(tmp_path, "NVD_API_KEY=k\n")
    empty = tmp_path / "empty"; empty.mkdir()
    env = {"PATH": str(empty), "HOME": os.environ.get("HOME", "/")}
    r = subprocess.run([shutil.which("bash"), str(root / "scripts" / "cve-mcp.sh")], capture_output=True, text=True, env=env)
    assert r.returncode != 0 and "uv" in r.stderr and "astral" in r.stderr


def test_installer_no_longer_clones_the_cve_server():
    text = Path("scripts/install.sh").read_text()
    assert "git clone" not in text and "cve-server-dir" not in text
    assert "scripts/cve-mcp.sh --warm" in text or "cve-mcp.sh\" --warm" in text
