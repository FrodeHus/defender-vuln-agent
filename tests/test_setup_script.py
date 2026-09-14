import subprocess

def test_dry_run_prints_expected_commands():
    out = subprocess.run(["bash", "setup/create-app.sh", "--dry-run", "--name", "dva-test"], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "az ad app create --display-name dva-test" in out.stdout
    assert "fc780465-2017-40d4-a0c5-307022471b92" in out.stdout and "dd98c7f5-2d42-42d3-a0e4-633161547251" in out.stdout
    for perm in ["Machine.Read.All", "Vulnerability.Read.All", "Software.Read.All", "SecurityRecommendation.Read.All", "Score.Read.All"]:
        assert perm in out.stdout
    assert "DVA_TENANT_ID" in out.stdout and "admin consent" in out.stdout.lower()
