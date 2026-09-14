import os
from pathlib import Path
import pytest
from dva.errors import DvaError
from dva import tenant
from dva.__main__ import main


def _make(root, name, **env):
    d = root / name
    d.mkdir(parents=True)
    (d / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    return d


@pytest.fixture
def tenants(tmp_path, monkeypatch):
    root = tmp_path / "tenants"
    monkeypatch.setenv("DVA_TENANTS_DIR", str(root))
    for k in ["DVA_TENANT", "DVA_TENANT_ID", "DVA_CLIENT_ID", "DVA_CLIENT_SECRET", "DVA_RUNS_DIR", "DVA_CACHE_DIR", "DVA_TENANT_NAME", "DVA_TENANT_DIR", "DVA_RUN"]:
        monkeypatch.delenv(k, raising=False)
    _make(root, "contoso", DVA_TENANT_ID="t-contoso", DVA_CLIENT_ID="c1", DVA_CLIENT_SECRET="s1")
    _make(root, "fabrikam", DVA_TENANT_ID="t-fabrikam", DVA_CLIENT_ID="c2", DVA_CLIENT_SECRET="s2")
    return root


def test_list_tenants(tenants):
    assert tenant.list_tenants() == ["contoso", "fabrikam"]


def test_activate_isolates_env_runs_and_cache(tenants, monkeypatch):
    monkeypatch.setenv("DVA_TENANT_ID", "leaked-from-shell")
    monkeypatch.setenv("DVA_RUNS_DIR", "/somewhere/shared")
    t = tenant.activate("contoso")
    assert t.name == "contoso" and t.dir == tenants / "contoso"
    assert os.environ["DVA_TENANT_ID"] == "t-contoso"          # tenant .env wins over shell
    assert os.environ["DVA_RUNS_DIR"] == str(tenants / "contoso" / "runs")
    assert os.environ["DVA_CACHE_DIR"] == str(tenants / "contoso" / ".cache")
    assert os.environ["DVA_TENANT_NAME"] == "contoso"
    assert os.environ["DVA_TENANT_DIR"] == str(tenants / "contoso")


def test_activate_second_tenant_replaces_first(tenants):
    tenant.activate("contoso")
    tenant.activate("fabrikam")
    assert os.environ["DVA_TENANT_ID"] == "t-fabrikam" and os.environ["DVA_CLIENT_SECRET"] == "s2"
    assert os.environ["DVA_RUNS_DIR"].endswith("fabrikam/runs")


def test_activate_unknown_or_ambiguous(tenants):
    with pytest.raises(DvaError, match="unknown tenant 'nope'"):
        tenant.activate("nope")
    _make(tenants, "contoso-dev", DVA_TENANT_ID="x", DVA_CLIENT_ID="y", DVA_CLIENT_SECRET="z")
    with pytest.raises(DvaError, match="ambiguous"):
        tenant.resolve_name("cont")
    assert tenant.resolve_name("contoso") == "contoso"       # exact match beats prefix
    assert tenant.resolve_name("FABR") == "fabrikam"          # case-insensitive unique prefix


def test_activate_requires_env_file(tenants):
    (tenants / "empty").mkdir()
    with pytest.raises(DvaError, match="no .env"):
        tenant.activate("empty")


def test_config_overrides_per_tenant(tenants, monkeypatch):
    from dva.config import load_scoring, load_sources
    (tenants / "contoso" / "scoring.yaml").write_text(Path("config/scoring.yaml").read_text().replace("report_threshold: 40", "report_threshold: 55"))
    (tenants / "contoso" / "sources.yaml").write_text("cloud: true\nsubscriptions: [sub-1]\n")
    tenant.activate("contoso")
    assert load_scoring().report_threshold == 55
    src = load_sources()
    assert src.cloud is True and src.subscriptions == ["sub-1"] and src.mde is True
    tenant.activate("fabrikam")
    assert load_scoring().report_threshold == 40 and load_sources().cloud is False


def test_cli_tenant_option_and_env(tenants, capsys, monkeypatch):
    assert main(["tenant", "list"]) == 0
    assert capsys.readouterr().out.splitlines() == ["contoso", "fabrikam"]
    assert main(["--tenant", "contoso", "run", "new"]) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith(str(tenants / "contoso" / "runs"))
    monkeypatch.setenv("DVA_TENANT", "fabrikam")
    assert main(["run", "new"]) == 0
    assert capsys.readouterr().out.strip().startswith(str(tenants / "fabrikam" / "runs"))
    assert main(["tenant", "show"]) == 0
    assert "fabrikam" in capsys.readouterr().out
    assert main(["--tenant", "nope", "run", "new"]) == 1
    assert "unknown tenant" in capsys.readouterr().err


def test_cli_tenant_init_creates_skeleton(tenants, capsys):
    assert main(["tenant", "init", "northwind"]) == 0
    d = tenants / "northwind"
    assert (d / ".env").exists() and (d / "runs").is_dir() and (d / ".cache").is_dir()
    assert oct(os.stat(d / ".env").st_mode & 0o777) == "0o600"
    assert "DVA_TENANT_ID=" in (d / ".env").read_text()
    assert main(["tenant", "init", "northwind"]) == 1  # refuses to overwrite


def test_no_tenants_dir_keeps_single_tenant_behaviour(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DVA_TENANTS_DIR", str(tmp_path / "missing"))
    monkeypatch.delenv("DVA_TENANT", raising=False)
    monkeypatch.setenv("DVA_RUNS_DIR", str(tmp_path / "runs"))
    assert main(["run", "new"]) == 0
    assert capsys.readouterr().out.strip().startswith(str(tmp_path / "runs"))
    assert main(["tenant", "list"]) == 0
    assert capsys.readouterr().out.strip() == ""


def test_sole_tenant_is_selected_automatically(tenants, capsys):
    import shutil
    shutil.rmtree(tenants / "fabrikam")
    assert main(["tenant", "show"]) == 0
    assert "tenant: contoso" in capsys.readouterr().out
    assert main(["run", "new"]) == 0
    assert capsys.readouterr().out.strip().startswith(str(tenants / "contoso" / "runs"))
    assert os.environ["DVA_TENANT_ID"] == "t-contoso"


def test_several_tenants_require_a_choice(tenants, capsys):
    assert main(["run", "new"]) == 1
    err = capsys.readouterr().err
    assert "contoso, fabrikam" in err and "--tenant" in err
    assert main(["tenant", "show"]) == 0          # informational commands still work
    assert "no tenant active" in capsys.readouterr().out
