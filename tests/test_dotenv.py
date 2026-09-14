import os
from dva.dotenv import parse, load


def test_parse_handles_comments_quotes_and_export():
    text = "# comment\nexport DVA_TENANT_ID=abc\nDVA_CLIENT_ID='cid'\nDVA_CLIENT_SECRET=\"s3c=ret\"\nDVA_RUNS_DIR=runs # trailing\n\nBROKEN\n"
    assert parse(text) == {"DVA_TENANT_ID": "abc", "DVA_CLIENT_ID": "cid", "DVA_CLIENT_SECRET": "s3c=ret", "DVA_RUNS_DIR": "runs"}


def test_load_does_not_override_shell_env(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("DVA_TENANT_ID=from-file\nDVA_CLIENT_ID=from-file\n")
    monkeypatch.setenv("DVA_TENANT_ID", "from-shell")
    monkeypatch.delenv("DVA_CLIENT_ID", raising=False)
    applied = load(env)
    assert applied == ["DVA_CLIENT_ID"]
    assert os.environ["DVA_TENANT_ID"] == "from-shell"
    assert os.environ["DVA_CLIENT_ID"] == "from-file"


def test_load_finds_file_in_cwd(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("DVA_CACHE_DIR=/tmp/x\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DVA_CACHE_DIR", raising=False)
    assert load() == ["DVA_CACHE_DIR"]


def test_load_without_file_is_noop(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("dva.dotenv.ROOT", tmp_path)
    assert load() == []
