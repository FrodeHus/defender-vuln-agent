from __future__ import annotations

import os
from datetime import date, datetime, timezone

import pytest

from dva import exceptions as exc
from dva.errors import DvaError
from dva.config import load_scoring
from dva.cache import IntelCache
from dva.rollup import build
from tests.test_rollup import seed


def test_load_missing_file_returns_empty(tmp_path):
    assert exc.load(tmp_path / "nope.yaml") == []


def test_save_load_round_trip_mode_600(tmp_path):
    path = tmp_path / "exceptions.yaml"
    items = [exc.Exception_(product="openssl/openssl", cve=None, reason="Bundled OpenSSL", until="2099-01-01",
                             owner="frode", added="2026-09-14T10:00:00+00:00", source="user")]
    exc.save(path, items)
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert exc.load(path) == items


def test_load_malformed_raises(tmp_path):
    path = tmp_path / "exceptions.yaml"
    path.write_text("exceptions: [unterminated\n")
    with pytest.raises(DvaError, match="corrupt exceptions file"):
        exc.load(path)


def test_load_exceptions_not_a_list_raises(tmp_path):
    path = tmp_path / "exceptions.yaml"
    path.write_text("exceptions: not-a-list\n")
    with pytest.raises(DvaError, match="must be a list"):
        exc.load(path)


def test_split_active_and_expired():
    items = [
        exc.Exception_(product="a/a", cve=None, reason="r", until="2099-01-01", owner=None, added="x", source="user"),
        exc.Exception_(product="b/b", cve=None, reason="r", until="2000-01-01", owner=None, added="x", source="user"),
    ]
    active, expired = exc.split(items, date(2026, 9, 14))
    assert [i.product for i in active] == ["a/a"]
    assert [i.product for i in expired] == ["b/b"]


def test_apply_drops_product_and_removes_cve(tmp_path):
    # adobe/acrobat-reader-dc has only one CVE in the seed run, so excepting it directly (rather
    # than via a CVE exception that would empty its cves) keeps this test focused on the
    # product-exception path; the CVE-exception-empties-a-product path is covered separately below.
    run = seed(tmp_path / "runs")
    products, assets = build(run)
    items = [
        exc.Exception_(product="adobe/acrobat-reader-dc", cve=None, reason="vendor cadence", until="2099-01-01",
                        owner="frode", added="2026-09-14T10:00:00+00:00", source="user"),
        exc.Exception_(product=None, cve="CVE-2025-46512", reason="tracked elsewhere", until="2099-01-01",
                        owner="frode", added="2026-09-14T10:00:00+00:00", source="user"),
    ]
    remaining, dropped = exc.apply(products, items)
    assert "adobe/acrobat-reader-dc" not in remaining
    assert dropped["adobe/acrobat-reader-dc"].reason == "vendor cadence"
    assert "ivanti/connect-secure" in remaining
    assert "CVE-2025-46512" not in remaining["ivanti/connect-secure"].cves
    assert "CVE-2026-21887" in remaining["ivanti/connect-secure"].cves  # the product's other CVE survives


def test_apply_drops_product_left_with_no_cves_after_cve_exception(tmp_path):
    run = seed(tmp_path / "runs")
    products, assets = build(run)
    items = [exc.Exception_(product=None, cve="CVE-2026-24433", reason="only CVE excepted", until="2099-01-01",
                             owner="frode", added="2026-09-14T10:00:00+00:00", source="user")]
    remaining, dropped = exc.apply(products, items)
    assert "adobe/acrobat-reader-dc" not in remaining  # its sole CVE was excepted, so nothing is left to score
    assert dropped == {}  # not a product exception, so it isn't in the dropped/accepted-risk mapping either


def test_compute_drops_product_with_no_remaining_cves_after_cve_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("DVA_TENANT_DIR", str(tmp_path / "tenant"))
    (tmp_path / "tenant").mkdir()
    run = seed(tmp_path / "runs")
    items = [exc.Exception_(product=None, cve="CVE-2026-24433", reason="only CVE excepted",
                             until="2099-01-01", owner="frode", added=datetime.now(timezone.utc).isoformat(), source="user")]
    exc.save(exc.path_for_current(), items)
    from dva.score_cmd import compute
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    keys = [p["key"] for p in doc["products"]]
    assert "adobe/acrobat-reader-dc" not in keys


def test_compute_active_product_exception_excluded_and_would_be_scored(tmp_path, monkeypatch):
    monkeypatch.setenv("DVA_TENANT_DIR", str(tmp_path / "tenant"))
    (tmp_path / "tenant").mkdir()
    run = seed(tmp_path / "runs")
    items = [exc.Exception_(product="ivanti/connect-secure", cve=None, reason="Vendor patches on their cadence",
                             until="2099-01-01", owner="frode", added=datetime.now(timezone.utc).isoformat(), source="user")]
    exc.save(exc.path_for_current(), items)
    from dva.score_cmd import compute
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    keys = [p["key"] for p in doc["products"]]
    assert "ivanti/connect-secure" not in keys
    active = doc["accepted_risks"]["active"]
    assert len(active) == 1
    assert active[0]["key"] == "ivanti/connect-secure"
    assert active[0]["reason"] == "Vendor patches on their cadence"
    assert active[0]["owner"] == "frode"
    assert active[0]["would_be_score"] >= 40
    assert doc["accepted_risks"]["expired"] == []


def test_compute_expired_exception_flags_row_and_lists_as_expired(tmp_path, monkeypatch):
    monkeypatch.setenv("DVA_TENANT_DIR", str(tmp_path / "tenant"))
    (tmp_path / "tenant").mkdir()
    run = seed(tmp_path / "runs")
    items = [exc.Exception_(product="ivanti/connect-secure", cve=None, reason="stale exception",
                             until="2000-01-01", owner="frode", added="2020-01-01T00:00:00+00:00", source="user")]
    exc.save(exc.path_for_current(), items)
    from dva.score_cmd import compute
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "cache", 7))
    row = next(p for p in doc["products"] if p["key"] == "ivanti/connect-secure")
    assert row["flags"]["exception_expired"] is True
    expired = doc["accepted_risks"]["expired"]
    assert any(e["key"] == "ivanti/connect-secure" and e["reason"] == "stale exception" for e in expired)
    assert doc["accepted_risks"]["active"] == []


def test_cli_add_then_list_writes_tenant_file(tmp_path, monkeypatch, capsys):
    tenants_root = tmp_path / "tenants"
    monkeypatch.setenv("DVA_TENANTS_DIR", str(tenants_root))
    for k in ["DVA_TENANT", "DVA_TENANT_DIR", "DVA_TENANT_ID", "DVA_CLIENT_ID", "DVA_CLIENT_SECRET",
              "DVA_RUNS_DIR", "DVA_CACHE_DIR", "DVA_TENANT_NAME", "DVA_RUN"]:
        monkeypatch.delenv(k, raising=False)
    d = tenants_root / "contoso"
    d.mkdir(parents=True)
    (d / ".env").write_text("DVA_TENANT_ID=t1\nDVA_CLIENT_ID=c1\nDVA_CLIENT_SECRET=s1\n")
    from dva.__main__ import main
    rc = main(["--tenant", "contoso", "exception", "add", "--product", "openssl/openssl",
               "--reason", "bundled component", "--until", "2099-01-01", "--owner", "frode"])
    assert rc == 0
    exc_file = d / "exceptions.yaml"
    assert exc_file.exists()
    assert oct(os.stat(exc_file).st_mode & 0o777) == "0o600"
    capsys.readouterr()
    rc2 = main(["--tenant", "contoso", "exception", "list"])
    out = capsys.readouterr().out
    assert rc2 == 0
    assert "openssl/openssl" in out and "2099-01-01" in out and "frode" in out
    # `tenant.activate()` sets process environment directly (not via monkeypatch, since it runs
    # inside main()). monkeypatch.delenv would just restore that leaked value at teardown (it
    # snapshots the "current" value to restore), so pop directly to keep it from leaking into
    # later test modules.
    for k in ["DVA_TENANT", "DVA_TENANT_DIR", "DVA_TENANT_ID", "DVA_CLIENT_ID", "DVA_CLIENT_SECRET",
              "DVA_RUNS_DIR", "DVA_CACHE_DIR", "DVA_TENANT_NAME", "DVA_RUN"]:
        os.environ.pop(k, None)


def test_cli_add_same_key_twice_updates_single_entry(tmp_path, monkeypatch, capsys):
    tenants_root = tmp_path / "tenants"
    monkeypatch.setenv("DVA_TENANTS_DIR", str(tenants_root))
    for k in ["DVA_TENANT", "DVA_TENANT_DIR", "DVA_TENANT_ID", "DVA_CLIENT_ID", "DVA_CLIENT_SECRET",
              "DVA_RUNS_DIR", "DVA_CACHE_DIR", "DVA_TENANT_NAME", "DVA_RUN"]:
        monkeypatch.delenv(k, raising=False)
    d = tenants_root / "contoso"
    d.mkdir(parents=True)
    (d / ".env").write_text("DVA_TENANT_ID=t1\nDVA_CLIENT_ID=c1\nDVA_CLIENT_SECRET=s1\n")
    from dva.__main__ import main
    try:
        rc1 = main(["--tenant", "contoso", "exception", "add", "--product", "openssl/openssl",
                    "--reason", "first reason", "--until", "2099-01-01", "--owner", "frode"])
        assert rc1 == 0
        assert "added exception for openssl/openssl" in capsys.readouterr().out

        rc2 = main(["--tenant", "contoso", "exception", "add", "--product", "openssl/openssl",
                    "--reason", "newer reason", "--until", "2099-06-01", "--owner", "frode"])
        assert rc2 == 0
        assert "updated exception for openssl/openssl" in capsys.readouterr().out

        items = exc.load(d / "exceptions.yaml")
        assert len(items) == 1
        assert items[0].reason == "newer reason" and items[0].until == "2099-06-01"
    finally:
        # see the cleanup note in test_cli_add_then_list_writes_tenant_file above
        for k in ["DVA_TENANT", "DVA_TENANT_DIR", "DVA_TENANT_ID", "DVA_CLIENT_ID", "DVA_CLIENT_SECRET",
                  "DVA_RUNS_DIR", "DVA_CACHE_DIR", "DVA_TENANT_NAME", "DVA_RUN"]:
            os.environ.pop(k, None)


def test_cli_add_without_product_or_cve_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DVA_TENANT", raising=False)
    monkeypatch.delenv("DVA_TENANT_DIR", raising=False)
    from dva.__main__ import main
    rc = main(["exception", "add", "--reason", "x", "--until", "2099-01-01"])
    assert rc == 1
    assert "requires --product or --cve" in capsys.readouterr().err
