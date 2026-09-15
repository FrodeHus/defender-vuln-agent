import os
import pytest


@pytest.fixture(autouse=True)
def _isolated_tenants(tmp_path_factory, monkeypatch):
    """Never let a developer's real tenants/ (or a tenant activated by an earlier test) reach a test.

    Tenant activation writes DVA_TENANT & co. straight into os.environ, and subprocess tests inherit it,
    so snapshot the environment and point DVA_TENANTS_DIR at an empty directory unless a test overrides it.
    """
    snapshot = dict(os.environ)
    monkeypatch.setenv("DVA_TENANTS_DIR", str(tmp_path_factory.mktemp("no-tenants")))
    monkeypatch.setenv("DVA_CACHE_DIR", str(tmp_path_factory.mktemp("cache")))  # never the checkout's real .cache
    monkeypatch.setenv("DVA_KEV_URL", str(os.path.join(os.path.dirname(__file__), "fixtures", "kev", "catalog.json")))  # never the network
    for k in ("DVA_TENANT", "DVA_TENANT_DIR", "DVA_TENANT_NAME"):
        monkeypatch.delenv(k, raising=False)
    yield
    os.environ.clear()
    os.environ.update(snapshot)
