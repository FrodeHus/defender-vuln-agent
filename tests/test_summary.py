from pathlib import Path
from dva.summary import risk_summary
from dva.tenantinfo import resolve_display_name, lookup_display_name
from dva.http import Client
from tests.fakes import FakeSession, FakeResponse, FakeTokens


def test_risk_summary_kev_rce_internet_facing():
    s = risk_summary("Connect Secure", {"id": "CVE-2026-21887", "severity": "Critical", "cvss": 9.8, "epss": 0.94, "kev": True, "poc": True},
                     "An unauthenticated attacker can send a crafted request to execute arbitrary code on the appliance.",
                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6, 6, 6, 0)
    assert s.startswith("The most critical issue is CVE-2026-21887 (critical, CVSS 9.8): it is in CISA's Known Exploited Vulnerabilities catalog")
    assert "public exploit code is available" in s and "94%" in s
    assert "run their own code on the affected device and take control of it over the network without any credentials" in s
    assert "6 devices run Connect Secure, 6 of them internet-facing and 6 tagged as critical" in s
    assert s.endswith("risks full compromise on systems reachable from the internet.")


def test_risk_summary_without_intel_uses_vector_and_defaults():
    s = risk_summary("Java Runtime 8", {"id": "CVE-2026-21032", "severity": "High", "cvss": 7.5, "epss": None, "kev": False, "poc": False}, None, None, 1, 0, 0, 0)
    assert s == ("The most critical issue is CVE-2026-21032 (high, CVSS 7.5). An attacker could exploit the flaw against the affected device. "
                 "1 device runs Java Runtime 8; leaving it unpatched risks compromise.")


def test_risk_summary_local_privilege_escalation():
    s = risk_summary("Windows Server 2019", {"id": "CVE-2026-21335", "severity": "Critical", "cvss": 8.8, "epss": 0.61, "kev": True, "poc": False},
                     "A use after free in the Win32k kernel driver allows a local attacker to elevate privileges to SYSTEM.", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 312, 0, 40, 0)
    assert "turn a foothold into administrator-level control with local access to the device" in s
    assert "312 devices run Windows Server 2019, 40 tagged as critical; leaving it unpatched risks privilege escalation." in s


def test_tenant_name_lookup_and_fallbacks(tmp_path, monkeypatch):
    for k in ["DVA_TENANT_NAME", "DVA_TENANT", "DVA_TENANT_ID"]:
        monkeypatch.delenv(k, raising=False)
    assert resolve_display_name(tmp_path) == "unknown"
    monkeypatch.setenv("DVA_TENANT_ID", "tid-1")
    assert resolve_display_name(tmp_path) == "tid-1"                       # no client factory: id
    monkeypatch.setenv("DVA_TENANT", "contoso")
    assert resolve_display_name(tmp_path) == "contoso"                     # directory name beats id
    base = "https://graph.microsoft.com/v1.0"
    ok = FakeSession({f"GET {base}/tenantRelationships/findTenantInformationByTenantId(tenantId='tid-1')": [FakeResponse(200, {"displayName": "Contoso Ltd", "tenantId": "tid-1"})]})
    factory = lambda: Client(FakeTokens(), "s", base_url=base, session=ok, sleep=lambda s: None)
    assert resolve_display_name(tmp_path, client_factory=factory) == "Contoso Ltd"
    assert resolve_display_name(tmp_path, client_factory=lambda: (_ for _ in ()).throw(AssertionError("must use cache"))) == "Contoso Ltd"
    denied = FakeSession({f"GET {base}/tenantRelationships/findTenantInformationByTenantId(tenantId='tid-2')": [FakeResponse(403, {"error": {"message": "denied"}})]})
    monkeypatch.setenv("DVA_TENANT_ID", "tid-2")
    logs = []
    assert resolve_display_name(tmp_path, client_factory=lambda: Client(FakeTokens(), "s", base_url=base, session=denied, sleep=lambda s: None, max_attempts=1), log=logs.append) == "contoso"
    assert logs and "CrossTenantInformation.ReadBasic.All" in logs[0]
    monkeypatch.setenv("DVA_TENANT_NAME", "Explicit Name")
    assert resolve_display_name(tmp_path) == "Explicit Name"


def test_html_toolbar_sits_above_the_list_it_filters():
    t = Path("dva/report_template.html").read_text()
    assert t.index("All prioritized products") < t.index('id="toolbar"') < t.index('id="all"')
    assert 'id="top"' in t and t.index('id="top"') < t.index('id="toolbar"')
