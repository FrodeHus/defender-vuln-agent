from dva.doctor import checks, run_checks, format_table
from dva.config import Sources
from dva.http import Client
from tests.fakes import FakeSession, FakeResponse, FakeTokens


def test_checks_cover_phase1_permissions():
    names = {c.permission for c in checks(Sources(mde=True, hunting=True, cloud=False))}
    assert names == {"Machine.Read.All", "Vulnerability.Read.All", "Software.Read.All", "SecurityRecommendation.Read.All", "Score.Read.All", "ThreatHunting.Read.All"}


def test_run_checks_reports_pass_and_fail():
    cs = checks(Sources(mde=True, hunting=True))
    def factory(scope, base_url):
        routes = {f"{c.method} {c.base_url}{c.path}": [FakeResponse(403 if c.permission == "Score.Read.All" else 200, {"value": []})] for c in cs}
        return Client(FakeTokens(), scope, base_url=base_url, session=FakeSession(routes), sleep=lambda s: None, max_attempts=1)
    results = run_checks(cs, factory)
    status = {c.permission: ok for c, ok, _ in results}
    assert status["Machine.Read.All"] is True and status["Score.Read.All"] is False
    table = format_table(results)
    assert "FAIL" in table and "Score.Read.All" in table
