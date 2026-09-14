from dva.config import load_scoring
from dva.model import Asset, CveRef, Product
from dva.scoring import threat_score, asset_multiplier, product_score, CveIntel, label_for, reason_for

cfg = load_scoring()


def ref(id="CVE-1", cvss=9.8, expl="NoExploit", sev="Critical"):
    return CveRef(id=id, severity=sev, cvss=cvss, exploitability=expl, first_seen=None)


def test_threat_without_intel_uses_defender_fields():
    assert abs(threat_score(ref(cvss=10.0), None, cfg) - 0.35) < 1e-9
    assert abs(threat_score(ref(cvss=10.0, expl="ExploitIsInKit"), None, cfg) - 0.50) < 1e-9


def test_threat_with_intel():
    intel = CveIntel(cvss=9.8, epss=0.94, epss_percentile=0.99, kev=True, kev_added=None, ransomware=False, exploit_public=True, exploit_sources=["exploit-db"], title="t", cwe=None, fetched_at=None)
    t = threat_score(ref(), intel, cfg)
    assert abs(t - (0.35 * 0.98 + 0.25 * 0.99 + 0.25 + 0.15)) < 1e-9


def test_asset_multiplier_bonuses_and_cap():
    a = Asset(id="a", name="a", internet_facing=True, exposure_level="High", device_value="High", tags=["Tier0", "Prod"])
    assert asset_multiplier(a, cfg) == cfg.asset_cap  # 1 + .6 + .4 + .4 + .5 > cap
    b = Asset(id="b", name="b", exposure_level="Medium")
    assert abs(asset_multiplier(b, cfg) - 1.2) < 1e-9


def test_product_score_ranks_kev_gateway_above_fleet_mediums():
    gw = Product(key="ivanti/connect-secure", vendor="ivanti", name="connect_secure", asset_ids={"a"}, cves={"CVE-1": ref(expl="ExploitIsInKit")})
    fleet = Product(key="x/y", vendor="x", name="y", asset_ids={f"d{i}" for i in range(300)}, cves={f"CVE-{i}": ref(id=f"CVE-{i}", cvss=5.5, sev="Medium") for i in range(20)})
    assets = {"a": Asset(id="a", name="gw", internet_facing=True, tags=["Tier0"])}
    assets.update({f"d{i}": Asset(id=f"d{i}", name=f"d{i}") for i in range(300)})
    intel = {"CVE-1": CveIntel(cvss=9.8, epss=0.9, epss_percentile=0.99, kev=True, kev_added=None, ransomware=False, exploit_public=True, exploit_sources=[], title=None, cwe=None, fetched_at=None)}
    s_gw = product_score(gw, assets, intel, cfg, estate_size=2000)
    s_fleet = product_score(fleet, assets, {}, cfg, estate_size=2000)
    assert s_gw.score > s_fleet.score and s_gw.label == "Critical"
    assert s_gw.flags == {"kev": True, "exploit": True, "internet_facing": True}
    assert s_gw.top_assets[0][2] == "Internet-facing · Tier0"
    assert s_fleet.counts == {"critical": 0, "high": 0, "medium": 20, "low": 0}
    assert len(s_gw.driving) == 1 and len(s_fleet.driving) == 3


def test_label_and_reason():
    assert label_for(80, cfg) == "Critical" and label_for(59, cfg) == "Medium" and label_for(10, cfg) == "Low"
