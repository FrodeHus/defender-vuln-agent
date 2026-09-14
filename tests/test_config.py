from dva.config import load_scoring, load_sources


def test_scoring_defaults():
    s = load_scoring()
    assert s.threat_weights == {"cvss": 0.35, "epss": 0.25, "kev": 0.25, "exploit": 0.15}
    assert s.enrich_top_per_product == 3
    assert s.enrich_max_cves == 200
    assert s.enrich_threshold == 20
    assert s.report_threshold == 40
    assert s.bands == {"critical": 80, "high": 60, "medium": 40}
    assert "Tier0" in s.criticality_tags


def test_sources_defaults():
    src = load_sources()
    assert src.mde and src.hunting and not src.cloud
    assert "internet-facing" in src.hunting_queries
