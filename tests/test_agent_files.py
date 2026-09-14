import json, re
from pathlib import Path

def test_agent_definition():
    text = Path(".claude/agents/vuln-assessor.md").read_text()
    fm = text.split("---")[1]
    assert "name: vuln-assessor" in fm and "model: sonnet" in fm
    assert re.search(r"tools:.*Bash", fm) and "mcp__cve-mcp__" in fm
    for step in ["dva doctor", "dva run new", "dva mde all", "dva hunt", "dva enrich --list", "bulk_cve_lookup", "triage_cve", "dva enrich --store", "dva score", "dva report --all"]:
        assert step in text
    assert "never read raw" in text.lower() or "never cat" in text.lower()
    assert "<<'JSON'" in text

def test_skills_and_mcp():
    for s in ["defender-auth", "defender-inventory", "defender-hunting", "vuln-prioritize-report"]:
        t = Path(f".claude/skills/{s}/SKILL.md").read_text()
        assert t.startswith("---") and f"name: {s}" in t and "description:" in t
    mcp = json.loads(Path(".mcp.json").read_text())
    assert mcp["mcpServers"]["cve-mcp"]["command"] and "cve_mcp.server" in " ".join(mcp["mcpServers"]["cve-mcp"]["args"])


def test_inventory_skill_matches_actual_output_filename():
    text = Path(".claude/skills/defender-inventory/SKILL.md").read_text()
    assert "exposure.json" in text
    assert "score.json" not in text


def test_hunting_skill_timespan_examples_are_iso8601():
    text = Path(".claude/skills/defender-hunting/SKILL.md").read_text()
    assert "P7D" in text
    assert "--timespan 7d" not in text
