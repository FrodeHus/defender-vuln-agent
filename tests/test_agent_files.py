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

def test_skills_and_mcp():
    for s in ["defender-auth", "defender-inventory", "defender-hunting", "vuln-prioritize-report"]:
        t = Path(f".claude/skills/{s}/SKILL.md").read_text()
        assert t.startswith("---") and f"name: {s}" in t and "description:" in t
    mcp = json.loads(Path(".mcp.json").read_text())
    assert mcp["mcpServers"]["cve-mcp"]["command"] and "cve_mcp.server" in " ".join(mcp["mcpServers"]["cve-mcp"]["args"])
