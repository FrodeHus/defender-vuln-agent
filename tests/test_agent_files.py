import json, re
from pathlib import Path

def test_agent_definition():
    text = Path("agents/vuln-assessor.md").read_text()
    fm = text.split("---")[1]
    assert "name: vuln-assessor" in fm and "model: sonnet" in fm
    assert re.search(r"tools:.*Bash", fm) and "mcp__cve-mcp__" in fm
    for step in ["dva doctor", "dva run new", "dva mde all", "dva hunt", "dva enrich --list", "triage_cve", "depth", "lookup_cve", "describe",
                 "get_vendor_advisory", "privileged-logons", "certificates", "dva enrich --store", "dva score", "dva report --all",
                 "exception suggest", "exception add"]:
        assert step in text
    assert "never read raw" in text.lower() or "never cat" in text.lower()
    assert "<<'TXT'" in text

def test_skills_and_mcp():
    for s in ["defender-auth", "defender-inventory", "defender-hunting", "vuln-prioritize-report"]:
        t = Path(f"skills/{s}/SKILL.md").read_text()
        assert t.startswith("---") and f"name: {s}" in t and "description:" in t
    mcp = json.loads(Path(".mcp.json").read_text())
    cmd = mcp["mcpServers"]["cve-mcp"]["command"]
    # Works both as a plugin (CLAUDE_PLUGIN_ROOT set) and as the project .mcp.json of a plain `claude` in the checkout.
    assert cmd == "${CLAUDE_PLUGIN_ROOT:-.}/scripts/cve-mcp.sh" and "args" not in mcp["mcpServers"]["cve-mcp"]
    assert Path("scripts/cve-mcp.sh").stat().st_mode & 0o111, "wrapper must be executable"


def test_inventory_skill_matches_actual_output_filename():
    text = Path("skills/defender-inventory/SKILL.md").read_text()
    assert "exposure.json" in text
    assert "score.json" not in text


def test_hunting_skill_timespan_examples_are_iso8601():
    text = Path("skills/defender-hunting/SKILL.md").read_text()
    assert "P7D" in text
    assert "--timespan 7d" not in text
