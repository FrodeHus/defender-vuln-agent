"""dva/mcp_client.py: a stdlib-only MCP client over stdio, enough to call the cve-mcp server's tools."""
import os
import sys
from pathlib import Path

import pytest

from dva.errors import DvaError
from dva.mcp_client import McpStdioClient

FAKE = [sys.executable, str(Path(__file__).parent / "fake_mcp_server.py")]


def test_call_tool_returns_the_text_content(tmp_path):
    with McpStdioClient(FAKE) as client:
        text = client.call_tool("triage_cve", {"cve_id": "CVE-2026-21887", "depth": "standard"})
    assert text.startswith("=== CVE Triage: CVE-2026-21887 ===")
    assert "CVSS:   8.8 HIGH" in text


def test_tool_error_result_raises_dva_error():
    with McpStdioClient(FAKE, env=dict(os.environ, FAKE_MCP_FAIL_IDS="CVE-2020-1")) as client:
        with pytest.raises(DvaError, match="upstream failed for CVE-2020-1"):
            client.call_tool("triage_cve", {"cve_id": "CVE-2020-1"})
        # the session survives a failed call
        assert "CVE-2020-2" in client.call_tool("lookup_cve", {"cve_id": "CVE-2020-2"})


def test_jsonrpc_error_raises_dva_error():
    with McpStdioClient(FAKE) as client:
        with pytest.raises(DvaError, match="Unknown tool: nope"):
            client.call_tool("nope", {})


def test_non_json_lines_on_stdout_are_ignored():
    with McpStdioClient(FAKE, env=dict(os.environ, FAKE_MCP_BANNER="1")) as client:
        assert "CVE-2021-1" in client.call_tool("get_vendor_advisory", {"cve_id": "CVE-2021-1"})


def test_unstartable_server_raises_dva_error(tmp_path):
    with pytest.raises(DvaError, match="CVE server"):
        with McpStdioClient([str(tmp_path / "missing-server")]):
            pass


def test_server_that_exits_before_answering_raises_dva_error():
    with pytest.raises(DvaError, match="CVE server"):
        with McpStdioClient([sys.executable, "-c", "import sys; sys.exit(3)"], timeout=5):
            pass
