"""A minimal MCP server over stdio for tests: answers initialize and tools/call with fixture text.

tools/call for triage_cve / lookup_cve / get_vendor_advisory returns the matching tests/fixtures/cve text with the
CVE id substituted. Knobs (environment): FAKE_MCP_BANNER=1 prints a non-JSON line on stdout before serving
(some servers do); FAKE_MCP_FAIL_IDS=CVE-a,CVE-b answers those ids with an isError result.
"""
import json
import os
import re
import sys
from pathlib import Path

FX = Path(__file__).parent / "fixtures" / "cve"
FILES = {"triage_cve": "triage-standard.txt", "lookup_cve": "lookup.txt", "get_vendor_advisory": "advisory.txt"}


def _text(tool: str, cve_id: str) -> str:
    raw = (FX / FILES[tool]).read_text()
    return re.sub(r"CVE-\d{4}-\d{4,}", cve_id, raw)


def main() -> None:
    fail = {s for s in os.environ.get("FAKE_MCP_FAIL_IDS", "").split(",") if s}
    if os.environ.get("FAKE_MCP_BANNER"):
        print("fake-mcp: starting up", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if "id" not in msg:
            continue  # notification
        method, params, rid = msg["method"], msg.get("params") or {}, msg["id"]
        if method == "initialize":
            result = {"protocolVersion": params.get("protocolVersion"), "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fake-mcp", "version": "0"}}
        elif method == "tools/call":
            tool, args = params["name"], params.get("arguments") or {}
            cve_id = args.get("cve_id", "")
            if tool not in FILES:
                print(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": f"Unknown tool: {tool}"}}), flush=True)
                continue
            if cve_id in fail:
                result = {"content": [{"type": "text", "text": f"Error: upstream failed for {cve_id}"}], "isError": True}
            else:
                result = {"content": [{"type": "text", "text": _text(tool, cve_id)}], "isError": False}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Method not found: {method}"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}), flush=True)


if __name__ == "__main__":
    main()
