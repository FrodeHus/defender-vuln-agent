"""A stdlib-only MCP client over stdio: enough to start the cve-mcp server and call its tools.

MCP over stdio is newline-delimited JSON-RPC 2.0: one `initialize` request, one `notifications/initialized`
notification, then `tools/call` requests. Keeping the client here (subprocess + json + threading) means `dva`
can enrich CVEs without the agent relaying every result, and without a new runtime dependency.
"""
from __future__ import annotations

import json
import queue
import subprocess
import threading
from typing import Any

from dva.errors import DvaError

PROTOCOL_VERSION = "2024-11-05"


class McpStdioClient:
    def __init__(self, command: list[str], env: dict[str, str] | None = None, timeout: float = 120.0):
        self.command, self.env, self.timeout = command, env, timeout
        self._proc: subprocess.Popen | None = None
        self._lines: queue.Queue = queue.Queue()
        self._next_id = 0

    # -- lifecycle -------------------------------------------------------------------------------------------------
    def __enter__(self) -> "McpStdioClient":
        try:
            self._proc = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True, encoding="utf-8", env=self.env, bufsize=1)
        except OSError as exc:
            raise DvaError(f"CVE server could not be started ({' '.join(self.command)}): {exc}")
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        try:
            self._request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                         "clientInfo": {"name": "dva", "version": "0.3.0"}})
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except DvaError:
            self.close()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        p = self._proc
        if p is None:
            return
        self._proc = None
        for stream in (p.stdin, p.stdout, p.stderr):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

    # -- public ----------------------------------------------------------------------------------------------------
    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Call a tool and return its text content joined together; raises DvaError on any error."""
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        text = "\n".join(c.get("text", "") for c in result.get("content") or [] if c.get("type") == "text")
        if result.get("isError"):
            raise DvaError(f"CVE server tool {name} failed: {text.strip() or 'no details'}")
        return text

    # -- plumbing --------------------------------------------------------------------------------------------------
    def _pump(self) -> None:
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        try:
            for line in proc.stdout:
                self._lines.put(line)
        except ValueError:
            pass  # stream closed under us
        self._lines.put(None)

    def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        try:
            for _ in proc.stderr:
                pass
        except ValueError:
            pass

    def _send(self, msg: dict) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise DvaError("CVE server is not running")
        try:
            proc.stdin.write(json.dumps(msg) + "\n")
            proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise DvaError(f"CVE server went away: {exc}")

    def _request(self, method: str, params: dict) -> dict:
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        while True:
            try:
                line = self._lines.get(timeout=self.timeout)
            except queue.Empty:
                raise DvaError(f"CVE server did not answer {method} within {self.timeout:.0f}s")
            if line is None:
                code = self._proc.poll() if self._proc else None
                raise DvaError(f"CVE server exited before answering {method}" + (f" (exit code {code})" if code is not None else ""))
            line = line.strip()
            if not line.startswith("{"):
                continue  # banners and log lines some servers print on stdout
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") != rid:
                continue  # notifications or answers to something else
            if "error" in msg:
                err = msg["error"] or {}
                raise DvaError(f"CVE server error on {method}: {err.get('message', err)}")
            return msg.get("result") or {}
