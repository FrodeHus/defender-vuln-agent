from __future__ import annotations
import json
from urllib.parse import urlsplit, parse_qsl


class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        return self._body

    @property
    def text(self):
        return json.dumps(self._body)


class FakeSession:
    """routes: {"GET https://host/path": [FakeResponse, ...]} consumed in order; last one repeats."""

    def __init__(self, routes: dict):
        self.routes = {k: list(v) for k, v in routes.items()}
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        base = url.split("?")[0]
        key = f"{method} {base}"
        self.calls.append((method, url, {"params": params, "json": json}))
        if key not in self.routes:
            raise AssertionError(f"unexpected request {key}")
        queue = self.routes[key]
        return queue.pop(0) if len(queue) > 1 else queue[0]


class FakeTokens:
    def token(self, scope):
        return "tok"
