from __future__ import annotations
import json


class FakeResponse:
    def __init__(self, status, body=None, headers=None, json_error=None, text=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.json_error = json_error
        self._text = text

    def json(self):
        if self.json_error:
            raise self.json_error
        return self._body

    @property
    def text(self):
        if self._text is not None:
            return self._text
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
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return item


class FakeTokens:
    def token(self, scope):
        return "tok"
