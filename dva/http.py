from __future__ import annotations
import time
from typing import Callable, Iterator
import requests
from dva.errors import DvaError

RETRY_STATUS = {429, 500, 502, 503, 504}


class Client:
    def __init__(self, tokens, scope: str, base_url: str = "", session=None,
                 sleep: Callable[[float], None] = time.sleep, max_attempts: int = 5, timeout: int = 120):
        self.tokens, self.scope, self.base_url = tokens, scope, base_url.rstrip("/")
        self.session = session or requests.Session()
        self.sleep, self.max_attempts, self.timeout = sleep, max_attempts, timeout

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    def _request(self, method: str, path: str, params=None, body=None) -> dict:
        url = self._url(path)
        last = None
        for attempt in range(1, self.max_attempts + 1):
            headers = {"Authorization": f"Bearer {self.tokens.token(self.scope)}", "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            resp = self.session.request(method, url, headers=headers, params=params, json=body, timeout=self.timeout)
            if resp.status_code < 300:
                return resp.json() if resp.text else {}
            last = resp
            if resp.status_code in RETRY_STATUS and attempt < self.max_attempts:
                retry_after = resp.headers.get("Retry-After")
                self.sleep(float(retry_after) if retry_after else min(60.0, 2.0 ** attempt))
                continue
            break
        detail = ""
        try:
            detail = (last.json().get("error") or {}).get("message", "") if last is not None else ""
        except Exception:
            detail = (last.text or "")[:200] if last is not None else ""
        raise DvaError(f"{method} {url} failed with HTTP {last.status_code}: {detail}")

    def get_json(self, path: str, params: dict | None = None) -> dict:
        return self._request("GET", path, params=params)

    def post_json(self, path: str, body: dict) -> dict:
        return self._request("POST", path, body=body)

    def paged(self, path: str, params: dict | None = None, value_key: str = "value") -> Iterator[dict]:
        page = self.get_json(path, params)
        while True:
            yield from page.get(value_key, [])
            nxt = page.get("@odata.nextLink")
            if not nxt:
                return
            page = self.get_json(nxt)
