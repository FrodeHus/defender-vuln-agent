from __future__ import annotations
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
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

    def _parse_retry_after(self, header_value: str | None) -> float | None:
        if not header_value:
            return None
        try:
            return float(header_value)
        except ValueError:
            try:
                dt = parsedate_to_datetime(header_value)
                now = datetime.now(dt.tzinfo)
                seconds = (dt - now).total_seconds()
                return max(0, seconds)
            except Exception:
                return None

    def _request(self, method: str, path: str, params=None, body=None) -> dict:
        url = self._url(path)
        last_exc = None
        last_resp = None
        for attempt in range(1, self.max_attempts + 1):
            headers = {"Authorization": f"Bearer {self.tokens.token(self.scope)}", "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            try:
                resp = self.session.request(method, url, headers=headers, params=params, json=body, timeout=self.timeout)
            except requests.RequestException as e:
                last_exc = e
                if attempt < self.max_attempts:
                    self.sleep(min(60.0, 2.0 ** attempt))
                    continue
                break
            last_exc = None
            if resp.status_code < 300:
                try:
                    return resp.json() if resp.text else {}
                except (ValueError, requests.exceptions.JSONDecodeError):
                    raise DvaError(f"{method} {url} returned HTTP {resp.status_code} with a non-JSON body: {resp.text[:200]}")
            last_resp = resp
            if resp.status_code in RETRY_STATUS and attempt < self.max_attempts:
                retry_after = self._parse_retry_after(resp.headers.get("Retry-After"))
                if retry_after is None:
                    retry_after = min(60.0, 2.0 ** attempt)
                self.sleep(retry_after)
                continue
            break
        if last_exc:
            raise DvaError(f"{method} {url} failed after {self.max_attempts} attempts: {last_exc}")
        detail = ""
        try:
            detail = (last_resp.json().get("error") or {}).get("message", "") if last_resp is not None else ""
        except Exception:
            detail = (last_resp.text or "")[:200] if last_resp is not None else ""
        raise DvaError(f"{method} {url} failed with HTTP {last_resp.status_code}: {detail}")

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
