from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dva.scoring import CveIntel
from dva.store import open_intel_store


class IntelCache:
    def __init__(self, directory: Path, ttl_days: int):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(days=ttl_days)
        self.store = open_intel_store(self.dir)
        self._import_legacy()

    def _p(self, cve_id: str) -> Path:
        return self.dir / f"{cve_id.upper()}.json"

    def _import_legacy(self) -> None:
        """Pull pre-existing per-file JSON entries into the store, once. Files that are already
        represented in the store, or that fail to parse, are left on disk untouched."""
        for p in self.dir.glob("CVE-*.json"):
            cve_id = p.stem
            if self.store.get_intel(cve_id) is not None:
                continue
            try:
                d = json.loads(p.read_text())
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict):
                continue
            fetched = d.get("fetched_at")
            if not fetched:
                continue
            self.store.put_intel(cve_id, d, fetched)

    def _fresh(self, fields: dict | None, fetched_at: str | None) -> CveIntel | None:
        if fields is None or not fetched_at:
            return None
        try:
            if datetime.fromisoformat(fetched_at) < datetime.now(timezone.utc) - self.ttl:
                return None
            return CveIntel(**{k: fields.get(k) for k in CveIntel.__dataclass_fields__})
        except (ValueError, TypeError):
            return None

    def get(self, cve_id: str) -> CveIntel | None:
        p = self._p(cve_id)
        if p.exists():
            try:
                d = json.loads(p.read_text())
            except json.JSONDecodeError:
                return None
            if not isinstance(d, dict):
                return None
            return self._fresh(d, d.get("fetched_at"))
        row = self.store.get_intel(cve_id)
        if row is None:
            return None
        fields, fetched_at = row
        return self._fresh(fields, fetched_at)

    def put(self, cve_id: str, intel: CveIntel) -> None:
        intel.fetched_at = intel.fetched_at or datetime.now(timezone.utc).isoformat()
        fields = asdict(intel)
        self._p(cve_id).write_text(json.dumps(fields))
        self.store.put_intel(cve_id, fields, intel.fetched_at)

    def all_fresh(self, ids) -> dict[str, CveIntel]:
        out: dict[str, CveIntel] = {}
        for i in ids:
            v = self.get(i)
            if v is not None:
                out[i] = v
        return out
