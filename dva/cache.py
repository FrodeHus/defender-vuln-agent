from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dva.scoring import CveIntel
from dva.store import open_intel_store


class IntelCache:
    """CVE intel cache backed entirely by the SQLite store: get/put/all_fresh read and write
    only ``self.store``. Pre-existing per-file JSON entries (from before this cache was
    store-backed) are imported into the store once, the first time a directory is opened;
    after that the JSON files are never read again, even if new ones appear later."""

    def __init__(self, directory: Path, ttl_days: int):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(days=ttl_days)
        self.store = open_intel_store(self.dir)
        self._import_legacy()

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

    def get(self, cve_id: str) -> CveIntel | None:
        row = self.store.get_intel(cve_id)
        if row is None:
            return None
        fields, fetched_at = row
        if not fetched_at:
            return None
        try:
            if datetime.fromisoformat(fetched_at) < datetime.now(timezone.utc) - self.ttl:
                return None
            return CveIntel(**{k: fields.get(k) for k in CveIntel.__dataclass_fields__})
        except (ValueError, TypeError):
            return None

    def put(self, cve_id: str, intel: CveIntel) -> None:
        intel.fetched_at = intel.fetched_at or datetime.now(timezone.utc).isoformat()
        self.store.put_intel(cve_id, asdict(intel), intel.fetched_at)

    def all_fresh(self, ids) -> dict[str, CveIntel]:
        out: dict[str, CveIntel] = {}
        for i in ids:
            v = self.get(i)
            if v is not None:
                out[i] = v
        return out

    def close(self) -> None:
        self.store.close()
