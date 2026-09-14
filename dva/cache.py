from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dva.scoring import CveIntel


class IntelCache:
    def __init__(self, directory: Path, ttl_days: int):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(days=ttl_days)

    def _p(self, cve_id: str) -> Path:
        return self.dir / f"{cve_id.upper()}.json"

    def get(self, cve_id: str) -> CveIntel | None:
        p = self._p(cve_id)
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        fetched = d.get("fetched_at")
        if not fetched or datetime.fromisoformat(fetched) < datetime.now(timezone.utc) - self.ttl:
            return None
        return CveIntel(**{k: d.get(k) for k in CveIntel.__dataclass_fields__})

    def put(self, cve_id: str, intel: CveIntel) -> None:
        intel.fetched_at = intel.fetched_at or datetime.now(timezone.utc).isoformat()
        self._p(cve_id).write_text(json.dumps(asdict(intel)))

    def all_fresh(self, ids) -> dict[str, CveIntel]:
        out: dict[str, CveIntel] = {}
        for i in ids:
            v = self.get(i)
            if v is not None:
                out[i] = v
        return out
