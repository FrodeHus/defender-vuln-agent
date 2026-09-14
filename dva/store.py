"""Per-tenant SQLite store for CVE intel and run history.

One file, ``<DVA_CACHE_DIR>/dva.sqlite`` by default, holds three tables:

    cve_intel(cve_id TEXT PRIMARY KEY, fields TEXT, fetched_at TEXT)
    runs(run_id TEXT PRIMARY KEY, tenant TEXT, generated_at TEXT, exposure_score REAL,
         secure_score REAL, summary TEXT)
    product_history(run_id TEXT, key TEXT, score INT, label TEXT, PRIMARY KEY(run_id, key))

CVE intel can instead be shared across tenants at ``<repo>/.cache/cve.sqlite`` when
``sources.yaml``'s ``shared_cve_cache`` is true; run history always stays per tenant.

The file is created with mode 600 inside a mode-700 directory, opened with WAL journaling.
Every failure surfaces as a single-line ``DvaError``.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from dva.config import load_sources
from dva.errors import DvaError

ROOT = Path(__file__).resolve().parent.parent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_intel (
    cve_id TEXT PRIMARY KEY,
    fields TEXT NOT NULL,
    fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    tenant TEXT,
    generated_at TEXT,
    exposure_score REAL,
    secure_score REAL,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS product_history (
    run_id TEXT,
    key TEXT,
    score INTEGER,
    label TEXT,
    PRIMARY KEY (run_id, key)
);
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            is_new = not self.path.exists()
            if is_new:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            self._conn = sqlite3.connect(self.path)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except (OSError, sqlite3.Error) as exc:
            raise DvaError(f"cannot open store at {self.path}: {exc}")

    def get_intel(self, cve_id: str) -> tuple[dict, str] | None:
        try:
            row = self._conn.execute(
                "SELECT fields, fetched_at FROM cve_intel WHERE cve_id = ?", (cve_id.upper(),)
            ).fetchone()
        except sqlite3.Error as exc:
            raise DvaError(f"store read failed for {cve_id}: {exc}")
        if row is None:
            return None
        try:
            return json.loads(row[0]), row[1]
        except json.JSONDecodeError:
            return None

    def put_intel(self, cve_id: str, fields: dict, fetched_at: str) -> None:
        try:
            self._conn.execute(
                "INSERT INTO cve_intel (cve_id, fields, fetched_at) VALUES (?, ?, ?) "
                "ON CONFLICT(cve_id) DO UPDATE SET fields = excluded.fields, fetched_at = excluded.fetched_at",
                (cve_id.upper(), json.dumps(fields), fetched_at),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise DvaError(f"store write failed for {cve_id}: {exc}")

    def touch_intel(self, cve_id: str, fetched_at: str) -> None:
        """Rewrite the fetched_at timestamp of an existing intel row (e.g. to age it in tests)."""
        try:
            self._conn.execute(
                "UPDATE cve_intel SET fetched_at = ? WHERE cve_id = ?",
                (fetched_at, cve_id.upper()),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise DvaError(f"store touch_intel failed for {cve_id}: {exc}")

    def record_run(self, run_id: str, tenant: str | None, summary: dict, products: list[dict]) -> None:
        try:
            self._conn.execute(
                "INSERT INTO runs (run_id, tenant, generated_at, exposure_score, secure_score, summary) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET tenant = excluded.tenant, "
                "generated_at = excluded.generated_at, exposure_score = excluded.exposure_score, "
                "secure_score = excluded.secure_score, summary = excluded.summary",
                (run_id, tenant, summary.get("generated_at"), summary.get("exposure_score"),
                 summary.get("secure_score"), json.dumps(summary)),
            )
            self._conn.execute("DELETE FROM product_history WHERE run_id = ?", (run_id,))
            self._conn.executemany(
                "INSERT INTO product_history (run_id, key, score, label) VALUES (?, ?, ?, ?)",
                [(run_id, p.get("key"), p.get("score"), p.get("label")) for p in products],
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise DvaError(f"store record_run failed for {run_id}: {exc}")

    def recent_runs(self, n: int) -> list[dict]:
        try:
            rows = self._conn.execute(
                "SELECT run_id, tenant, generated_at, exposure_score, secure_score, summary "
                "FROM runs ORDER BY run_id DESC LIMIT ?", (n,),
            ).fetchall()
        except sqlite3.Error as exc:
            raise DvaError(f"store recent_runs failed: {exc}")
        out: list[dict] = []
        for run_id, tenant, generated_at, exposure_score, secure_score, summary in reversed(rows):
            try:
                s = json.loads(summary) if summary else {}
            except json.JSONDecodeError:
                s = {}
            row = dict(s)
            row.update({"run_id": run_id, "tenant": tenant, "generated_at": generated_at,
                        "exposure_score": exposure_score, "secure_score": secure_score})
            out.append(row)
        return out

    def product_history(self, key: str, n: int) -> list[dict]:
        try:
            rows = self._conn.execute(
                "SELECT run_id, score, label FROM product_history WHERE key = ? "
                "ORDER BY run_id DESC LIMIT ?", (key, n),
            ).fetchall()
        except sqlite3.Error as exc:
            raise DvaError(f"store product_history failed for {key}: {exc}")
        return [{"run_id": r[0], "score": r[1], "label": r[2]} for r in reversed(rows)]

    def close(self) -> None:
        self._conn.close()


def open_store() -> Store:
    """Run-history store, always per tenant: ``<DVA_CACHE_DIR>/dva.sqlite``."""
    from dva.run import cache_dir
    return Store(cache_dir() / "dva.sqlite")


def open_intel_store(directory: Path) -> Store:
    """CVE-intel store: the repo-level shared file when ``shared_cve_cache`` is true,
    else ``<directory>/dva.sqlite``."""
    try:
        shared = load_sources().shared_cve_cache
    except Exception:
        shared = False
    if shared:
        return Store(ROOT / ".cache" / "cve.sqlite")
    return Store(Path(directory) / "dva.sqlite")
