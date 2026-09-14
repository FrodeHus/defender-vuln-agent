"""Minimal .env loader: KEY=VALUE lines, '#' comments, optional quotes.

Values already present in the process environment always win, so an exported
shell variable overrides the file. No third-party dependency.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def parse(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()
        out[key] = value
    return out


def find_env_file(start: Path | None = None) -> Path | None:
    """Look for .env in the current directory, then the repository root."""
    for candidate in (Path(start or os.getcwd()) / ".env", ROOT / ".env"):
        if candidate.is_file():
            return candidate
    return None


def load(path: Path | None = None) -> list[str]:
    """Load .env into os.environ without overriding existing variables. Returns the keys set."""
    p = path or find_env_file()
    if p is None:
        return []
    applied = []
    for key, value in parse(p.read_text(encoding="utf-8")).items():
        if key not in os.environ:
            os.environ[key] = value
            applied.append(key)
    return applied
