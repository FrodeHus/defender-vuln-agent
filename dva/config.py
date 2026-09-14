from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"


@dataclass
class Scoring:
    threat_weights: dict[str, float]
    asset_bonus: dict[str, float]
    asset_cap: float
    criticality_tags: list[str]
    enrich_top_per_product: int
    enrich_max_cves: int
    report_threshold: int
    top_n: int
    cache_ttl_days: int
    bands: dict[str, int]


@dataclass
class Sources:
    mde: bool = True
    hunting: bool = True
    cloud: bool = False
    subscriptions: list[str] = field(default_factory=list)
    hunting_queries: list[str] = field(default_factory=list)


def _read(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_scoring(path: Path | None = None) -> Scoring:
    return Scoring(**_read(path or CONFIG_DIR / "scoring.yaml"))


def load_sources(path: Path | None = None) -> Sources:
    return Sources(**_read(path or CONFIG_DIR / "sources.yaml"))
