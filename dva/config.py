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
    enrich_threshold: int
    report_threshold: int
    top_n: int
    cache_ttl_days: int
    bands: dict[str, int]
    sla_days: dict[str, int]
    overdue_boost: float
    mitigation_configs: list[str]
    exception_components: list[str]
    trend_runs: int
    long_standing_days: int = 90
    score_weights: dict[str, float] = field(default_factory=lambda: {"base": 0.5, "asset": 0.3, "reach": 0.2})
    severity_floor: dict[str, int] = field(default_factory=lambda: {"critical": 40})
    embedded_discount: float = 0.5
    max_paths: int = 10


@dataclass
class Sources:
    mde: bool = True
    hunting: bool = True
    cloud: bool = False
    subscriptions: list[str] = field(default_factory=list)
    hunting_queries: list[str] = field(default_factory=list)
    shared_cve_cache: bool = False
    kev: bool = True


def _read(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _tenant_override(filename: str) -> Path | None:
    from dva.tenant import override_path
    return override_path(filename)


def load_scoring(path: Path | None = None) -> Scoring:
    """Repo defaults, fully replaced by tenants/<name>/scoring.yaml when the active tenant has one."""
    return Scoring(**_read(path or _tenant_override("scoring.yaml") or CONFIG_DIR / "scoring.yaml"))


def load_sources(path: Path | None = None) -> Sources:
    """Repo defaults, with tenants/<name>/sources.yaml keys merged over them when present."""
    if path is not None:
        return Sources(**_read(path))
    data = _read(CONFIG_DIR / "sources.yaml")
    override = _tenant_override("sources.yaml")
    if override:
        data.update(_read(override))
    return Sources(**data)
