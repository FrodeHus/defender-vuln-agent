from __future__ import annotations
import re
from dataclasses import dataclass, field

EXPLOIT_RANK = {"NoExploit": 0, "ExploitIsPublic": 1, "ExploitIsVerified": 2, "ExploitIsInKit": 3}
SEVERITIES = ("Critical", "High", "Medium", "Low")


def product_key(vendor: str | None, name: str | None) -> str:
    def norm(s):
        return re.sub(r"[\s_]+", "-", (s or "unknown").strip().lower())
    return f"{norm(vendor)}/{norm(name)}"


@dataclass
class Asset:
    id: str
    name: str
    kind: str = "device"
    internet_facing: bool = False
    exposure_level: str | None = None
    device_value: str | None = None
    tags: list[str] = field(default_factory=list)
    group: str | None = None
    public_lb: bool = False
    privileged_user: bool = False
    mitigations: int = 0
    azure_resource_id: str | None = None
    attack_paths: list[str] = field(default_factory=list)


@dataclass
class CveRef:
    id: str
    severity: str
    cvss: float
    exploitability: str
    first_seen: str | None


@dataclass
class Product:
    key: str
    vendor: str
    name: str
    versions: dict[str, int] = field(default_factory=dict)
    cves: dict[str, CveRef] = field(default_factory=dict)
    asset_ids: set[str] = field(default_factory=set)
    remediation: str | None = None
    remediation_type: str | None = None
    recommended_version: str | None = None
    eos: dict | None = None
    fixes: dict[str, set[str]] = field(default_factory=dict)
