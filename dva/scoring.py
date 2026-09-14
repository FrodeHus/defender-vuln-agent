from __future__ import annotations
import math
from dataclasses import dataclass, field
from dva.config import Scoring
from dva.model import Asset, CveRef, Product, EXPLOIT_RANK, SEVERITIES

_EXPLOIT_TERM = {"NoExploit": 0.0, "ExploitIsPublic": 0.5, "ExploitIsVerified": 0.75, "ExploitIsInKit": 1.0}


@dataclass
class CveIntel:
    cvss: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_added: str | None = None
    ransomware: bool = False
    exploit_public: bool = False
    exploit_sources: list[str] = field(default_factory=list)
    exploit_maturity: float | None = None
    advisories: list[dict] = field(default_factory=list)
    title: str | None = None
    cwe: str | None = None
    description: str | None = None
    vector: str | None = None
    fetched_at: str | None = None


@dataclass
class ScoredProduct:
    product: Product
    score: int
    label: str
    driving: list[tuple[CveRef, float]]
    counts: dict[str, int]
    asset_mean: float
    reach: float
    flags: dict[str, bool]
    top_assets: list[tuple[Asset, float, str]]


def threat_score(ref: CveRef, intel: CveIntel | None, cfg: Scoring) -> float:
    w = cfg.threat_weights
    cvss = (intel.cvss if intel and intel.cvss is not None else ref.cvss) or 0.0
    epss = (intel.epss_percentile if intel and intel.epss_percentile is not None else 0.0)
    kev = 1.0 if intel and intel.kev else 0.0
    if intel and intel.exploit_maturity is not None:
        exploit = intel.exploit_maturity
    elif intel and intel.exploit_public:
        exploit = 1.0
    else:
        exploit = _EXPLOIT_TERM.get(ref.exploitability, 0.0)
    ransomware = 1.0 if intel and intel.ransomware else 0.0
    return (
        w["cvss"] * cvss / 10.0
        + w["epss"] * epss
        + w["kev"] * kev
        + w["exploit"] * exploit
        + w.get("ransomware", 0.0) * ransomware
    )


def asset_signals(asset: Asset, cfg: Scoring) -> list[tuple[str, float]]:
    b = cfg.asset_bonus
    sig: list[tuple[str, float]] = []
    if asset.internet_facing:
        sig.append(("Internet-facing", b["internet_facing"]))
    for t in asset.tags:
        if any(t.lower() == pat.lower() for pat in cfg.criticality_tags):
            sig.append((t, b["criticality_tag"]))
    if (asset.device_value or "").lower() == "high":
        sig.append(("High value", b["device_value_high"]))
    if (asset.exposure_level or "").lower() == "high":
        sig.append(("Exposure High", b["exposure_high"]))
    elif (asset.exposure_level or "").lower() == "medium":
        sig.append(("Exposure Medium", b["exposure_medium"]))
    if asset.public_lb:
        sig.append(("Public LoadBalancer", b["public_lb"]))
    if asset.privileged_user:
        sig.append(("Privileged user signs in", b["privileged_user"]))
    if asset.mitigations:
        sig.append((f"Mitigated: {asset.mitigations} controls", b["mitigated"]))
    if asset.attack_paths:
        extra = f" (+{len(asset.attack_paths) - 1} more)" if len(asset.attack_paths) > 1 else ""
        sig.append((f"On attack path: {asset.attack_paths[0]}{extra}", b["attack_path"]))
    return sig


def asset_multiplier(asset: Asset, cfg: Scoring) -> float:
    return min(cfg.asset_cap, 1.0 + sum(v for _, v in asset_signals(asset, cfg)))


def label_for(score: int, cfg: Scoring) -> str:
    if score >= cfg.bands["critical"]:
        return "Critical"
    if score >= cfg.bands["high"]:
        return "High"
    if score >= cfg.bands["medium"]:
        return "Medium"
    return "Low"


def product_score(p: Product, assets: dict[str, Asset], intel: dict[str, CveIntel], cfg: Scoring, estate_size: int, overdue: bool = False) -> ScoredProduct:
    threats = sorted(((ref, threat_score(ref, intel.get(ref.id), cfg)) for ref in p.cves.values()), key=lambda x: (-x[1], -x[0].cvss, x[0].id))
    driving = threats[:3]
    top3 = sum(t for _, t in driving) / len(driving) if driving else 0.0
    ranked_assets = sorted(((assets.get(a) or Asset(id=a, name=a)) for a in p.asset_ids), key=lambda a: (-asset_multiplier(a, cfg), a.name))
    mults = [asset_multiplier(a, cfg) for a in ranked_assets]
    if mults:
        weights = [2.0 if i < 5 else 1.0 for i in range(len(mults))]
        asset_mean = sum(m * w for m, w in zip(mults, weights)) / sum(weights)
    else:
        asset_mean = 1.0
    reach = math.log10(1 + len(p.asset_ids)) / math.log10(1 + max(estate_size, 1)) if estate_size > 0 else 0.0
    any_kev = any(intel.get(r.id) and intel[r.id].kev for r, _ in driving)
    any_inet = any(a.internet_facing for a in ranked_assets)
    boost = 1.25 if (any_kev and any_inet) else 1.0
    raw = top3 * (0.6 + 0.3 * asset_mean / cfg.asset_cap + 0.1 * reach) * boost
    if overdue:
        raw *= cfg.overdue_boost
    score = int(round(100 * min(1.0, raw)))
    counts = {s.lower(): sum(1 for r in p.cves.values() if r.severity == s) for s in SEVERITIES}
    flags = {
        "kev": any_kev,
        "exploit": any((intel.get(r.id) and intel[r.id].exploit_public) or EXPLOIT_RANK.get(r.exploitability, 0) >= 1 for r in p.cves.values()),
        "internet_facing": any_inet,
    }
    top_assets = [(a, asset_multiplier(a, cfg), " · ".join(n for n, _ in asset_signals(a, cfg)) or "No extra exposure") for a in ranked_assets[:5]]
    return ScoredProduct(p, score, label_for(score, cfg), driving, counts, asset_mean, reach, flags, top_assets)


def reason_for(sp: ScoredProduct) -> str:
    bits = []
    if sp.flags["internet_facing"]:
        bits.append("internet-facing hosts affected")
    if sp.flags["kev"]:
        bits.append("KEV-listed CVE")
    elif sp.flags["exploit"]:
        bits.append("public exploit available")
    if len(sp.product.asset_ids) >= 100:
        bits.append(f"{len(sp.product.asset_ids)} devices affected")
    if sp.counts["critical"]:
        bits.append(f"{sp.counts['critical']} critical CVEs")
    return ", ".join(bits).capitalize() if bits else "Open vulnerabilities without exposure signals"
