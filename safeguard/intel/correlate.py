"""Attack-path correlator.

Chains enriched findings into candidate kill-chains: findings on the same asset
are ordered along the ATT&CK tactic sequence to form a path (e.g. Discovery →
Initial Access → Execution). Each step is annotated with its technique and its
detection verdict (``UNKNOWN`` until the Detection Oracle runs in Phase 7). The
path's overall risk is the max step risk.

The paths are *candidates* — hypotheses for the report and the Oracle to test.
Nothing here executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from safeguard.intel.attack import AttackMap
from safeguard.tools.schema import Finding


@dataclass
class PathStep:
    finding_ref: str
    title: str
    technique_id: Optional[str]
    tactic: Optional[str]
    detection: str
    risk: float

    def as_dict(self) -> dict:
        return {"finding_ref": self.finding_ref, "title": self.title,
                "technique_id": self.technique_id, "tactic": self.tactic,
                "detection": self.detection, "risk": self.risk}


@dataclass
class AttackPath:
    asset: str
    steps: list[PathStep] = field(default_factory=list)
    overall_risk: float = 0.0

    def as_dict(self) -> dict:
        return {"asset": self.asset, "overall_risk": self.overall_risk,
                "steps": [s.as_dict() for s in self.steps]}


class AttackPathCorrelator:
    def __init__(self, attack: Optional[AttackMap] = None) -> None:
        self.attack = attack or AttackMap()

    def build(self, findings: list[Finding],
              detection_status: Optional[dict[str, str]] = None) -> list[AttackPath]:
        detection_status = detection_status or {}
        by_asset: dict[str, list[Finding]] = {}
        for f in findings:
            by_asset.setdefault(_asset_root(f.asset_ref), []).append(f)

        paths: list[AttackPath] = []
        for asset, group in by_asset.items():
            steps: list[PathStep] = []
            for f in group:
                techs = f.raw.get("attack_techniques") or []
                tech = techs[0] if techs else {}
                risk = float((f.raw.get("risk") or {}).get("score", 0.0))
                steps.append(PathStep(
                    finding_ref=f.id, title=f.title,
                    technique_id=tech.get("technique_id"),
                    tactic=tech.get("tactic"),
                    detection=detection_status.get(f.asset_ref, "UNKNOWN"),
                    risk=risk))
            steps.sort(key=lambda s: (self.attack.tactic_rank(s.tactic or ""),
                                      -s.risk))
            if steps:
                paths.append(AttackPath(
                    asset=asset, steps=steps,
                    overall_risk=round(max(s.risk for s in steps), 1)))
        paths.sort(key=lambda p: -p.overall_risk)
        return paths


def _asset_root(asset_ref: str) -> str:
    # Group endpoints of the same host together (strip path/query).
    ref = asset_ref.split("?")[0]
    if "://" in ref:
        rest = ref.split("://", 1)[1]
        return rest.split("/")[0]
    return ref.split("/")[0]
