"""Risk scoring — CVSS + EPSS + asset criticality + detection status.

The defining twist of Safeguard's scoring (per the design): *detection status is
a first-class factor.* An undetected medium can outrank a detected high, because
the product is control validation, not raw vulnerability severity.

Score is 0–100:
    base        = CVSS (0–10) × 10                      → 0–100
    likelihood  = ×(1 + EPSS)                           exploit probability
    criticality = ×(0.6 + 0.8 × asset_criticality)      0..1 → 0.6..1.4
    detection   = MISSED ×1.4 · PARTIAL ×1.15 · DETECTED ×0.8 · BLOCKED ×0.6
                  (unknown ×1.0 until the Oracle runs, Phase 7)
Clamped to [0, 100]. When CVSS is absent, a severity-derived base is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from safeguard.tools.schema import Severity

_SEVERITY_BASE = {
    Severity.INFO: 1.0, Severity.LOW: 3.0, Severity.MEDIUM: 5.0,
    Severity.HIGH: 7.5, Severity.CRITICAL: 9.5,
}
_DETECTION_FACTOR = {
    "MISSED": 1.4, "PARTIAL": 1.15, "UNKNOWN": 1.0,
    "DETECTED": 0.8, "BLOCKED": 0.6,
}


@dataclass(frozen=True)
class RiskScore:
    score: float
    priority: str  # "critical" | "high" | "medium" | "low" | "info"
    factors: dict


class RiskScorer:
    def score(
        self,
        *,
        cvss: Optional[float] = None,
        epss: Optional[float] = None,
        severity: Severity = Severity.INFO,
        asset_criticality: float = 0.5,
        detection_status: str = "UNKNOWN",
    ) -> RiskScore:
        base10 = cvss if cvss is not None else _SEVERITY_BASE[severity]
        base = base10 * 10.0
        likelihood = 1.0 + (epss or 0.0)
        crit = 0.6 + 0.8 * _clamp01(asset_criticality)
        det = _DETECTION_FACTOR.get(detection_status.upper(), 1.0)
        raw = base * likelihood * crit * det
        score = max(0.0, min(100.0, raw))
        return RiskScore(score=round(score, 1), priority=_priority(score),
                         factors={"base10": base10, "epss": epss or 0.0,
                                  "asset_criticality": asset_criticality,
                                  "detection": detection_status.upper()})


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _priority(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"
