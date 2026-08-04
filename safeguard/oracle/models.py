"""Detection Oracle data model.

``DetectionResult`` is *the product*: a finding with ``verdict=MISSED`` is worth
more to Detect/Act than ten detected criticals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    BLOCKED = "BLOCKED"      # the stack stopped the action (best)
    DETECTED = "DETECTED"    # an alert/rule fired
    PARTIAL = "PARTIAL"      # logged but not alerted
    MISSED = "MISSED"        # nothing (the gap)

    @property
    def covered(self) -> bool:
        return self in (Verdict.BLOCKED, Verdict.DETECTED)


# Best-first precedence for aggregating across sources.
_PRECEDENCE = {Verdict.BLOCKED: 3, Verdict.DETECTED: 2, Verdict.PARTIAL: 1,
               Verdict.MISSED: 0}


def best_verdict(verdicts: list[Verdict]) -> Verdict:
    if not verdicts:
        return Verdict.MISSED
    return max(verdicts, key=lambda v: _PRECEDENCE[v])


@dataclass
class DetectionEvent:
    """One telemetry record from a defensive source (read-only)."""

    source: str          # wazuh | waf | edr | pam | dam
    ts: datetime
    target: str
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    message: str = ""
    alerted: bool = True   # a rule/alert fired (vs. logged only)
    blocked: bool = False  # the request/action was stopped (WAF/EDR)


@dataclass
class DetectionResult:
    """Per-action detection verdict, optionally aggregated across sources."""

    action_ref: str
    target: str
    technique: Optional[str]
    verdict: Verdict
    source: str                       # connector name, or "aggregate"
    rule_id: Optional[str] = None
    ttd_seconds: Optional[float] = None
    per_source: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"action_ref": self.action_ref, "target": self.target,
                "technique": self.technique, "verdict": self.verdict.value,
                "source": self.source, "rule_id": self.rule_id,
                "ttd_seconds": self.ttd_seconds, "per_source": self.per_source}
