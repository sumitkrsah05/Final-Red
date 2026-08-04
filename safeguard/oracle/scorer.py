"""Coverage & MTTD scorer.

Turns per-source telemetry into one ``DetectionResult`` for an action: the
aggregate verdict is the best across sources (BLOCKED > DETECTED > PARTIAL >
MISSED), and time-to-detect is the earliest detection relative to the action
time.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from safeguard.oracle.connectors import DetectionConnector
from safeguard.oracle.models import (
    DetectionEvent,
    DetectionResult,
    Verdict,
    best_verdict,
)


class CoverageScorer:
    def score(
        self,
        *,
        action_ref: str,
        target: str,
        technique: Optional[str],
        action_time: datetime,
        per_connector: list[tuple[DetectionConnector, list[DetectionEvent]]],
    ) -> DetectionResult:
        per_source: list[dict] = []
        verdicts: list[Verdict] = []
        ttds: list[float] = []
        winning_rule: Optional[str] = None
        best_so_far = Verdict.MISSED

        for connector, events in per_connector:
            v = connector.verdict(events)
            verdicts.append(v)
            ttd = self._ttd(action_time, events) if v.covered else None
            rule = self._rule(events)
            if ttd is not None:
                ttds.append(ttd)
            # track the rule from the strongest-covering source
            if v.covered and _rank(v) >= _rank(best_so_far):
                best_so_far, winning_rule = v, rule
            per_source.append({"source": connector.source, "verdict": v.value,
                               "rule_id": rule, "ttd_seconds": ttd,
                               "events": len(events)})

        agg = best_verdict(verdicts)
        return DetectionResult(
            action_ref=action_ref, target=target, technique=technique,
            verdict=agg, source="aggregate", rule_id=winning_rule,
            ttd_seconds=(min(ttds) if ttds else None), per_source=per_source)

    @staticmethod
    def _ttd(action_time: datetime, events: list[DetectionEvent]) -> Optional[float]:
        deltas = [(e.ts - action_time).total_seconds()
                  for e in events if (e.alerted or e.blocked)]
        deltas = [d for d in deltas if d >= 0]
        return round(min(deltas), 3) if deltas else None

    @staticmethod
    def _rule(events: list[DetectionEvent]) -> Optional[str]:
        for e in events:
            if e.rule_id:
                return e.rule_id
        return None


def _rank(v: Verdict) -> int:
    return {Verdict.BLOCKED: 3, Verdict.DETECTED: 2,
            Verdict.PARTIAL: 1, Verdict.MISSED: 0}[v]
