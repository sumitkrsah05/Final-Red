"""Detect-loop integration — turn detection gaps into rule candidates.

Each MISSED/PARTIAL gap becomes a candidate correlation rule for the Detect loop
(SIEM/WAF), carrying the technique, the target, and the expected detection. In
this build candidates are returned/written to an outbox; production posts them to
the Detect API.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class RuleCandidate:
    technique: str
    target: str
    verdict: str
    expected_detection: str
    proposed_source: str  # wazuh | waf
    priority: str = "medium"

    def as_dict(self) -> dict:
        return asdict(self)


class DetectIntegration:
    def rule_candidates(self, report_data: dict) -> list[RuleCandidate]:
        gaps = report_data.get("gaps", []) or []
        out: list[RuleCandidate] = []
        for g in gaps:
            expected = g.get("expected_detection", "")
            source = "waf" if "WAF" in expected or "CRS" in expected else "wazuh"
            out.append(RuleCandidate(
                technique=g.get("technique") or "unknown",
                target=g.get("target", ""),
                verdict=g.get("verdict", "MISSED"),
                expected_detection=expected, proposed_source=source,
                priority="high" if g.get("verdict") == "MISSED" else "medium"))
        return out

    def push(self, report_data: dict, outbox: str | Path) -> str:
        candidates = [c.as_dict() for c in self.rule_candidates(report_data)]
        out = Path(outbox)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "detect_rule_candidates.json"
        path.write_text(json.dumps(candidates, indent=2), encoding="utf-8")
        return str(path)
