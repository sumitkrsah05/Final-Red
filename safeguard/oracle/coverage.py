"""Coverage matrix — aggregate detection results into the purple-team product.

Computes overall detection coverage, per-technique coverage, mean time-to-detect,
and the gap list (every MISSED/PARTIAL) that feeds the Detect/Act loops.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from safeguard.oracle.models import DetectionResult, Verdict


@dataclass
class CoverageMatrix:
    results: list[DetectionResult] = field(default_factory=list)

    def add(self, result: DetectionResult) -> None:
        self.results.append(result)

    @property
    def total(self) -> int:
        return len(self.results)

    def coverage_pct(self) -> float:
        if not self.results:
            return 0.0
        covered = sum(1 for r in self.results if r.verdict.covered)
        return round(100.0 * covered / len(self.results), 1)

    def mean_ttd(self) -> float | None:
        ttds = [r.ttd_seconds for r in self.results if r.ttd_seconds is not None]
        return round(sum(ttds) / len(ttds), 2) if ttds else None

    def by_verdict(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.results:
            counts[r.verdict.value] = counts.get(r.verdict.value, 0) + 1
        return counts

    def by_technique(self) -> dict[str, dict[str, int]]:
        matrix: dict[str, dict[str, int]] = {}
        for r in self.results:
            tech = r.technique or "unknown"
            cell = matrix.setdefault(tech, {})
            cell[r.verdict.value] = cell.get(r.verdict.value, 0) + 1
        return matrix

    def gaps(self) -> list[dict]:
        """Every MISSED/PARTIAL action — the actionable detection-gap feed."""
        return [
            {"action_ref": r.action_ref, "target": r.target,
             "technique": r.technique, "verdict": r.verdict.value,
             "expected_source": "wazuh/waf"}
            for r in self.results
            if r.verdict in (Verdict.MISSED, Verdict.PARTIAL)
        ]

    def summary(self) -> dict:
        return {"total_actions": self.total, "coverage_pct": self.coverage_pct(),
                "mean_ttd_seconds": self.mean_ttd(), "verdicts": self.by_verdict(),
                "gaps": self.gaps()}
