"""Baseline store and regression diff.

A baseline is a prior ``report.json`` bundle. The diff compares two bundles and
surfaces:
  * **regressions** — a (technique, host) that was covered (DETECTED/BLOCKED) and
    is now MISSED/PARTIAL. *This is the headline signal.*
  * **improvements** — the reverse (a gap now covered).
  * **new_gaps / resolved_gaps** — keys missing/present only on one side.
  * **new_findings / resolved_findings** — by finding id.
  * **coverage_delta** — change in overall detection coverage %.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_COVERED = {"DETECTED", "BLOCKED"}


@dataclass
class RegressionReport:
    engagement_id: str
    has_baseline: bool
    coverage_delta: float = 0.0
    regressions: list[dict] = field(default_factory=list)
    improvements: list[dict] = field(default_factory=list)
    new_gaps: list[str] = field(default_factory=list)
    resolved_gaps: list[str] = field(default_factory=list)
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressions)

    def summary(self) -> dict:
        return {"engagement_id": self.engagement_id,
                "has_baseline": self.has_baseline,
                "coverage_delta": self.coverage_delta,
                "regressions": self.regressions,
                "improvements": self.improvements,
                "new_gaps": self.new_gaps,
                "resolved_gaps": self.resolved_gaps,
                "new_findings": self.new_findings,
                "resolved_findings": self.resolved_findings}


def _covered(verdict: str) -> bool:
    return verdict in _COVERED


def diff_reports(baseline: Optional[dict], current: dict) -> RegressionReport:
    engagement_id = current.get("engagement_id", "")
    if not baseline:
        return RegressionReport(engagement_id=engagement_id, has_baseline=False)

    b_idx = baseline.get("detection_index", {}) or {}
    c_idx = current.get("detection_index", {}) or {}

    regressions, improvements = [], []
    for key, c_verdict in c_idx.items():
        if key in b_idx:
            b_verdict = b_idx[key]
            if _covered(b_verdict) and not _covered(c_verdict):
                regressions.append({"key": key, "was": b_verdict, "now": c_verdict})
            elif not _covered(b_verdict) and _covered(c_verdict):
                improvements.append({"key": key, "was": b_verdict, "now": c_verdict})

    new_gaps = sorted(k for k, v in c_idx.items()
                      if not _covered(v) and k not in b_idx)
    resolved_gaps = sorted(k for k, v in b_idx.items()
                           if not _covered(v) and k not in c_idx)

    b_finds = {f["id"] for f in baseline.get("findings", [])}
    c_finds = {f["id"] for f in current.get("findings", [])}
    new_findings = sorted(c_finds - b_finds)
    resolved_findings = sorted(b_finds - c_finds)

    b_cov = (baseline.get("detection_coverage", {}) or {}).get("coverage_pct", 0.0)
    c_cov = (current.get("detection_coverage", {}) or {}).get("coverage_pct", 0.0)

    return RegressionReport(
        engagement_id=engagement_id, has_baseline=True,
        coverage_delta=round(c_cov - b_cov, 1),
        regressions=regressions, improvements=improvements,
        new_gaps=new_gaps, resolved_gaps=resolved_gaps,
        new_findings=new_findings, resolved_findings=resolved_findings)


class BaselineStore:
    """Append-only store of report bundles per engagement, newest last."""

    def __init__(self, root: str | Path = "runs") -> None:
        self.root = Path(root)

    def _dir(self, engagement_id: str) -> Path:
        d = self.root / engagement_id / "baselines"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save(self, engagement_id: str, report_data: dict) -> str:
        d = self._dir(engagement_id)
        n = len(list(d.glob("baseline-*.json")))
        path = d / f"baseline-{n:04d}.json"
        path.write_text(json.dumps(report_data, indent=2, default=str),
                        encoding="utf-8")
        return str(path)

    def latest(self, engagement_id: str) -> Optional[dict]:
        d = self._dir(engagement_id)
        files = sorted(d.glob("baseline-*.json"))
        if not files:
            return None
        return json.loads(files[-1].read_text(encoding="utf-8"))

    def count(self, engagement_id: str) -> int:
        return len(list(self._dir(engagement_id).glob("baseline-*.json")))
