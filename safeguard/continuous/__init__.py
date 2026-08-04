"""Phase 10 — Continuous validation.

Schedules engagements per asset group, keeps a baseline of report bundles, and
computes regressions (a technique that was DETECTED/BLOCKED last run is now
MISSED/PARTIAL) plus new gaps — turning point-in-time assessment into a
continuous control-assurance signal for the SOC.
"""

from safeguard.continuous.baseline import BaselineStore, RegressionReport, diff_reports
from safeguard.continuous.runner import ContinuousRunner

__all__ = ["BaselineStore", "RegressionReport", "diff_reports", "ContinuousRunner"]
