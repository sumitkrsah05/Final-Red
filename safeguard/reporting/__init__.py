"""Phase 8 — Reporting & Evidence.

Turns the final engagement state into the deliverables humans and the Detect/Act
loops consume: a technical report, an executive summary, an ATT&CK coverage
heatmap (technique × detected/missed), and the detection-gap report. Every
figure is grounded (numeric-claim verifier); evidence is content-addressed.
"""

from safeguard.reporting.heatmap import AttackHeatmap
from safeguard.reporting.report import ReportBundle, Reporter

__all__ = ["AttackHeatmap", "ReportBundle", "Reporter"]
