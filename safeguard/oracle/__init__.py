"""Phase 7 — Detection Oracle (the differentiator).

After every emulated action, ask the Blue Team stack whether it noticed. Each
connector is **read-only** and queried for the action's time window and target;
the coverage & MTTD scorer turns raw telemetry into a per-action verdict
(DETECTED / PARTIAL / MISSED / BLOCKED) plus time-to-detect. Aggregated, this is
the detection-coverage matrix and the gap feed to Detect/Act.

All connectors are read-only by construction — they query telemetry, never
mutate it.
"""

from safeguard.oracle.models import (
    DetectionEvent,
    DetectionResult,
    Verdict,
)
from safeguard.oracle.telemetry import InMemoryTelemetryBackend, TelemetryBackend
from safeguard.oracle.connectors import (
    DAMConnector,
    DetectionConnector,
    EDRConnector,
    PAMConnector,
    WAFConnector,
    WazuhConnector,
    default_connectors,
)
from safeguard.oracle.scorer import CoverageScorer
from safeguard.oracle.oracle import DetectionOracle
from safeguard.oracle.coverage import CoverageMatrix

__all__ = [
    "DetectionEvent",
    "DetectionResult",
    "Verdict",
    "TelemetryBackend",
    "InMemoryTelemetryBackend",
    "DetectionConnector",
    "WazuhConnector",
    "WAFConnector",
    "EDRConnector",
    "PAMConnector",
    "DAMConnector",
    "default_connectors",
    "CoverageScorer",
    "DetectionOracle",
    "CoverageMatrix",
]
