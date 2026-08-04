"""Detection Oracle.

After an emulated action, ``observe`` queries every read-only connector over the
action's time window and target, then scores a single verdict. This is what
turns a scan into a control-validation exercise.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from safeguard.oracle.connectors import DetectionConnector, default_connectors
from safeguard.oracle.models import DetectionResult
from safeguard.oracle.scorer import CoverageScorer
from safeguard.oracle.telemetry import TelemetryBackend


class DetectionOracle:
    def __init__(
        self,
        connectors: list[DetectionConnector],
        *,
        scorer: Optional[CoverageScorer] = None,
        correlation_window_seconds: int = 300,
    ) -> None:
        self.connectors = connectors
        self.scorer = scorer or CoverageScorer()
        self.window = correlation_window_seconds

    @classmethod
    def from_backend(cls, backend: TelemetryBackend,
                     correlation_window_seconds: int = 300) -> "DetectionOracle":
        return cls(default_connectors(backend),
                   correlation_window_seconds=correlation_window_seconds)

    def observe(
        self,
        *,
        action_ref: str,
        target: str,
        technique: Optional[str],
        action_time: datetime,
        window_seconds: Optional[int] = None,
    ) -> DetectionResult:
        window = window_seconds or self.window
        start = action_time - timedelta(seconds=5)  # small pre-window for clock skew
        end = action_time + timedelta(seconds=window)
        per_connector = [
            (c, c.query(target, start, end, technique)) for c in self.connectors
        ]
        return self.scorer.score(
            action_ref=action_ref, target=target, technique=technique,
            action_time=action_time, per_connector=per_connector)
