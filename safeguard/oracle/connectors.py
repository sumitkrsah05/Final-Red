"""Read-only detection connectors.

Each connector queries one defensive source over the action's time window and
maps its telemetry to a per-source verdict:

| Connector | Answers |
|-----------|---------|
| Wazuh/SIEM | Did a rule fire? which? severity? time-to-detect? |
| WAF        | Blocked / logged? which CRS rule? |
| EDR        | Process/behaviour flagged or contained? |
| PAM (Nandi)| Privileged access logged / challenged? |
| DAM (Jatayoo)| DB access recorded / anomaly-flagged? |

Connectors never mutate telemetry — ``read_only`` is True by construction.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from safeguard.oracle.models import DetectionEvent, Verdict
from safeguard.oracle.telemetry import TelemetryBackend


class DetectionConnector:
    read_only = True
    #: source key in the telemetry backend
    source = "generic"
    #: whether this control can actively block (WAF/EDR) vs. only observe
    can_block = False

    def __init__(self, backend: TelemetryBackend) -> None:
        self.backend = backend

    def query(self, target: str, start: datetime, end: datetime,
              technique: Optional[str] = None) -> list[DetectionEvent]:
        return self.backend.query(self.source, target, start, end, technique)

    def verdict(self, events: list[DetectionEvent]) -> Verdict:
        if not events:
            return Verdict.MISSED
        if self.can_block and any(e.blocked for e in events):
            return Verdict.BLOCKED
        if any(e.alerted for e in events):
            return Verdict.DETECTED
        return Verdict.PARTIAL  # logged only


class WazuhConnector(DetectionConnector):
    source = "wazuh"
    can_block = False


class WAFConnector(DetectionConnector):
    source = "waf"
    can_block = True


class EDRConnector(DetectionConnector):
    source = "edr"
    can_block = True


class PAMConnector(DetectionConnector):
    source = "pam"
    can_block = False


class DAMConnector(DetectionConnector):
    source = "dam"
    can_block = False


def default_connectors(backend: TelemetryBackend) -> list[DetectionConnector]:
    return [WazuhConnector(backend), WAFConnector(backend), EDRConnector(backend),
            PAMConnector(backend), DAMConnector(backend)]
