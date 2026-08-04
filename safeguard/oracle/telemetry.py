"""Telemetry backend abstraction.

Connectors query telemetry through a ``TelemetryBackend``. In production each
maps to a real read-only source (Wazuh API, Coraza/ModSecurity logs, EDR API,
Nandi PAM, Jatayoo DAM) using dedicated read-only service accounts. Phase 7
ships the interface plus an in-memory backend for deterministic dev/tests; the
real backends slot in behind the same ``query`` contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from safeguard.oracle.models import DetectionEvent


class TelemetryBackend(ABC):
    read_only = True

    @abstractmethod
    def query(self, source: str, target: str, start: datetime, end: datetime,
              technique: Optional[str] = None) -> list[DetectionEvent]:
        ...


class InMemoryTelemetryBackend(TelemetryBackend):
    """Deterministic backend for dev/tests. Events are added out-of-band (as if
    the Blue Team stack recorded them); queries are read-only."""

    def __init__(self) -> None:
        self._events: list[DetectionEvent] = []

    def add(self, event: DetectionEvent) -> None:
        self._events.append(event)

    def query(self, source: str, target: str, start: datetime, end: datetime,
              technique: Optional[str] = None) -> list[DetectionEvent]:
        out = []
        for e in self._events:
            if e.source != source:
                continue
            if not _target_matches(e.target, target):
                continue
            if not (start <= e.ts <= end):
                continue
            out.append(e)
        return out


def _target_matches(event_target: str, query_target: str) -> bool:
    a = _host(event_target)
    b = _host(query_target)
    return a == b or a in b or b in a


def _host(t: str) -> str:
    t = t.split("?")[0]
    if "://" in t:
        t = t.split("://", 1)[1]
    return t.split("/")[0].split(":")[0]
