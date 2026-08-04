"""Lightweight in-process metrics.

Counters and gauges for the engagement (tools run, denials, findings, detection
verdicts). Deliberately dependency-free; a deployment exports these to
Prometheus/OTel. No wall-clock is captured here so the registry stays
deterministic and testable — callers pass any durations they measure.
"""

from __future__ import annotations

import threading
from collections import defaultdict


class Metrics:
    def __init__(self) -> None:
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = {}
        self._lock = threading.Lock()

    def incr(self, name: str, value: float = 1.0, **labels) -> None:
        with self._lock:
            self._counters[self._key(name, labels)] += value

    def gauge(self, name: str, value: float, **labels) -> None:
        with self._lock:
            self._gauges[self._key(name, labels)] = value

    def get(self, name: str, **labels) -> float:
        key = self._key(name, labels)
        with self._lock:
            return self._counters.get(key, self._gauges.get(key, 0.0))

    def snapshot(self) -> dict[str, float]:
        with self._lock:
            return {**self._counters, **self._gauges}

    @staticmethod
    def _key(name: str, labels: dict) -> str:
        if not labels:
            return name
        tags = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{tags}}}"
