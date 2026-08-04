"""Immutable, hash-chained audit log.

Every plan, tool proposal, approval, tool call, and result is appended as an
``AuditEvent`` whose hash includes the previous event's hash. Tampering with any
record breaks the chain, which ``verify()`` detects. Append-only: the log is
written as JSON Lines and never rewritten in place.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    ts: str  # ISO-8601 UTC, supplied by caller (deterministic/testable)
    actor: str  # "agent" | "human:<name>" | "system"
    action: str  # e.g. "tool.proposed", "scope.blocked", "tool.result"
    engagement_id: str
    params_hash: str
    detail: dict[str, Any]
    prev_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "seq": self.seq,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "engagement_id": self.engagement_id,
            "params_hash": self.params_hash,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def hash_params(params: Any) -> str:
    blob = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only hash-chained log. Thread-safe.

    If ``path`` is given, events are also flushed as JSON Lines to disk.
    In-memory events remain queryable via :meth:`events`.
    """

    def __init__(self, engagement_id: str, path: Optional[str | Path] = None) -> None:
        self.engagement_id = engagement_id
        self._path = Path(path) if path else None
        self._events: list[AuditEvent] = []
        self._head = GENESIS_HASH
        self._lock = threading.Lock()
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def head(self) -> str:
        return self._head

    def append(
        self,
        *,
        actor: str,
        action: str,
        ts: str,
        params: Any = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> AuditEvent:
        with self._lock:
            seq = len(self._events)
            base = AuditEvent(
                seq=seq,
                ts=ts,
                actor=actor,
                action=action,
                engagement_id=self.engagement_id,
                params_hash=hash_params(params),
                detail=detail or {},
                prev_hash=self._head,
            )
            event = AuditEvent(**{**asdict(base), "hash": base.compute_hash()})
            self._events.append(event)
            self._head = event.hash
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")
            return event

    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def verify(self) -> bool:
        """Recompute the chain; return True iff intact."""
        prev = GENESIS_HASH
        for i, ev in enumerate(self._events):
            if ev.seq != i or ev.prev_hash != prev:
                return False
            recomputed = ev.compute_hash()
            if recomputed != ev.hash:
                return False
            prev = ev.hash
        return True
