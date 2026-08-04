"""Approval store — the human-in-the-loop gate for active-validate steps.

In the full system a LangGraph ``interrupt()`` parks the graph and the Control
Plane resolves the approval. Phase 1 provides the deterministic core: a store
that holds pending requests and records named, in-ROE approver decisions. The
pipeline consults it before any ``active-validate`` action runs.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ApprovalDecision(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass
class ApprovalRequest:
    request_id: str
    engagement_id: str
    tool: str
    target: str
    technique: str
    rationale: str
    decision: ApprovalDecision = ApprovalDecision.PENDING
    approver: Optional[str] = None


class ApprovalStore:
    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        engagement_id: str,
        tool: str,
        target: str,
        technique: str,
        rationale: str,
        request_id: Optional[str] = None,
    ) -> ApprovalRequest:
        rid = request_id or uuid.uuid4().hex
        req = ApprovalRequest(
            request_id=rid,
            engagement_id=engagement_id,
            tool=tool,
            target=target,
            technique=technique,
            rationale=rationale,
        )
        with self._lock:
            self._requests[rid] = req
        return req

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            return self._requests.get(request_id)

    def resolve(
        self, request_id: str, *, decision: ApprovalDecision, approver: str
    ) -> ApprovalRequest:
        with self._lock:
            req = self._requests[request_id]
            req.decision = decision
            req.approver = approver
            return req

    def is_approved(self, request_id: Optional[str]) -> bool:
        if not request_id:
            return False
        with self._lock:
            req = self._requests.get(request_id)
            return bool(req and req.decision is ApprovalDecision.APPROVED)

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            return [
                r for r in self._requests.values()
                if r.decision is ApprovalDecision.PENDING
            ]
