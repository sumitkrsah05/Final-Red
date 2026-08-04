"""Control-plane core (transport-agnostic).

Wraps an ``Orchestrator`` with RBAC and audit so every operator action — start,
approve, kill, query — is authorised and recorded. A FastAPI app maps HTTP routes
onto these methods; the safety semantics live here, not in the transport.
"""

from __future__ import annotations

from typing import Optional

from safeguard.observability.metrics import Metrics
from safeguard.safety.approvals import ApprovalDecision
from safeguard.safety.rbac import RBAC, Action
from safeguard.orchestrator import Orchestrator


class ControlPlane:
    def __init__(self, orchestrator: Orchestrator, rbac: RBAC, *,
                 metrics: Optional[Metrics] = None, now_iso: str = "1970-01-01T00:00:00") -> None:
        self.orch = orchestrator
        self.rbac = rbac
        self.metrics = metrics or Metrics()
        self._now = now_iso
        self._audit = orchestrator.engagement.audit

    def _record(self, operator: str, action: Action, **detail) -> None:
        self._audit.append(actor=f"human:{operator}", action=f"control.{action.value}",
                           ts=self._now, detail=detail)
        self.metrics.incr("control.action", action=action.value)

    def start(self, operator: str):
        self.rbac.require(operator, Action.START)
        self._record(operator, Action.START,
                     engagement=self.orch.engagement.roe.engagement_id)
        return self.orch.run()

    def approve(self, operator: str, request_id: str, *,
                decision: ApprovalDecision = ApprovalDecision.APPROVED):
        self.rbac.require(operator, Action.APPROVE)
        # Named-approver check is enforced again inside the orchestrator.
        self.orch.approve(request_id, approver=operator, decision=decision)
        self._record(operator, Action.APPROVE, request_id=request_id,
                     decision=decision.value)
        return self.orch.resume()

    def kill(self, operator: str, reason: str = "operator halt") -> None:
        self.rbac.require(operator, Action.KILL)
        self.orch.engagement.kill_switch.engage(reason)
        self._record(operator, Action.KILL, reason=reason)

    def audit_query(self, operator: str) -> list[dict]:
        self.rbac.require(operator, Action.QUERY)
        self._record(operator, Action.QUERY)
        from dataclasses import asdict
        return [asdict(e) for e in self._audit.events()]
