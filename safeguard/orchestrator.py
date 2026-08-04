"""Engagement orchestrator — drives the graph over an assembled Engagement.

Wires the recon/scan flows, planner, approval store, audit log, and checkpointer
into a compiled graph and runs it. Passive phases run autonomously; an active
step parks for approval and can be resumed after sign-off — all replayable from
the checkpointer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Optional
from zoneinfo import ZoneInfo

from safeguard.engagement import Engagement

if TYPE_CHECKING:
    from safeguard.oracle.oracle import DetectionOracle
from safeguard.graph.build import build_engagement_graph
from safeguard.graph.checkpoint import Checkpointer, InMemoryCheckpointer
from safeguard.graph.engine import CompiledGraph, InvokeResult
from safeguard.graph.state import AgentState
from safeguard.llm.planner import Planner
from safeguard.recon.flow import ReconFlow
from safeguard.safety.approvals import ApprovalDecision, ApprovalStore
from safeguard.scan.flow import ScanFlow
from safeguard.validate.flow import ValidateFlow


@dataclass
class Orchestrator:
    engagement: Engagement
    graph: CompiledGraph
    approvals: ApprovalStore
    thread_id: str

    @classmethod
    def build(
        cls,
        engagement: Engagement,
        *,
        planner: Optional[Planner] = None,
        checkpointer: Optional[Checkpointer] = None,
        oracle: Optional["DetectionOracle"] = None,
        recon_plan: Optional[list[str]] = None,
        scan_plan: Optional[list[str]] = None,
        thread_id: Optional[str] = None,
    ) -> "Orchestrator":
        roe = engagement.roe
        recon = ReconFlow(engagement.pipeline, engagement.registry)
        scan = ScanFlow(engagement.pipeline, engagement.registry)
        validate = ValidateFlow(engagement.pipeline, engagement.registry)
        tz = ZoneInfo(roe.timezone)
        graph_def = build_engagement_graph(
            roe=roe, recon=recon, scan=scan, planner=planner,
            approvals=engagement.approvals, audit=engagement.audit,
            validate_flow=validate, oracle=oracle,
            recon_plan=recon_plan, scan_plan=scan_plan,
            now_iso=datetime.now(tz).isoformat(),
        )
        compiled = graph_def.compile(checkpointer or InMemoryCheckpointer())
        return cls(engagement=engagement, graph=compiled,
                   approvals=engagement.approvals,
                   thread_id=thread_id or roe.engagement_id)

    def initial_state(self) -> AgentState:
        roe = self.engagement.roe
        return AgentState(
            engagement_id=roe.engagement_id, mode=roe.mode.value,
            profile=roe.profile,
            targets=list(roe.scope.domains) + list(roe.scope.cidrs),
            max_actions=roe.budget.max_total_actions)

    def run(self, state: Optional[AgentState] = None) -> InvokeResult:
        return self.graph.invoke(state or self.initial_state(),
                                 thread_id=self.thread_id)

    def approve(self, request_id: str, *, approver: str,
                decision: ApprovalDecision = ApprovalDecision.APPROVED) -> None:
        if not self.engagement.pipeline.scope.is_approver(approver):
            raise PermissionError(f"{approver!r} is not a named ROE approver")
        self.approvals.resolve(request_id, decision=decision, approver=approver)

    def resume(self) -> InvokeResult:
        return self.graph.resume(thread_id=self.thread_id)
