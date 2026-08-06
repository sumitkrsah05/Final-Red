"""Assemble the engagement StateGraph.

Nodes: planner → (recon | scan | approval_gate → validate | report). The planner
is re-entered after each passive phase. Any active step routes through
``approval_gate``, which parks the run at a ``GraphInterrupt`` until a named
approver resolves the request in the shared ``ApprovalStore`` — then resumes.

    planner ─┬─ recon ──┐
             ├─ scan ───┤→ planner
             ├─ approval_gate ─(approved)→ validate → planner
             │                └─(denied)──────────────→ planner
             └─ report → END
"""

from __future__ import annotations

from typing import Optional

from safeguard.config.models import RulesOfEngagement
from safeguard.graph.engine import END, GraphInterrupt, StateGraph
from safeguard.graph.state import AgentState, PlanDecision
from safeguard.llm.planner import Planner, RulePlanner
from safeguard.recon.flow import ReconFlow
from safeguard.safety.approvals import ApprovalStore
from datetime import datetime

from safeguard.intel.correlate import AttackPathCorrelator, _asset_root as _root
from safeguard.intel.enrich import Enricher
from safeguard.llm.verifier import NumericClaimVerifier
from safeguard.oracle.coverage import CoverageMatrix
from safeguard.oracle.models import DetectionResult, Verdict
from safeguard.oracle.oracle import DetectionOracle
from safeguard.safety.audit import AuditLog
from safeguard.scan.flow import ScanFlow
from safeguard.validate.flow import ValidateFlow


def build_engagement_graph(
    *,
    roe: RulesOfEngagement,
    recon: ReconFlow,
    scan: ScanFlow,
    planner: Optional[Planner] = None,
    approvals: Optional[ApprovalStore] = None,
    audit: Optional[AuditLog] = None,
    validate_flow: Optional["ValidateFlow"] = None,
    enricher: Optional["Enricher"] = None,
    correlator: Optional["AttackPathCorrelator"] = None,
    verifier: Optional["NumericClaimVerifier"] = None,
    oracle: Optional["DetectionOracle"] = None,
    recon_plan: Optional[list[str]] = None,
    recon_params: Optional[dict[str, dict]] = None,
    scan_plan: Optional[list[str]] = None,
    now_iso: str = "1970-01-01T00:00:00",
) -> StateGraph:
    planner = planner or RulePlanner(recon.registry)
    approvals = approvals or ApprovalStore()
    enricher = enricher or Enricher()
    correlator = correlator or AttackPathCorrelator()
    verifier = verifier or NumericClaimVerifier()
    action_time = datetime.fromisoformat(now_iso)

    # Phase → ATT&CK technique the Oracle correlates against.
    _PHASE_TECHNIQUE = {"recon": "T1046", "scan": "T1595"}

    # Mode-aware default scan plans (overridable via scan_plan).
    _SCAN_BY_MODE = {
        "black_box": ["nuclei", "nikto"],
        "gray_box": ["prowler", "trivy"],
        "white_box": ["semgrep", "gitleaks", "checkov", "trivy"],
    }

    def _scan_plan_and_targets(state: AgentState) -> tuple[list[str], list[str]]:
        mode = roe.mode.value
        endpoints = [a.address for a in state.inventory.by_type("endpoint")]
        if scan_plan is not None:
            return scan_plan, (endpoints or state.targets)
        plan = _SCAN_BY_MODE.get(mode, _SCAN_BY_MODE["black_box"])
        if mode == "white_box":
            targets = list(roe.scope.repos)
        elif mode == "gray_box":
            targets = list(roe.scope.cloud_accounts) or (endpoints or state.targets)
        else:
            targets = endpoints or state.targets
        return plan, targets

    def _audit(event: str, **detail) -> None:
        if audit is not None:
            audit.append(actor="agent", action=event, ts=now_iso, detail=detail)

    def _observe(state: AgentState, action_ref: str, targets: list[str],
                 technique: Optional[str]) -> None:
        """After an emulated action, ask the Blue Team stack if it noticed."""
        if oracle is None:
            return
        for tgt in targets:
            dr = oracle.observe(action_ref=action_ref, target=tgt,
                                technique=technique, action_time=action_time)
            state.detections.append(dr.as_dict())
            state.detection_status[_root(tgt)] = dr.verdict.value
        _audit("oracle.observed", action_ref=action_ref,
               detections=len(state.detections))

    # -- nodes -----------------------------------------------------------
    def planner_node(state: AgentState) -> None:
        decision = planner.decide(state, roe)
        state.last_decision = decision
        state.phase = "plan"
        state.plan_history.append({
            "action": decision.action, "tool": decision.tool,
            "target": decision.target, "rationale": decision.rationale,
        })
        _audit("plan.decision", action=decision.action, tool=decision.tool,
               rationale=decision.rationale)

    def recon_node(state: AgentState) -> None:
        state.phase = "recon"
        report = recon.run(state.targets, plan=recon_plan, params=recon_params)
        for a in report.inventory.assets():
            state.inventory.add(a)
        state.actions_spent += report.allowed_steps
        _audit("phase.recon", assets=len(state.inventory),
               allowed=report.allowed_steps, denied=report.denied_steps)
        _observe(state, "recon", state.targets, _PHASE_TECHNIQUE["recon"])

    def scan_node(state: AgentState) -> None:
        state.phase = "scan"
        plan, targets = _scan_plan_and_targets(state)
        report = scan.run(targets, plan=plan)
        for f in report.ledger.findings():
            state.ledger.add(f)
        state.actions_spent += report.allowed_steps
        _audit("phase.scan", findings=len(state.ledger),
               allowed=report.allowed_steps, denied=report.denied_steps)
        # Correlate detection against the assets the findings actually landed on.
        finding_targets = sorted({f.asset_ref for f in state.ledger.findings()})
        _observe(state, "scan", finding_targets or targets,
                 _PHASE_TECHNIQUE["scan"])

    def correlate_node(state: AgentState) -> None:
        state.phase = "correlate"
        findings = state.ledger.findings()
        # Detection status flows into risk scoring (undetected outranks detected).
        finding_status = {
            f.asset_ref: state.detection_status.get(_root(f.asset_ref), "UNKNOWN")
            for f in findings}
        enrichment = enricher.enrich(findings, detection_status=finding_status)
        state.grounded_tokens = sorted(enrichment.grounded_tokens)
        state.attack_paths = [p.as_dict()
                              for p in correlator.build(findings, finding_status)]
        _audit("phase.correlate", enriched=enrichment.enriched,
               cve_hits=enrichment.cve_hits, cve_misses=enrichment.cve_misses,
               attack_paths=len(state.attack_paths))

    def approval_gate_node(state: AgentState) -> None:
        state.phase = "approval_gate"
        decision = state.last_decision or PlanDecision(action="report")
        pa = state.pending_approval
        if pa is None:
            req = approvals.create(
                engagement_id=state.engagement_id, tool=decision.tool or "",
                target=decision.target or "", technique=decision.technique or "",
                rationale=decision.rationale)
            state.pending_approval = {
                "request_id": req.request_id, "tool": req.tool,
                "target": req.target, "technique": req.technique,
                "decision": "pending"}
            _audit("approval.requested", request_id=req.request_id,
                   tool=req.tool, target=req.target)
            raise GraphInterrupt(state.pending_approval)
        # Resumed: re-evaluate the store.
        req = approvals.get(pa["request_id"])
        status = req.decision.value if req else "pending"
        if status == "pending":
            raise GraphInterrupt(pa)  # still waiting
        pa["decision"] = status
        pa["approver"] = req.approver if req else None
        _audit("approval.resolved", request_id=pa["request_id"],
               decision=status, approver=pa.get("approver"))

    def validate_node(state: AgentState) -> None:
        state.phase = "validate"
        pa = state.pending_approval or {}
        tool, target = pa.get("tool"), pa.get("target")
        if validate_flow is not None and tool and target:
            outcome = validate_flow.run(
                tool=tool, target=target, approval_id=pa.get("request_id"),
                technique=pa.get("technique"),
                rationale=(state.last_decision.rationale
                           if state.last_decision else ""))
            state.actions_spent += 1
            for v in outcome.validations:
                state.validations.append({
                    "tool": v.tool, "target": v.target, "method": v.method,
                    "technique": pa.get("technique"),
                    "approved_by": v.approved_by or pa.get("approver"),
                    "result": v.result.value, "non_destructive": v.non_destructive,
                    "evidence_ref": v.evidence_ref})
            _audit("validate.ran", tool=tool, target=target,
                   allowed=outcome.allowed, denial=outcome.denial,
                   validations=len(outcome.validations))
            # Oracle: did the Blue Team stack catch the validation attempt?
            _observe(state, f"validate:{tool}", [target], pa.get("technique"))
        else:
            # No validate flow wired (e.g. planner-only dry run): record intent.
            state.validations.append({
                "tool": tool, "target": target, "technique": pa.get("technique"),
                "approved_by": pa.get("approver"), "result": "not-executed",
                "non_destructive": True})
            _audit("validate.recorded", tool=tool, target=target,
                   approver=pa.get("approver"))
        state.pending_approval = None

    def report_node(state: AgentState) -> None:
        state.phase = "report"
        # Numeric-claim verifier: every CVE in the findings must be grounded.
        grounded = set(state.grounded_tokens)
        cve_text = " ".join(c for f in state.ledger.findings() for c in f.cve_ids)
        verdict = verifier.verify(cve_text, grounded)
        top_risk = max(
            (float((f.raw.get("risk") or {}).get("score", 0.0))
             for f in state.ledger.findings()), default=0.0)
        # Detection coverage matrix (the purple-team product).
        matrix = CoverageMatrix()
        for d in state.detections:
            matrix.add(DetectionResult(
                action_ref=d["action_ref"], target=d["target"],
                technique=d.get("technique"), verdict=Verdict(d["verdict"]),
                source=d.get("source", "aggregate"), rule_id=d.get("rule_id"),
                ttd_seconds=d.get("ttd_seconds")))
        state.report = {
            "engagement_id": state.engagement_id,
            "assets": len(state.inventory),
            "hosts": state.inventory.hosts(),
            "findings": len(state.ledger),
            "severity_counts": state.ledger.by_severity(),
            "attack_paths": state.attack_paths,
            "top_risk": round(top_risk, 1),
            "validations": state.validations,
            "detection_coverage": matrix.summary(),
            "actions_spent": state.actions_spent,
            "numeric_verification": {"ok": verdict.ok,
                                     "ungrounded": verdict.ungrounded},
        }
        _audit("phase.report", assets=state.report["assets"],
               findings=state.report["findings"],
               attack_paths=len(state.attack_paths),
               coverage_pct=matrix.coverage_pct(), numeric_ok=verdict.ok)

    # -- routing ---------------------------------------------------------
    def route_from_planner(state: AgentState) -> str:
        action = (state.last_decision.action if state.last_decision else "report")
        return {
            "recon": "recon", "scan": "scan", "correlate": "correlate",
            "validate": "approval_gate", "report": "report",
        }.get(action, "report")

    def route_from_gate(state: AgentState) -> str:
        pa = state.pending_approval or {}
        return "validate" if pa.get("decision") == "approved" else "planner"

    g = StateGraph()
    g.add_node("planner", planner_node)
    g.add_node("recon", recon_node)
    g.add_node("scan", scan_node)
    g.add_node("correlate", correlate_node)
    g.add_node("approval_gate", approval_gate_node)
    g.add_node("validate", validate_node)
    g.add_node("report", report_node)

    g.set_entry("planner")
    g.add_conditional_edges("planner", route_from_planner)
    g.add_edge("recon", "planner")
    g.add_edge("scan", "planner")
    g.add_edge("correlate", "planner")
    g.add_conditional_edges("approval_gate", route_from_gate)
    g.add_edge("validate", "planner")
    g.add_edge("report", END)
    return g
