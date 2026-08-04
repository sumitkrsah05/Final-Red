"""Phase 4 tests: planner-driven passive engagement, the active-step approval
interrupt + resume, checkpoint replay, and in-code validation of LLM proposals."""

import pytest

from safeguard.config.models import SafetyClass, ToolSpec
from safeguard.graph.build import build_engagement_graph
from safeguard.graph.checkpoint import InMemoryCheckpointer, SqliteCheckpointer
from safeguard.graph.state import AgentState, PlanDecision
from safeguard.llm.planner import LLMPlanner, RulePlanner
from safeguard.recon.flow import ReconFlow
from safeguard.safety.approvals import ApprovalDecision, ApprovalStore
from safeguard.scan.flow import ScanFlow
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.runner import CommandResult


NMAP_XML = ('<?xml version="1.0"?><nmaprun><host>'
            '<address addr="10.20.30.44" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https" product="nginx"/></port></ports>'
            '</host></nmaprun>')


class StubRunner:
    def __init__(self, outputs):
        self._outputs = outputs
        self._revoked = False

    def revoke(self):
        self._revoked = True

    def run(self, command, *, image, timeout=300.0, env=None):
        return CommandResult(exit_code=0, stdout=self._outputs.get(command[0], ""),
                             stderr="")


def _registry():
    return ToolRegistry({
        "nmap": ToolSpec(name="nmap", safety_class=SafetyClass.ACTIVE_RECON),
        "nuclei": ToolSpec(name="nuclei", safety_class=SafetyClass.ACTIVE_RECON,
                           sandbox="scan-runner"),
        "dalfox": ToolSpec(name="dalfox", safety_class=SafetyClass.ACTIVE_VALIDATE),
    })


def _flows(make_pipeline, nuclei_severity):
    outputs = {
        "nmap": NMAP_XML,
        "nuclei": ('{"template-id":"t","matched-at":"https://10.20.30.44/",'
                   f'"info":{{"name":"Issue","severity":"{nuclei_severity}"}}}}'),
    }
    pipe = make_pipeline(runner=StubRunner(outputs))
    reg = _registry()
    return pipe, ReconFlow(pipe, reg), ScanFlow(pipe, reg), reg


def _initial(roe):
    return AgentState(engagement_id=roe.engagement_id, mode=roe.mode.value,
                      profile=roe.profile,
                      targets=list(roe.scope.domains) + list(roe.scope.cidrs),
                      max_actions=roe.budget.max_total_actions)


# -- passive engagement --------------------------------------------------
def test_passive_engagement_completes(make_pipeline, roe):
    pipe, recon, scan, reg = _flows(make_pipeline, "medium")
    graph = build_engagement_graph(roe=roe, recon=recon, scan=scan,
                                   audit=pipe.audit, recon_plan=["nmap"],
                                   scan_plan=["nuclei"]).compile()
    result = graph.invoke(_initial(roe), thread_id="t1")
    assert result.status == "complete"
    st = result.state
    assert st.done and st.phase == "report"
    assert len(st.inventory) >= 1 and len(st.ledger) == 1
    assert st.report["findings"] == 1
    # planner drove recon -> scan -> correlate -> report
    actions = [h["action"] for h in st.plan_history]
    assert actions == ["recon", "scan", "correlate", "report"]


# -- active step parks then resumes -------------------------------------
def test_active_step_parks_for_approval_and_resumes(make_pipeline, roe):
    pipe, recon, scan, reg = _flows(make_pipeline, "high")
    approvals = ApprovalStore()
    cp = InMemoryCheckpointer()
    graph = build_engagement_graph(roe=roe, recon=recon, scan=scan,
                                   approvals=approvals, audit=pipe.audit,
                                   planner=RulePlanner(reg), recon_plan=["nmap"],
                                   scan_plan=["nuclei"]).compile(cp)

    result = graph.invoke(_initial(roe), thread_id="t2")
    # high finding -> planner proposes validate -> gate interrupts
    assert result.status == "interrupted" and result.node == "approval_gate"
    pa = result.state.pending_approval
    assert pa["decision"] == "pending" and pa["tool"] == "dalfox"

    # named approver signs off, then resume
    approvals.resolve(pa["request_id"], decision=ApprovalDecision.APPROVED,
                      approver="void")
    result2 = graph.resume(thread_id="t2")
    assert result2.status == "complete"
    assert result2.state.validations
    v = result2.state.validations[0]
    assert v["approved_by"] == "void" and v["non_destructive"] is True


def test_active_step_runs_real_validation_with_evidence(make_pipeline, roe):
    from safeguard.evidence import EvidenceStore
    from safeguard.validate.flow import ValidateFlow
    outputs = {
        "nmap": NMAP_XML,
        "nuclei": ('{"template-id":"t","matched-at":"https://10.20.30.44/",'
                   '"info":{"name":"Reflected param","severity":"high"}}'),
        "dalfox": '[{"type":"V","method":"GET","param":"q"}]',
    }
    evidence = EvidenceStore()
    pipe = make_pipeline(runner=StubRunner(outputs), evidence=evidence)
    reg = ToolRegistry({
        "nmap": ToolSpec(name="nmap", safety_class=SafetyClass.ACTIVE_RECON),
        "nuclei": ToolSpec(name="nuclei", safety_class=SafetyClass.ACTIVE_RECON,
                           sandbox="scan-runner"),
        "dalfox": ToolSpec(name="dalfox", safety_class=SafetyClass.ACTIVE_VALIDATE,
                           sandbox="validate-runner"),
    })
    approvals = pipe.approvals
    vflow = ValidateFlow(pipe, reg)
    graph = build_engagement_graph(
        roe=roe, recon=ReconFlow(pipe, reg), scan=ScanFlow(pipe, reg),
        approvals=approvals, planner=RulePlanner(reg), validate_flow=vflow,
        recon_plan=["nmap"], scan_plan=["nuclei"]).compile()

    r1 = graph.invoke(_initial(roe), thread_id="tv")
    assert r1.status == "interrupted"
    pa = r1.state.pending_approval
    approvals.resolve(pa["request_id"], decision=ApprovalDecision.APPROVED,
                      approver="void")
    r2 = graph.resume(thread_id="tv")
    assert r2.status == "complete"
    v = r2.state.validations[0]
    assert v["result"] == "confirmed" and v["approved_by"] == "void"
    assert v["evidence_ref"] and evidence.get(v["evidence_ref"]) is not None


def test_denied_approval_skips_validation(make_pipeline, roe):
    pipe, recon, scan, reg = _flows(make_pipeline, "critical")
    approvals = ApprovalStore()
    graph = build_engagement_graph(roe=roe, recon=recon, scan=scan,
                                   approvals=approvals, planner=RulePlanner(reg),
                                   recon_plan=["nmap"], scan_plan=["nuclei"]).compile()
    result = graph.invoke(_initial(roe), thread_id="t3")
    pa = result.state.pending_approval
    approvals.resolve(pa["request_id"], decision=ApprovalDecision.DENIED,
                      approver="void")
    result2 = graph.resume(thread_id="t3")
    assert result2.status == "complete"
    assert result2.state.validations == []  # denied -> not validated


# -- checkpoint replay ---------------------------------------------------
def test_checkpoint_replay_records_each_node(make_pipeline, roe):
    pipe, recon, scan, reg = _flows(make_pipeline, "low")
    cp = InMemoryCheckpointer()
    graph = build_engagement_graph(roe=roe, recon=recon, scan=scan,
                                   recon_plan=["nmap"], scan_plan=["nuclei"]).compile(cp)
    graph.invoke(_initial(roe), thread_id="t4")
    nodes = [h["node"] for h in cp.history("t4")]
    assert "recon" in nodes and "scan" in nodes and "report" in nodes
    assert nodes[-1] == "__end__"


def test_sqlite_checkpointer_roundtrip(make_pipeline, roe, tmp_path):
    pipe, recon, scan, reg = _flows(make_pipeline, "low")
    cp = SqliteCheckpointer(tmp_path / "cp.db")
    graph = build_engagement_graph(roe=roe, recon=recon, scan=scan,
                                   recon_plan=["nmap"], scan_plan=["nuclei"]).compile(cp)
    graph.invoke(_initial(roe), thread_id="t5")
    hist = cp.history("t5")
    assert hist and hist[-1]["node"] == "__end__"
    # state reconstructs from the persisted checkpoint
    st = AgentState.from_checkpoint(cp.latest("t5"))
    assert st.done and len(st.inventory) >= 1


# -- LLM proposal validation (no network) --------------------------------
class FakeClient:
    configured = True

    def __init__(self, payload):
        self._payload = payload

    def chat(self, messages, *, node="planner", response_json=False, profile=None):
        return self._payload


def test_llm_planner_rejects_unknown_validate_tool(roe):
    reg = _registry()
    planner = LLMPlanner(
        FakeClient('{"action":"validate","tool":"metasploit","rationale":"pwn"}'),
        reg)
    st = AgentState(engagement_id="e", mode="black_box", profile="non_destructive",
                    targets=["x"])
    decision = planner.decide(st, roe)
    # metasploit is not registered / not active-validate -> downgraded to report
    assert decision.action == "report"


def test_llm_planner_accepts_valid_validate_tool(roe):
    reg = _registry()
    planner = LLMPlanner(
        FakeClient('{"action":"validate","tool":"dalfox","target":"https://x",'
                   '"rationale":"confirm xss"}'), reg)
    st = AgentState(engagement_id="e", mode="black_box", profile="non_destructive",
                    targets=["x"])
    decision = planner.decide(st, roe)
    assert decision.action == "validate" and decision.tool == "dalfox"
    assert decision.requires_approval is True
