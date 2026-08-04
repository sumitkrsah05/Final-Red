"""Phase 7 tests: read-only connectors, verdict scoring + MTTD, coverage matrix,
and the oracle wired into the graph feeding detection-aware risk."""

from datetime import datetime, timedelta

from safeguard.config.models import SafetyClass, ToolSpec
from safeguard.graph.build import build_engagement_graph
from safeguard.graph.state import AgentState
from safeguard.llm.planner import RulePlanner
from safeguard.oracle.connectors import default_connectors
from safeguard.oracle.coverage import CoverageMatrix
from safeguard.oracle.models import DetectionEvent, Verdict, best_verdict
from safeguard.oracle.oracle import DetectionOracle
from safeguard.oracle.telemetry import InMemoryTelemetryBackend
from safeguard.recon.flow import ReconFlow
from safeguard.scan.flow import ScanFlow
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.runner import CommandResult

T0 = datetime(2026, 8, 4, 3, 0, 0)


def _ev(source, target, secs, **kw):
    return DetectionEvent(source=source, ts=T0 + timedelta(seconds=secs),
                          target=target, **kw)


# -- verdict scoring -----------------------------------------------------
def test_wazuh_detected_with_mttd():
    b = InMemoryTelemetryBackend()
    b.add(_ev("wazuh", "10.20.30.44", 40, rule_id="86601", alerted=True))
    oracle = DetectionOracle.from_backend(b)
    dr = oracle.observe(action_ref="recon", target="10.20.30.44",
                        technique="T1046", action_time=T0)
    assert dr.verdict is Verdict.DETECTED
    assert dr.ttd_seconds == 40.0 and dr.rule_id == "86601"


def test_waf_block_beats_siem_detect():
    b = InMemoryTelemetryBackend()
    b.add(_ev("wazuh", "h", 30, alerted=True))
    b.add(_ev("waf", "h", 2, rule_id="CRS-941100", blocked=True))
    dr = DetectionOracle.from_backend(b).observe(
        action_ref="scan", target="h", technique="T1595", action_time=T0)
    assert dr.verdict is Verdict.BLOCKED  # best-of across sources


def test_missed_when_no_telemetry():
    oracle = DetectionOracle.from_backend(InMemoryTelemetryBackend())
    dr = oracle.observe(action_ref="scan", target="h", technique="T1595",
                        action_time=T0)
    assert dr.verdict is Verdict.MISSED and dr.ttd_seconds is None


def test_partial_when_logged_not_alerted():
    b = InMemoryTelemetryBackend()
    b.add(_ev("waf", "h", 5, alerted=False, blocked=False))  # logged only
    dr = DetectionOracle.from_backend(b).observe(
        action_ref="scan", target="h", technique="T1595", action_time=T0)
    assert dr.verdict is Verdict.PARTIAL


def test_event_outside_window_ignored():
    b = InMemoryTelemetryBackend()
    b.add(_ev("wazuh", "h", 10_000, alerted=True))  # way past window
    dr = DetectionOracle(default_connectors(b), correlation_window_seconds=300).observe(
        action_ref="scan", target="h", technique="T1595", action_time=T0)
    assert dr.verdict is Verdict.MISSED


def test_connectors_are_read_only():
    b = InMemoryTelemetryBackend()
    assert all(c.read_only for c in default_connectors(b))


def test_best_verdict_precedence():
    assert best_verdict([Verdict.MISSED, Verdict.PARTIAL]) is Verdict.PARTIAL
    assert best_verdict([Verdict.DETECTED, Verdict.BLOCKED]) is Verdict.BLOCKED
    assert best_verdict([]) is Verdict.MISSED


# -- coverage matrix -----------------------------------------------------
def test_coverage_matrix_pct_and_gaps():
    oracle = DetectionOracle.from_backend(_backend_mixed())
    m = CoverageMatrix()
    m.add(oracle.observe(action_ref="a1", target="h1", technique="T1046",
                         action_time=T0))  # detected
    m.add(oracle.observe(action_ref="a2", target="h2", technique="T1595",
                         action_time=T0))  # missed
    assert m.total == 2
    assert m.coverage_pct() == 50.0
    gaps = m.gaps()
    assert len(gaps) == 1 and gaps[0]["technique"] == "T1595"


def _backend_mixed():
    b = InMemoryTelemetryBackend()
    b.add(_ev("wazuh", "h1", 20, alerted=True))  # h1 detected; h2 nothing
    return b


# -- graph integration: detection feeds risk ----------------------------
NMAP_XML = ('<?xml version="1.0"?><nmaprun><host>'
            '<address addr="10.20.30.44" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https"/></port></ports></host></nmaprun>')


class StubRunner:
    def __init__(self, out):
        self._out = out
        self._revoked = False
    def revoke(self):
        self._revoked = True
    def run(self, command, *, image, timeout=300.0, env=None):
        return CommandResult(exit_code=0, stdout=self._out.get(command[0], ""),
                             stderr="")


def test_oracle_wired_into_graph_marks_missed(make_pipeline, roe):
    outputs = {
        "nmap": NMAP_XML,
        "nuclei": ('{"template-id":"t","matched-at":"https://10.20.30.44/",'
                   '"info":{"name":"Exposed thing","severity":"medium"}}'),
    }
    pipe = make_pipeline(runner=StubRunner(outputs))
    reg = ToolRegistry({
        "nmap": ToolSpec(name="nmap", safety_class=SafetyClass.ACTIVE_RECON),
        "nuclei": ToolSpec(name="nuclei", safety_class=SafetyClass.ACTIVE_RECON,
                           sandbox="scan-runner")})
    # Empty telemetry -> every action MISSED (the compelling gap story).
    oracle = DetectionOracle.from_backend(InMemoryTelemetryBackend())
    graph = build_engagement_graph(
        roe=roe, recon=ReconFlow(pipe, reg), scan=ScanFlow(pipe, reg),
        planner=RulePlanner(reg), oracle=oracle,
        recon_plan=["nmap"], scan_plan=["nuclei"],
        now_iso="2026-08-04T03:00:00").compile()
    st = graph.invoke(_initial(roe), thread_id="to").state
    assert st.done
    cov = st.report["detection_coverage"]
    assert cov["coverage_pct"] == 0.0 and cov["total_actions"] >= 2
    assert cov["gaps"]  # gap report populated
    # detection status fed into risk: MISSED boosts score above the base medium
    f = st.ledger.findings()[0]
    assert f.raw["risk"]["factors"]["detection"] == "MISSED"


def _initial(roe):
    return AgentState(engagement_id=roe.engagement_id, mode=roe.mode.value,
                      profile=roe.profile,
                      targets=list(roe.scope.domains) + list(roe.scope.cidrs),
                      max_actions=roe.budget.max_total_actions)
