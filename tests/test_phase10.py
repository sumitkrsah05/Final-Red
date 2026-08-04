"""Phase 10 tests: regression diff, continuous runner, Detect/Act integration,
RBAC control plane, and metrics."""

import pytest

from safeguard.continuous.baseline import BaselineStore, diff_reports
from safeguard.continuous.runner import ContinuousRunner
from safeguard.integration.act import ActIntegration
from safeguard.integration.detect import DetectIntegration
from safeguard.observability.metrics import Metrics
from safeguard.safety.rbac import RBAC, Action, AccessDenied, Role


def _report(index, coverage, findings=None, gaps=None):
    return {"engagement_id": "e1", "detection_index": index,
            "detection_coverage": {"coverage_pct": coverage, "gaps": gaps or []},
            "findings": findings or [], "gaps": gaps or []}


# -- regression diff -----------------------------------------------------
def test_diff_detects_regression():
    base = _report({"T1046|h": "DETECTED", "T1190|h": "DETECTED"}, 100.0)
    curr = _report({"T1046|h": "DETECTED", "T1190|h": "MISSED"}, 50.0)
    r = diff_reports(base, curr)
    assert r.has_regressions
    assert r.regressions[0]["key"] == "T1190|h"
    assert r.regressions[0]["was"] == "DETECTED" and r.regressions[0]["now"] == "MISSED"
    assert r.coverage_delta == -50.0


def test_diff_detects_improvement_and_new_gap():
    base = _report({"T1046|h": "MISSED"}, 0.0)
    curr = _report({"T1046|h": "DETECTED", "T1595|h": "MISSED"}, 50.0)
    r = diff_reports(base, curr)
    assert r.improvements and r.improvements[0]["key"] == "T1046|h"
    assert "T1595|h" in r.new_gaps
    assert not r.has_regressions


def test_diff_first_run_has_no_baseline():
    r = diff_reports(None, _report({"T1046|h": "MISSED"}, 0.0))
    assert not r.has_baseline and not r.has_regressions


def test_finding_delta():
    base = _report({}, 0.0, findings=[{"id": "find-a"}, {"id": "find-b"}])
    curr = _report({}, 0.0, findings=[{"id": "find-b"}, {"id": "find-c"}])
    r = diff_reports(base, curr)
    assert r.new_findings == ["find-c"] and r.resolved_findings == ["find-a"]


# -- continuous runner ---------------------------------------------------
def test_continuous_runner_cycles(tmp_path):
    store = BaselineStore(tmp_path)
    runner = ContinuousRunner(store)
    c1 = runner.record("e1", _report({"T1046|h": "DETECTED"}, 100.0))
    assert not c1.regression.has_baseline and c1.cycle_index == 0
    c2 = runner.record("e1", _report({"T1046|h": "MISSED"}, 0.0))
    assert c2.regression.has_baseline and c2.regression.has_regressions
    assert c2.cycle_index == 1
    assert store.count("e1") == 2


# -- Detect / Act integration -------------------------------------------
_GAP_REPORT = {"engagement_id": "e1",
               "gaps": [{"technique": "T1189", "target": "https://h/search",
                         "verdict": "MISSED",
                         "expected_detection": "WAF/CRS rule for reflected-XSS"}],
               "findings": [{"title": "Reflected XSS", "priority": "high",
                             "asset": "https://h/search", "risk": 70.0,
                             "detection": "MISSED", "cve_ids": [],
                             "techniques": ["T1189"]}]}


def test_detect_rule_candidates():
    cands = DetectIntegration().rule_candidates(_GAP_REPORT)
    assert cands[0].technique == "T1189"
    assert cands[0].proposed_source == "waf"      # expected mentions WAF/CRS
    assert cands[0].priority == "high"            # MISSED


def test_detect_push_writes_outbox(tmp_path):
    path = DetectIntegration().push(_GAP_REPORT, tmp_path / "outbox")
    import json
    data = json.loads(open(path).read())
    assert data[0]["technique"] == "T1189"


def test_act_playbooks_and_tickets(tmp_path):
    act = ActIntegration()
    pbs = act.playbooks(_GAP_REPORT)
    assert pbs[0].technique == "T1189" and "XSS" in pbs[0].action
    tickets = act.tickets(_GAP_REPORT, min_priority="high")
    assert tickets and "undetected" in tickets[0].labels
    paths = act.push(_GAP_REPORT, tmp_path / "outbox")
    assert paths["tickets"].endswith("act_tickets.json")


def test_act_tickets_respect_min_priority():
    low = {"findings": [{"title": "x", "priority": "low", "asset": "h",
                         "risk": 5, "detection": "DETECTED"}]}
    assert ActIntegration().tickets(low, min_priority="high") == []


# -- RBAC ----------------------------------------------------------------
def test_rbac_matrix():
    rbac = RBAC({"alice": Role.OPERATOR, "bob": Role.APPROVER,
                 "carol": Role.VIEWER, "dan": Role.ADMIN})
    assert rbac.can("alice", Action.START)
    assert not rbac.can("alice", Action.APPROVE)
    assert rbac.can("bob", Action.APPROVE)
    assert not rbac.can("bob", Action.START)
    assert rbac.can("carol", Action.QUERY)
    assert not rbac.can("carol", Action.KILL)
    assert all(rbac.can("dan", a) for a in Action)


def test_rbac_require_raises():
    rbac = RBAC({"carol": Role.VIEWER})
    with pytest.raises(AccessDenied):
        rbac.require("carol", Action.KILL)
    with pytest.raises(AccessDenied):
        rbac.require("eve", Action.QUERY)  # unknown operator


# -- metrics -------------------------------------------------------------
def test_metrics_counters_and_labels():
    m = Metrics()
    m.incr("tool.exec", tool="nmap")
    m.incr("tool.exec", tool="nmap")
    m.incr("tool.exec", tool="nuclei")
    m.gauge("findings.total", 3)
    assert m.get("tool.exec", tool="nmap") == 2
    assert m.get("tool.exec", tool="nuclei") == 1
    assert m.get("findings.total") == 3
