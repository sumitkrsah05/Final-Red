"""Phase 5 tests: dalfox/sqlmap adapters, the non-destructive profile guard,
approval-gated validation through the pipeline, and evidence capture."""

import pytest

from safeguard.config.models import SafetyClass, ToolSpec
from safeguard.evidence import EvidenceStore
from safeguard.safety.approvals import ApprovalDecision, ApprovalStore
from safeguard.safety.exceptions import ForbiddenFlag, ProfileViolation
from safeguard.safety.pipeline import ActionRequest
from safeguard.safety.profile import ProfileGuard
from safeguard.safety.scope_guard import Target
from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.adapters.dalfox import DalfoxAdapter
from safeguard.tools.adapters.sqlmap import SqlmapAdapter
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import ToolResult, ToolStatus, ValidationResult
from safeguard.validate.flow import ValidateFlow


def _cmd(stdout, code=0):
    return CommandResult(exit_code=code, stdout=stdout, stderr="")


def _vspec(name, **extra):
    return ToolSpec(name=name, safety_class=SafetyClass.ACTIVE_VALIDATE,
                    sandbox="validate-runner", **extra)


# -- dalfox --------------------------------------------------------------
def test_dalfox_confirms_reflected_xss():
    out = '[{"type":"V","method":"GET","param":"q","data":"<svg/onload>"}]'
    res = DalfoxAdapter(_vspec("dalfox")).parse(
        ToolInvocation(tool="dalfox", target="https://x?q=1"), _cmd(out))
    assert res.status is ToolStatus.OK
    assert res.validations[0].result is ValidationResult.CONFIRMED
    assert res.validations[0].method == "reflected-xss"


def test_dalfox_inconclusive_when_empty():
    res = DalfoxAdapter(_vspec("dalfox")).parse(
        ToolInvocation(tool="dalfox", target="https://x"), _cmd(""))
    assert res.validations[0].result is ValidationResult.INCONCLUSIVE


def test_dalfox_blocks_blind_and_exploit():
    ad = DalfoxAdapter(_vspec("dalfox"))
    for bad in (["dalfox", "url", "x", "--blind"], ["dalfox", "url", "x", "--exploit"]):
        with pytest.raises(ForbiddenFlag):
            ad.validate(bad)


# -- sqlmap --------------------------------------------------------------
def test_sqlmap_detects_injection():
    out = ("sqlmap identified the following injection point\n"
           "Parameter: id (GET)\n    Type: boolean-based blind\n")
    res = SqlmapAdapter(_vspec("sqlmap")).parse(
        ToolInvocation(tool="sqlmap", target="https://x?id=1"), _cmd(out))
    assert res.status is ToolStatus.OK
    v = res.validations[0]
    assert v.result is ValidationResult.CONFIRMED
    assert any("boolean" in t for t in v.detail["techniques"])


def test_sqlmap_blocks_dump_and_shell():
    ad = SqlmapAdapter(_vspec("sqlmap",
                              forbidden_flags=("--dump", "--os-shell")))
    for bad in (["sqlmap", "-u", "x", "--dump"], ["sqlmap", "-u", "x", "--os-shell"],
                ["sqlmap", "-u", "x", "--tables"]):
        with pytest.raises(ForbiddenFlag):
            ad.validate(bad)


# -- profile guard (defence in depth) ------------------------------------
def test_profile_guard_blocks_destructive_tokens():
    g = ProfileGuard("non_destructive")
    g.check(["nmap", "-sV", "10.0.0.1"])  # benign ok
    for bad in (["sqlmap", "--os-shell"], ["x", "--dump"], ["x", "--file-write=y"]):
        with pytest.raises(ProfileViolation):
            g.check(bad)


def test_profile_guard_non_default_profile_fails_closed():
    with pytest.raises(ProfileViolation):
        ProfileGuard("aggressive").check(["nmap", "-sV"])


def test_pipeline_profile_guard_denies_destructive(make_pipeline):
    """Even a tool the class ceiling would pass is stopped by the profile guard."""
    class Destructive(ToolAdapter):
        def build_command(self, inv):
            return ["sqlmap", "-u", inv.target, "--os-shell"]  # no forbidden_flags set
        def parse(self, inv, result):
            return ToolResult(tool=self.name, status=ToolStatus.OK, target=inv.target)

    spec = ToolSpec(name="sqlmap", safety_class=SafetyClass.ACTIVE_VALIDATE)
    approvals = ApprovalStore()
    pipe = make_pipeline(approvals=approvals)
    req = approvals.create(engagement_id="e", tool="sqlmap", target="10.20.30.44",
                           technique="t", rationale="r")
    approvals.resolve(req.request_id, decision=ApprovalDecision.APPROVED, approver="void")
    out = pipe.execute(Destructive(spec), ActionRequest(
        invocation=ToolInvocation(tool="sqlmap", target="10.20.30.44",
                                  approval_id=req.request_id),
        target=Target(raw="10.20.30.44")))
    assert not out.allowed and "destructive" in out.denial


# -- validate flow: approval-gated + evidence ----------------------------
class StubRunner:
    def __init__(self, out):
        self._out = out
        self._revoked = False
    def revoke(self):
        self._revoked = True
    def run(self, command, *, image, timeout=300.0, env=None):
        return _cmd(self._out.get(command[0], ""))


def test_validate_flow_requires_approval_then_confirms(make_pipeline):
    approvals = ApprovalStore()
    evidence = EvidenceStore()
    runner = StubRunner({"dalfox": '[{"type":"V","method":"GET","param":"q"}]'})
    pipe = make_pipeline(runner=runner, approvals=approvals, evidence=evidence)
    reg = ToolRegistry({"dalfox": _vspec("dalfox")})
    flow = ValidateFlow(pipe, reg)

    # 1. no approval -> denied
    out = flow.run(tool="dalfox", target="10.20.30.44", approval_id=None)
    assert not out.allowed and "approver" in out.denial

    # 2. approved -> runs, confirms, evidence captured
    req = approvals.create(engagement_id="e", tool="dalfox", target="10.20.30.44",
                           technique="xss", rationale="confirm")
    approvals.resolve(req.request_id, decision=ApprovalDecision.APPROVED, approver="void")
    out2 = flow.run(tool="dalfox", target="10.20.30.44", approval_id=req.request_id,
                    technique="xss")
    assert out2.allowed
    v = out2.validations[0]
    assert v.result is ValidationResult.CONFIRMED
    assert v.approved_by == "void"
    assert v.evidence_ref and evidence.get(v.evidence_ref) is not None
