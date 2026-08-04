"""Phase 9 tests: gray/white-box adapters (parsing + read-only guards), scope
matching for repos/cloud accounts, and a mode-aware white-box engagement."""

import dataclasses

import pytest

from safeguard.config.models import (
    Exclusions, Mode, RulesOfEngagement, SafetyClass, ScopeSpec, ToolSpec,
)
from safeguard.graph.build import build_engagement_graph
from safeguard.graph.state import AgentState
from safeguard.llm.planner import RulePlanner
from safeguard.recon.flow import ReconFlow
from safeguard.safety.exceptions import ForbiddenFlag, OutOfScope
from safeguard.safety.scope_guard import ScopeGuard, Target
from safeguard.scan.flow import ScanFlow
from safeguard.tools.adapter import ToolInvocation
from safeguard.tools.adapters.checkov import CheckovAdapter
from safeguard.tools.adapters.gitleaks import GitleaksAdapter
from safeguard.tools.adapters.prowler import ProwlerAdapter
from safeguard.tools.adapters.semgrep import SemgrepAdapter
from safeguard.tools.adapters.trivy import TrivyAdapter
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Severity, ToolStatus


def _cmd(stdout, code=0):
    return CommandResult(exit_code=code, stdout=stdout, stderr="")


def _spec(name, cls=SafetyClass.PASSIVE, **extra):
    return ToolSpec(name=name, safety_class=cls, **extra)


# -- white-box adapters --------------------------------------------------
def test_semgrep_parses_results():
    out = ('{"results":[{"check_id":"py.lang.security.audit.exec",'
           '"path":"app.py","start":{"line":10},'
           '"extra":{"severity":"ERROR","message":"use of exec"}}]}')
    res = SemgrepAdapter(_spec("semgrep")).parse(
        ToolInvocation(tool="semgrep", target="./src"), _cmd(out))
    assert res.status is ToolStatus.OK
    assert res.findings[0].severity is Severity.HIGH
    assert "app.py:10" in res.findings[0].asset_ref


def test_gitleaks_omits_secret_value():
    out = ('[{"RuleID":"aws-access-key","File":"config.env","StartLine":3,'
           '"Secret":"AKIAREALSECRET","Description":"AWS key"}]')
    res = GitleaksAdapter(_spec("gitleaks")).parse(
        ToolInvocation(tool="gitleaks", target="./repo"), _cmd(out))
    f = res.findings[0]
    assert f.severity is Severity.HIGH
    assert "AKIAREALSECRET" not in str(f.raw)  # DPDP: value not stored


def test_checkov_parses_failed_checks():
    out = ('{"results":{"failed_checks":[{"check_id":"CKV_AWS_20",'
           '"check_name":"S3 not public","file_path":"main.tf",'
           '"resource":"aws_s3_bucket.data","severity":"HIGH"}]}}')
    res = CheckovAdapter(_spec("checkov")).parse(
        ToolInvocation(tool="checkov", target="./iac"), _cmd(out))
    assert res.findings[0].severity is Severity.HIGH
    assert "CKV_AWS_20" in res.findings[0].title


# -- cloud / dependency adapters ----------------------------------------
def test_trivy_parses_cve_and_cvss():
    out = ('{"Results":[{"Target":"app","Vulnerabilities":[{'
           '"VulnerabilityID":"CVE-2021-44228","Severity":"CRITICAL",'
           '"PkgName":"log4j","Title":"Log4Shell",'
           '"CVSS":{"nvd":{"V3Score":10.0}}}]}]}')
    res = TrivyAdapter(_spec("trivy", cls=SafetyClass.ACTIVE_RECON)).parse(
        ToolInvocation(tool="trivy", target="app"), _cmd(out))
    f = res.findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.cve_ids == ["CVE-2021-44228"] and f.cvss == 10.0


def test_prowler_parses_fail_and_blocks_mutating_flags():
    out = ('[{"check_id":"iam_root_mfa","status":"FAIL","severity":"high",'
           '"region":"us-east-1","resource_id":"root","check_title":"Root MFA"}]')
    ad = ProwlerAdapter(_spec("prowler", cls=SafetyClass.ACTIVE_RECON))
    res = ad.parse(ToolInvocation(tool="prowler", target="123456789012"), _cmd(out))
    assert res.findings[0].severity is Severity.HIGH
    with pytest.raises(ForbiddenFlag):
        ad.validate(["prowler", "aws", "--fixer"])


# -- scope for repos / cloud accounts ------------------------------------
def _roe(mode, **scope):
    return RulesOfEngagement(
        engagement_id="e", owner="o", authorised_by="m", authorisation_ref="R",
        mode=mode, profile="non_destructive",
        scope=ScopeSpec(**scope), exclusions=Exclusions(),
        timezone="Asia/Kolkata",
        windows=(dataclasses.replace(_win()),), approvers=("void",),
        budget=_budget())


def _win():
    from safeguard.config.models import TimeWindow
    return TimeWindow(days=("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"),
                      start="00:00", end="23:59")


def _budget():
    from safeguard.config.models import Budget
    return Budget(max_total_actions=50)


def test_scope_allows_repo_and_cloud_account():
    roe = _roe(Mode.WHITE_BOX, repos=("./src",), cloud_accounts=("123456789012",))
    g = ScopeGuard(roe)
    g.check_target(Target(raw="./src"))
    g.check_target(Target(raw="123456789012"))
    with pytest.raises(OutOfScope):
        g.check_target(Target(raw="./other"))


# -- mode-aware white-box engagement ------------------------------------
class StubRunner:
    def __init__(self, out):
        self._out = out
        self._revoked = False
    def revoke(self):
        self._revoked = True
    def run(self, command, *, image, timeout=300.0, env=None):
        return _cmd(self._out.get(command[0], ""))


def test_white_box_engagement_scans_source_no_recon(make_pipeline):
    roe = _roe(Mode.WHITE_BOX, repos=("./src",))
    # rebuild pipeline bound to this white-box ROE
    from safeguard.safety.pipeline import SafetyPipeline
    from safeguard.safety.scope_guard import ScopeGuard as SG
    from safeguard.safety.rate_limiter import RateLimiter
    from safeguard.safety.killswitch import KillSwitch
    from safeguard.safety.audit import AuditLog
    from safeguard.safety.approvals import ApprovalStore
    from safeguard.tools.runner import LocalSubprocessRunner
    from datetime import datetime
    from zoneinfo import ZoneInfo
    import itertools
    tz = ZoneInfo(roe.timezone)
    ticker = itertools.count()
    runner = StubRunner({"semgrep": '{"results":[{"check_id":"exec","path":"a.py",'
                         '"start":{"line":1},"extra":{"severity":"ERROR",'
                         '"message":"exec"}}]}'})
    pipe = SafetyPipeline(
        roe=roe, scope_guard=SG(roe), rate_limiter=RateLimiter(roe.budget),
        kill_switch=KillSwitch(), audit=AuditLog("e"), runner=runner,
        approvals=ApprovalStore(),
        now_fn=lambda: datetime(2026, 8, 4, 3, 0, tzinfo=tz),
        monotonic_fn=lambda: next(ticker) * 0.01)
    reg = ToolRegistry({
        "semgrep": _spec("semgrep", cls=SafetyClass.PASSIVE),
        "gitleaks": _spec("gitleaks", cls=SafetyClass.PASSIVE),
        "checkov": _spec("checkov", cls=SafetyClass.PASSIVE),
        "trivy": _spec("trivy", cls=SafetyClass.ACTIVE_RECON)})
    graph = build_engagement_graph(
        roe=roe, recon=ReconFlow(pipe, reg), scan=ScanFlow(pipe, reg),
        planner=RulePlanner(reg)).compile()
    st = AgentState(engagement_id="e", mode="white_box", profile="non_destructive",
                    targets=["./src"], max_actions=50)
    result = graph.invoke(st, thread_id="wb")
    assert result.status == "complete"
    actions = [h["action"] for h in result.state.plan_history]
    assert "recon" not in actions        # no network recon in white-box
    assert "scan" in actions and "report" in actions
    assert len(result.state.ledger) >= 1  # semgrep finding folded in
