"""Phase 1 tests: Nmap adapter parsing + the full safety pipeline path
(scope block, approval gate, kill switch, forbidden flag, happy path)."""

from datetime import datetime
from zoneinfo import ZoneInfo

from safeguard.safety.approvals import ApprovalStore, ApprovalDecision
from safeguard.safety.killswitch import KillSwitch
from safeguard.safety.pipeline import ActionRequest
from safeguard.safety.scope_guard import Target
from safeguard.tools.adapter import ToolInvocation
from safeguard.tools.adapters.nmap import NmapAdapter
from safeguard.tools.runner import CommandResult, LocalSubprocessRunner
from safeguard.tools.schema import ToolStatus


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.20.30.44" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy" product="Apache Tomcat" version="8.5"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class StubRunner(LocalSubprocessRunner):
    """Returns canned nmap XML without executing anything."""

    def __init__(self, stdout):
        super().__init__(dry_run=False)
        self._stdout = stdout

    def run(self, command, *, image, timeout=300.0, env=None):
        if self._revoked:
            from safeguard.tools.runner import SandboxError
            raise SandboxError("revoked")
        return CommandResult(exit_code=0, stdout=self._stdout, stderr="")


def _inv(target="10.20.30.44", **kw):
    return ToolInvocation(tool="nmap", target=target, **kw)


def test_nmap_parses_open_ports(nmap_spec):
    adapter = NmapAdapter(nmap_spec)
    res = adapter.parse(_inv(), CommandResult(exit_code=0, stdout=_NMAP_XML, stderr=""))
    assert res.status is ToolStatus.OK
    services = [a for a in res.assets if a.asset_type.value == "service"]
    assert {s.port for s in services} == {443, 8080}  # closed 22 excluded
    tomcat = next(s for s in services if s.port == 8080)
    assert tomcat.tech.get("product") == "Apache Tomcat"


def test_pipeline_happy_path(make_pipeline, nmap_spec):
    pipe = make_pipeline(runner=StubRunner(_NMAP_XML))
    adapter = NmapAdapter(nmap_spec)
    out = pipe.execute(adapter, ActionRequest(invocation=_inv(),
                                              target=Target(raw="10.20.30.44")))
    assert out.allowed
    assert out.result.status is ToolStatus.OK
    assert any(a.port == 443 for a in out.result.assets)
    # audit recorded proposed + exec + result
    actions = [e.action for e in pipe.audit.events()]
    assert "tool.proposed" in actions and "tool.result" in actions
    assert pipe.audit.verify()


def test_pipeline_blocks_out_of_scope(make_pipeline, nmap_spec):
    pipe = make_pipeline(runner=StubRunner(_NMAP_XML))
    adapter = NmapAdapter(nmap_spec)
    out = pipe.execute(adapter, ActionRequest(invocation=_inv(target="8.8.8.8"),
                                              target=Target(raw="8.8.8.8")))
    assert not out.allowed
    assert "not in ROE allowlist" in out.denial
    assert "tool.denied" in [e.action for e in pipe.audit.events()]


def test_pipeline_kill_switch(make_pipeline, nmap_spec):
    pipe = make_pipeline(runner=StubRunner(_NMAP_XML))
    pipe.kill.engage("operator halt")
    out = pipe.execute(NmapAdapter(nmap_spec),
                       ActionRequest(invocation=_inv(), target=Target(raw="10.20.30.44")))
    assert not out.allowed
    assert "kill switch" in out.denial.lower()


def test_active_validate_requires_approval(make_pipeline):
    from safeguard.config.models import SafetyClass, ToolSpec
    from safeguard.tools.adapter import ToolAdapter

    class DummyValidate(ToolAdapter):
        def build_command(self, invocation):
            return ["true"]
        def parse(self, invocation, result):
            from safeguard.tools.schema import ToolResult
            return ToolResult(tool=self.name, status=ToolStatus.OK, target=invocation.target)

    spec = ToolSpec(name="dalfox", safety_class=SafetyClass.ACTIVE_VALIDATE)
    approvals = ApprovalStore()
    pipe = make_pipeline(runner=LocalSubprocessRunner(dry_run=True), approvals=approvals)
    adapter = DummyValidate(spec)

    # 1. no approval -> denied
    out = pipe.execute(adapter, ActionRequest(
        invocation=ToolInvocation(tool="dalfox", target="10.20.30.44"),
        target=Target(raw="10.20.30.44")))
    assert not out.allowed and "approver" in out.denial

    # 2. with approval -> allowed
    req = approvals.create(engagement_id="e", tool="dalfox", target="10.20.30.44",
                           technique="xss-reflection", rationale="confirm")
    approvals.resolve(req.request_id, decision=ApprovalDecision.APPROVED, approver="void")
    out2 = pipe.execute(adapter, ActionRequest(
        invocation=ToolInvocation(tool="dalfox", target="10.20.30.44",
                                  approval_id=req.request_id),
        target=Target(raw="10.20.30.44")))
    assert out2.allowed


def test_forbidden_flag_blocked(nmap_spec):
    from safeguard.config.models import ToolSpec, SafetyClass
    from safeguard.safety.exceptions import ForbiddenFlag
    spec = ToolSpec(name="nmap", safety_class=SafetyClass.ACTIVE_RECON,
                    default_flags=("-sV",), forbidden_flags=("-A",))
    adapter = NmapAdapter(spec)
    import pytest
    with pytest.raises(ForbiddenFlag):
        adapter.validate(["nmap", "-A", "10.20.30.44"])
