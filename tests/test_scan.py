"""Phase 3 tests: nuclei safe-template policy, nikto parsing, cross-tool
finding dedup/merge, and the scan flow through the safety pipeline."""

import pytest

from safeguard.config.models import SafetyClass, ToolSpec
from safeguard.safety.exceptions import ForbiddenFlag
from safeguard.scan.findings import FindingLedger
from safeguard.scan.flow import ScanFlow
from safeguard.tools.adapter import ToolInvocation
from safeguard.tools.adapters.nikto import NiktoAdapter
from safeguard.tools.adapters.nuclei import BANNED_TAGS, NucleiAdapter
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Finding, Severity, ToolStatus


def _spec(name, **extra):
    return ToolSpec(name=name, safety_class=SafetyClass.ACTIVE_RECON,
                    sandbox="scan-runner", **extra)


def _cmd(stdout, code=0):
    return CommandResult(exit_code=code, stdout=stdout, stderr="")


# -- nuclei policy -------------------------------------------------------
def test_nuclei_excludes_banned_tags_by_default():
    cmd = NucleiAdapter(_spec("nuclei", template_policy="safe-only")).build_command(
        ToolInvocation(tool="nuclei", target="https://x"))
    assert "-etags" in cmd
    etags = cmd[cmd.index("-etags") + 1].split(",")
    assert BANNED_TAGS.issubset(set(etags))


def test_nuclei_blocks_reenabling_banned_tags():
    ad = NucleiAdapter(_spec("nuclei", template_policy="safe-only"))
    with pytest.raises(ForbiddenFlag):
        ad.validate(["nuclei", "-tags", "dos,cve", "-u", "https://x"])
    with pytest.raises(ForbiddenFlag):
        ad.validate(["nuclei", "-itags", "cve", "-u", "https://x"])
    ad.validate(["nuclei", "-tags", "cve,exposure", "-u", "https://x"])  # ok


def test_nuclei_parses_severity_and_cve():
    line = ('{"template-id":"tomcat-manager","matched-at":"https://x:8080/manager",'
            '"host":"x","info":{"name":"Exposed Tomcat Manager","severity":"high",'
            '"classification":{"cve-id":["cve-2020-1938"],"cvss-score":9.8}}}')
    res = NucleiAdapter(_spec("nuclei")).parse(
        ToolInvocation(tool="nuclei", target="https://x"), _cmd(line))
    assert res.status is ToolStatus.OK and len(res.findings) == 1
    f = res.findings[0]
    assert f.severity is Severity.HIGH
    assert f.cve_ids == ["CVE-2020-1938"] and f.cvss == 9.8


# -- nikto ---------------------------------------------------------------
def test_nikto_parses_vulnerabilities():
    out = ('[{"host":"10.20.30.44","vulnerabilities":['
           '{"id":"999957","url":"/","msg":"Missing X-Frame-Options header",'
           '"method":"GET"}]}]')
    res = NiktoAdapter(_spec("nikto")).parse(
        ToolInvocation(tool="nikto", target="10.20.30.44"), _cmd(out))
    assert len(res.findings) == 1
    assert res.findings[0].severity is Severity.LOW
    assert "X-Frame-Options" in res.findings[0].title


# -- ledger dedup / merge ------------------------------------------------
def test_ledger_merges_and_keeps_highest_severity():
    led = FindingLedger()
    led.add(Finding(title="Missing header", asset_ref="https://x/",
                    source_tool="nikto", severity=Severity.LOW))
    led.add(Finding(title="missing header", asset_ref="https://x/",
                    source_tool="nuclei", severity=Severity.MEDIUM,
                    cve_ids=["CVE-1"]))
    assert len(led) == 1
    f = led.findings()[0]
    assert f.severity is Severity.MEDIUM
    assert f.cve_ids == ["CVE-1"]
    assert set(f.raw["sources"]) == {"nikto", "nuclei"}


def test_ledger_severity_counts_and_ordering():
    led = FindingLedger()
    led.add(Finding(title="a", asset_ref="h1", source_tool="nuclei",
                    severity=Severity.LOW))
    led.add(Finding(title="b", asset_ref="h2", source_tool="nuclei",
                    severity=Severity.CRITICAL))
    assert led.by_severity() == {"low": 1, "critical": 1}
    assert led.findings()[0].severity is Severity.CRITICAL  # highest first


# -- scan flow -----------------------------------------------------------
class MultiStubRunner:
    def __init__(self, outputs):
        self._outputs = outputs
        self._revoked = False

    def revoke(self):
        self._revoked = True

    def run(self, command, *, image, timeout=300.0, env=None):
        return _cmd(self._outputs.get(command[0], ""))


def test_scan_flow_dedups_across_tools(make_pipeline):
    outputs = {
        "nuclei": '{"template-id":"missing-header","matched-at":"https://10.20.30.44/",'
                  '"info":{"name":"Missing header","severity":"medium"}}',
        "nikto": '[{"host":"https://10.20.30.44","vulnerabilities":['
                 '{"id":"1","url":"/","msg":"Missing header"}]}]',
    }
    pipe = make_pipeline(runner=MultiStubRunner(outputs))
    registry = ToolRegistry({"nuclei": _spec("nuclei"), "nikto": _spec("nikto")})
    report = ScanFlow(pipe, registry).run(["https://10.20.30.44"],
                                          plan=["nuclei", "nikto"])
    assert report.allowed_steps == 2 and report.denied_steps == 0
    # both tools report the same header issue on the same asset -> 1 finding
    assert len(report.ledger) == 1
    f = report.ledger.findings()[0]
    assert set(f.raw["sources"]) == {"nuclei", "nikto"}
    assert f.severity is Severity.MEDIUM
    assert pipe.audit.verify()


def test_scan_flow_blocks_out_of_scope(make_pipeline):
    pipe = make_pipeline(runner=MultiStubRunner({}))
    registry = ToolRegistry({"nuclei": _spec("nuclei")})
    report = ScanFlow(pipe, registry).run(["8.8.8.8"], plan=["nuclei"])
    assert report.denied_steps == 1
    assert "not in ROE allowlist" in report.steps[0].denial
