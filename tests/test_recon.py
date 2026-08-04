"""Phase 2 tests: recon adapters (httpx/whatweb/gobuster) parsing,
asset dedup/merge, and the recon flow through the safety pipeline."""

import pytest

from safeguard.config.models import SafetyClass, ToolSpec
from safeguard.recon.assets import AssetInventory
from safeguard.recon.flow import ReconFlow
from safeguard.tools.adapter import ToolInvocation
from safeguard.tools.adapters.gobuster import GobusterAdapter
from safeguard.tools.adapters.httpx import HttpxAdapter
from safeguard.tools.adapters.whatweb import WhatWebAdapter
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Asset, AssetType, ToolStatus


def _spec(name, cls=SafetyClass.ACTIVE_RECON, **extra):
    return ToolSpec(name=name, safety_class=cls, sandbox="recon-runner", extra=extra)


def _cmd(stdout, code=0):
    return CommandResult(exit_code=code, stdout=stdout, stderr="")


# -- adapter parsing -----------------------------------------------------
def test_httpx_parses_jsonl():
    out = (
        '{"url":"https://demo-app.esds-lab.internal","host":"10.20.30.44",'
        '"port":443,"scheme":"https","status_code":200,"webserver":"nginx",'
        '"tech":["Nginx","Tomcat"],"title":"Home"}\n'
        'garbage line\n'
    )
    res = HttpxAdapter(_spec("httpx")).parse(
        ToolInvocation(tool="httpx", target="10.20.30.44"), _cmd(out))
    assert res.status is ToolStatus.OK and len(res.assets) == 1
    a = res.assets[0]
    assert a.asset_type is AssetType.ENDPOINT
    assert a.port == 443 and a.tech["technologies"] == ["Nginx", "Tomcat"]


def test_whatweb_parses_plugins():
    out = ('[{"target":"https://demo-app.esds-lab.internal","http_status":200,'
           '"plugins":{"nginx":{"version":["1.24"]},"Tomcat":{"version":[]}}}]')
    res = WhatWebAdapter(_spec("whatweb")).parse(
        ToolInvocation(tool="whatweb", target="x"), _cmd(out))
    assert len(res.assets) == 1
    techs = res.assets[0].tech["technologies"]
    assert techs["nginx"] == ["1.24"] and "Tomcat" in techs


def test_whatweb_aggression_blocked():
    from safeguard.safety.exceptions import ForbiddenFlag
    ad = WhatWebAdapter(_spec("whatweb"))
    with pytest.raises(ForbiddenFlag):
        ad.validate(["whatweb", "-a", "4", "https://x"])
    with pytest.raises(ForbiddenFlag):
        ad.validate(["whatweb", "--aggression=3", "https://x"])
    ad.validate(["whatweb", "-a", "1", "https://x"])  # stealthy ok


def test_gobuster_parses_paths_and_requires_wordlist():
    ad = GobusterAdapter(_spec("gobuster"))
    with pytest.raises(ValueError):
        ad.build_command(ToolInvocation(tool="gobuster", target="https://x"))
    cmd = ad.build_command(ToolInvocation(tool="gobuster", target="https://x/",
                                          params={"wordlist": "/w.txt"}))
    assert "-w" in cmd and "/w.txt" in cmd
    out = "/admin (Status: 200) [Size: 1234]\n/api (Status: 301)\n"
    res = ad.parse(ToolInvocation(tool="gobuster", target="https://x/",
                                  params={"wordlist": "/w.txt"}), _cmd(out))
    addrs = {a.address for a in res.assets}
    assert addrs == {"https://x/admin", "https://x/api"}


# -- dedup / merge -------------------------------------------------------
def test_inventory_merges_same_service():
    inv = AssetInventory()
    inv.add(Asset(address="10.20.30.44", asset_type=AssetType.SERVICE, port=443,
                  protocol="tcp", service="https", tech={"product": "nginx"}))
    inv.add(Asset(address="10.20.30.44", asset_type=AssetType.SERVICE, port=443,
                  protocol="tcp", tech={"technologies": ["Nginx"]}))
    assert len(inv) == 1
    merged = inv.assets()[0]
    assert merged.service == "https"
    assert merged.tech["product"] == "nginx"
    assert merged.tech["technologies"] == ["Nginx"]


def test_inventory_distinct_ports_not_merged():
    inv = AssetInventory()
    inv.add(Asset(address="h", asset_type=AssetType.SERVICE, port=443, protocol="tcp"))
    inv.add(Asset(address="h", asset_type=AssetType.SERVICE, port=8080, protocol="tcp"))
    assert len(inv) == 2


# -- flow through pipeline ----------------------------------------------
class MultiStubRunner:
    """Returns canned stdout keyed by the tool binary in the command."""

    def __init__(self, outputs):
        self._outputs = outputs
        self._revoked = False

    def revoke(self):
        self._revoked = True

    def run(self, command, *, image, timeout=300.0, env=None):
        return _cmd(self._outputs.get(command[0], ""))


def test_recon_flow_merges_across_tools(make_pipeline):
    outputs = {
        "nmap": '<?xml version="1.0"?><nmaprun><host>'
                '<address addr="10.20.30.44" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="443"><state state="open"/>'
                '<service name="https" product="nginx"/></port></ports>'
                '</host></nmaprun>',
        "httpx": '{"url":"https://10.20.30.44","host":"10.20.30.44","port":443,'
                 '"scheme":"https","tech":["Nginx"]}',
        "whatweb": '[{"target":"https://10.20.30.44","http_status":200,'
                   '"plugins":{"nginx":{"version":["1.24"]}}}]',
    }
    pipe = make_pipeline(runner=MultiStubRunner(outputs))
    registry = ToolRegistry({
        "nmap": _spec("nmap", default_flags=()),
        "httpx": _spec("httpx"),
        "whatweb": _spec("whatweb"),
    })
    flow = ReconFlow(pipe, registry)
    report = flow.run(["10.20.30.44"], plan=["nmap", "httpx", "whatweb"])

    assert report.allowed_steps == 3 and report.denied_steps == 0
    assert len(report.inventory) >= 1
    assert "10.20.30.44" in report.inventory.hosts()
    assert pipe.audit.verify()


def test_recon_flow_records_denied_out_of_scope(make_pipeline):
    pipe = make_pipeline(runner=MultiStubRunner({}))
    registry = ToolRegistry({"nmap": _spec("nmap")})
    report = ReconFlow(pipe, registry).run(["8.8.8.8"], plan=["nmap"])
    assert report.denied_steps == 1
    assert "not in ROE allowlist" in report.steps[0].denial
