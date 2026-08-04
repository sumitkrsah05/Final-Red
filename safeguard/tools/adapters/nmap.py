"""Nmap adapter — the Phase 1 reference implementation.

Runs Nmap with XML output (``-oX -``) and parses hosts/ports/services into
``Asset`` records. Service-version detection (``-sV -T3``) comes from tools.yaml
default flags. Aggressive timing and NSE scripts are not added by default; the
forbidden-flag guard in the base ``validate`` blocks anything the ToolSpec bans.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Asset, AssetType, ToolResult, ToolStatus

# Flags that would push Nmap out of the active-recon (benign probe) class.
# Blocked regardless of what the planner proposes.
_DENY = {"-A", "-O", "--script", "-sU", "-T4", "-T5"}


class NmapAdapter(ToolAdapter):
    default_image = "recon-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        cmd = ["nmap", *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        ports = invocation.params.get("ports")
        if ports:
            cmd += ["-p", str(ports)]
        cmd += ["-oX", "-", invocation.target]
        return cmd

    def validate(self, command: list[str]) -> None:
        super().validate(command)
        for token in command:
            head = token.split("=", 1)[0]
            if token in _DENY or head in _DENY:
                from safeguard.safety.exceptions import ForbiddenFlag

                raise ForbiddenFlag(
                    f"nmap: flag {token!r} exceeds active-recon class"
                )

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        command = ["nmap"]  # placeholder; real command echoed by pipeline
        if result.timed_out:
            return ToolResult(
                tool=self.name,
                status=ToolStatus.ERROR,
                target=invocation.target,
                exit_code=result.exit_code,
                error="nmap timed out",
            )
        assets: list[Asset] = []
        xml = result.stdout.strip()
        if xml:
            try:
                assets = self._parse_xml(xml)
            except ET.ParseError as exc:
                return ToolResult(
                    tool=self.name,
                    status=ToolStatus.ERROR,
                    target=invocation.target,
                    exit_code=result.exit_code,
                    error=f"nmap XML parse error: {exc}",
                )
        status = ToolStatus.OK if assets else ToolStatus.NO_RESULTS
        return ToolResult(
            tool=self.name,
            status=status,
            target=invocation.target,
            exit_code=result.exit_code,
            assets=assets,
            detail={"host_count": len({a.address for a in assets})},
        )

    @staticmethod
    def _parse_xml(xml: str) -> list[Asset]:
        root = ET.fromstring(xml)
        assets: list[Asset] = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            address = addr_el.get("addr") if addr_el is not None else None
            if not address:
                continue
            # host-level asset
            assets.append(Asset(address=address, asset_type=AssetType.HOST))
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                tech: dict = {}
                service_name = None
                if svc is not None:
                    service_name = svc.get("name")
                    for k in ("product", "version", "extrainfo"):
                        if svc.get(k):
                            tech[k] = svc.get(k)
                assets.append(
                    Asset(
                        address=address,
                        asset_type=AssetType.SERVICE,
                        port=int(port.get("portid")),
                        protocol=port.get("protocol"),
                        service=service_name,
                        tech=tech,
                    )
                )
        return assets
