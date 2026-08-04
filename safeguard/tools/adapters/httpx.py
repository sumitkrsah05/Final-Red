"""httpx adapter (ProjectDiscovery) — live-host probing + tech fingerprint.

Runs httpx with JSONL output and normalises each line into an ``endpoint``
asset carrying status, title, webserver and detected technologies. The target
feed flag defaults to ``-u`` and can be overridden via the ToolSpec
(``feed_flag`` in tools.yaml ``extra``) to match the installed httpx build.
"""

from __future__ import annotations

import json

from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Asset, AssetType, ToolResult, ToolStatus


class HttpxAdapter(ToolAdapter):
    default_image = "recon-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        feed_flag = self.spec.extra.get("feed_flag", "-u")
        cmd = ["httpx", "-json", "-silent", "-no-color", *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        cmd += [feed_flag, invocation.target]
        return cmd

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, exit_code=result.exit_code,
                              error="httpx timed out")
        assets: list[Asset] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            assets.append(self._to_asset(rec))
        status = ToolStatus.OK if assets else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, assets=assets)

    @staticmethod
    def _to_asset(rec: dict) -> Asset:
        url = rec.get("url") or rec.get("input") or ""
        tech = {}
        techs = rec.get("tech") or rec.get("technologies")
        if techs:
            tech["technologies"] = techs
        for k in ("webserver", "title", "status_code", "status-code"):
            if rec.get(k) is not None:
                tech[k.replace("-", "_")] = rec[k]
        port = rec.get("port")
        return Asset(
            address=rec.get("host") or url,
            asset_type=AssetType.ENDPOINT,
            port=int(port) if str(port).isdigit() else None,
            protocol=rec.get("scheme"),
            service=rec.get("scheme"),
            tech={"url": url, **tech} if url else tech,
        )
