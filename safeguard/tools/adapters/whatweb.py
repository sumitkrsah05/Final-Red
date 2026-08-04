"""WhatWeb adapter — web technology fingerprinting.

Runs WhatWeb with JSON logging (``--log-json=-``) and normalises the plugin
map into an ``endpoint`` asset whose ``tech`` dict lists detected technologies
and their versions. Aggression is capped at the default (stealthy) level; the
class ceiling forbids the intrusive/aggressive levels.
"""

from __future__ import annotations

import json

from safeguard.safety.exceptions import ForbiddenFlag
from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Asset, AssetType, ToolResult, ToolStatus

# WhatWeb aggression 3 (aggressive) and 4 (heavy) send extra/intrusive requests
# — beyond the active-recon benign-probe class.
_DENY = {"-a", "--aggression"}
_DENY_VALUES = {"3", "4"}


class WhatWebAdapter(ToolAdapter):
    default_image = "recon-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        cmd = ["whatweb", "--log-json=-", "--no-errors", *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        cmd.append(invocation.target)
        return cmd

    def validate(self, command: list[str]) -> None:
        super().validate(command)
        for i, token in enumerate(command):
            head, _, value = token.partition("=")
            if head in _DENY:
                lvl = value or (command[i + 1] if i + 1 < len(command) else "")
                if lvl in _DENY_VALUES:
                    raise ForbiddenFlag(
                        f"whatweb: aggression level {lvl} exceeds active-recon class"
                    )

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, exit_code=result.exit_code,
                              error="whatweb timed out")
        out = result.stdout.strip()
        records: list[dict] = []
        if out:
            try:
                parsed = json.loads(out)
                records = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                # WhatWeb can emit one JSON object per line
                for line in out.splitlines():
                    line = line.strip().rstrip(",")
                    if line.startswith("{"):
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        assets = [self._to_asset(r) for r in records if r.get("target")]
        status = ToolStatus.OK if assets else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, assets=assets)

    @staticmethod
    def _to_asset(rec: dict) -> Asset:
        plugins = rec.get("plugins", {}) or {}
        technologies: dict[str, list] = {}
        for name, info in plugins.items():
            versions = []
            if isinstance(info, dict):
                versions = info.get("version", []) or []
            technologies[name] = versions
        return Asset(
            address=rec.get("target", ""),
            asset_type=AssetType.ENDPOINT,
            tech={
                "http_status": rec.get("http_status"),
                "technologies": technologies,
            },
        )
