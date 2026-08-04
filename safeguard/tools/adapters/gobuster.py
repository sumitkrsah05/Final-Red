"""Gobuster adapter — content/directory discovery.

Runs ``gobuster dir`` against a base URL with a wordlist and normalises each
discovered path into an ``endpoint`` asset. A wordlist must be supplied
(``params['wordlist']``); without one the invocation is rejected at build time
rather than silently scanning nothing.

Parses both the quiet plain-text format (``/admin (Status: 200) [Size: 1234]``)
and, when ``params['json']`` is set, gobuster's JSON output.
"""

from __future__ import annotations

import json
import re

from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Asset, AssetType, ToolResult, ToolStatus

_LINE = re.compile(r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)"
                   r"(?:\s+\[Size:\s*(?P<size>\d+)\])?")


class GobusterAdapter(ToolAdapter):
    default_image = "recon-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        wordlist = invocation.params.get("wordlist")
        if not wordlist:
            raise ValueError("gobuster requires params['wordlist']")
        cmd = ["gobuster", "dir", "-u", invocation.target, "-w", str(wordlist),
               "-q", "--no-color", *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        return cmd

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, exit_code=result.exit_code,
                              error="gobuster timed out")
        base = invocation.target.rstrip("/")
        assets: list[Asset] = []
        for path, status_code, size in self._iter_hits(result.stdout):
            assets.append(Asset(
                address=f"{base}{path}",
                asset_type=AssetType.ENDPOINT,
                tech={"path": path, "status": status_code, "size": size},
            ))
        status = ToolStatus.OK if assets else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, assets=assets,
                          detail={"paths_found": len(assets)})

    @staticmethod
    def _iter_hits(stdout: str):
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                path = rec.get("path") or rec.get("url")
                if path:
                    yield path, rec.get("status"), rec.get("size")
                continue
            m = _LINE.match(line)
            if m:
                size = m.group("size")
                yield (m.group("path"), int(m.group("status")),
                       int(size) if size else None)
