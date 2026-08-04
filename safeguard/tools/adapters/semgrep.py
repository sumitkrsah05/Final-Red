"""Semgrep adapter — white-box SAST (passive).

Runs Semgrep over provided source and normalises results into ``Finding`` records.
Passive class: it reads source only, sends no packets to any target. Rules come
from a local/provided config (sovereign: no auto-fetch of remote rules unless the
operator supplies a ruleset).
"""

from __future__ import annotations

import json

from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Finding, Severity, ToolResult, ToolStatus

_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


class SemgrepAdapter(ToolAdapter):
    default_image = "code-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore",
               *self.spec.default_flags]
        config = invocation.params.get("config")
        if config:
            cmd += ["--config", str(config)]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        cmd.append(invocation.target)
        return cmd

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, error="semgrep timed out")
        findings: list[Finding] = []
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            data = {}
        for r in data.get("results", []) or []:
            extra = r.get("extra", {}) or {}
            path = r.get("path", invocation.target)
            line = (r.get("start", {}) or {}).get("line")
            findings.append(Finding(
                title=f"{r.get('check_id', 'semgrep')} @ {path}:{line}",
                asset_ref=f"{path}:{line}", source_tool=self.name,
                severity=_SEV.get(str(extra.get("severity", "INFO")).upper(),
                                  Severity.LOW),
                description=extra.get("message", ""),
                raw={"check_id": r.get("check_id"), "path": path, "line": line}))
        status = ToolStatus.OK if findings else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, findings=findings)
