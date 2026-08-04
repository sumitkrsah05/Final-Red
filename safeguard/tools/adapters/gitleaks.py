"""Gitleaks adapter — white-box secret detection (passive).

Detects committed secrets in provided source. The secret *value* is never
stored (DPDP: evidence is proof-of-signal, not the secret itself) — only the
rule, file, and line are recorded.
"""

from __future__ import annotations

import json

from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Finding, Severity, ToolResult, ToolStatus


class GitleaksAdapter(ToolAdapter):
    default_image = "code-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        # Report to stdout; do not print the raw secret in verbose form.
        cmd = ["gitleaks", "detect", "--no-banner", "--report-format", "json",
               "--report-path", "-", "--source", invocation.target,
               *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        return cmd

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, error="gitleaks timed out")
        try:
            leaks = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            leaks = []
        findings: list[Finding] = []
        for leak in leaks if isinstance(leaks, list) else []:
            file = leak.get("File") or leak.get("file", "?")
            line = leak.get("StartLine") or leak.get("line")
            rule = leak.get("RuleID") or leak.get("rule", "secret")
            findings.append(Finding(
                title=f"Secret '{rule}' in {file}:{line}",
                asset_ref=f"{file}:{line}", source_tool=self.name,
                severity=Severity.HIGH,
                description=leak.get("Description", "committed secret detected"),
                raw={"rule": rule, "file": file, "line": line}))  # value omitted
        status = ToolStatus.OK if findings else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, findings=findings)
