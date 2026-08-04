"""Checkov adapter — white-box IaC scanning (passive).

Scans infrastructure-as-code (Terraform, CloudFormation, k8s manifests, …) for
misconfigurations and normalises failed checks into ``Finding`` records.
"""

from __future__ import annotations

import json

from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Finding, Severity, ToolResult, ToolStatus

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


class CheckovAdapter(ToolAdapter):
    default_image = "code-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        cmd = ["checkov", "-d", invocation.target, "-o", "json", "--compact",
               *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        return cmd

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, error="checkov timed out")
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            data = {}
        # checkov emits an object or a list of {check_type, results}.
        blocks = data if isinstance(data, list) else [data]
        findings: list[Finding] = []
        for block in blocks:
            results = (block.get("results", {}) or {}) if isinstance(block, dict) else {}
            for chk in results.get("failed_checks", []) or []:
                sev = _SEV.get(str(chk.get("severity", "MEDIUM")).upper(),
                               Severity.MEDIUM)
                file = chk.get("file_path", "?")
                findings.append(Finding(
                    title=f"{chk.get('check_id')}: {chk.get('check_name', '')}",
                    asset_ref=f"{file}:{chk.get('resource', '')}",
                    source_tool=self.name, severity=sev,
                    description=chk.get("check_name", ""),
                    raw={"check_id": chk.get("check_id"), "file": file,
                         "resource": chk.get("resource")}))
        status = ToolStatus.OK if findings else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, findings=findings)
