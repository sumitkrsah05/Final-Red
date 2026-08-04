"""Prowler adapter — gray-box cloud posture (active-recon, read-only IAM).

Assesses a cloud account's security posture using read-only access and
normalises failed checks into ``Finding`` records. Read-only by nature; the
forbidden-flag guard rejects any mutating/remediation flag so the assessment
cannot change cloud state.
"""

from __future__ import annotations

import json

from safeguard.safety.exceptions import ForbiddenFlag
from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Finding, Severity, ToolResult, ToolStatus

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW,
        "informational": Severity.INFO}
# Prowler can remediate / write with these — never allowed (read-only posture).
_DENY = {"--fixer", "--remediate", "--quick-inventory-write"}


class ProwlerAdapter(ToolAdapter):
    default_image = "cloud-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        provider = str(invocation.params.get("provider", "aws"))
        cmd = ["prowler", provider, "-M", "json", "--status", "FAIL",
               *self.spec.default_flags]
        account = invocation.target
        if account:
            cmd += ["--account", account] if provider == "aws" else ["--subscription", account]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        return cmd

    def validate(self, command: list[str]) -> None:
        super().validate(command)
        for token in command:
            head = token.split("=", 1)[0]
            if token in _DENY or head in _DENY:
                raise ForbiddenFlag(
                    f"prowler: {token!r} would mutate cloud state (read-only only)")

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, error="prowler timed out")
        records = _load(result.stdout or "")
        findings: list[Finding] = []
        for rec in records:
            status_ext = str(rec.get("status") or rec.get("Status", "")).upper()
            if status_ext and status_ext != "FAIL":
                continue
            sev = _SEV.get(str(rec.get("severity") or rec.get("Severity", "")).lower(),
                           Severity.MEDIUM)
            check = rec.get("check_id") or rec.get("CheckID") or "prowler-check"
            resource = rec.get("resource_id") or rec.get("ResourceId", "")
            region = rec.get("region") or rec.get("Region", "")
            findings.append(Finding(
                title=f"{check}: {rec.get('check_title') or rec.get('CheckTitle', '')}",
                asset_ref=f"{invocation.target}/{region}/{resource}".rstrip("/"),
                source_tool=self.name, severity=sev,
                description=rec.get("status_extended")
                or rec.get("StatusExtended", ""),
                raw={"check_id": check, "region": region, "resource": resource}))
        status = ToolStatus.OK if findings else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, findings=findings)


def _load(out: str) -> list[dict]:
    out = out.strip()
    if not out:
        return []
    try:
        data = json.loads(out)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        records = []
        for line in out.splitlines():  # prowler can emit JSON-lines
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records
