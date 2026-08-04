"""Dalfox adapter — reflected-XSS confirmation (active-validate, non-destructive).

Confirms the *signal* of reflected XSS with a benign marker payload; it never
weaponises. Blind/out-of-band and remote-payload modes are rejected by the class
ceiling (and by the global non-destructive profile guard). Runs only after a
named approver has signed off — enforced by the safety pipeline, not here.

Parses Dalfox JSON output into ``Validation`` records: any reported PoC ⇒
``confirmed``; otherwise ``inconclusive``.
"""

from __future__ import annotations

import json

from safeguard.safety.exceptions import ForbiddenFlag
from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import (
    ToolResult,
    ToolStatus,
    Validation,
    ValidationResult,
)

# Flags that would move Dalfox from confirmation to exploitation / OOB.
_DENY = {"--blind", "-b", "--exploit", "--remote-payloads", "--remote-wordlists",
         "--grep", "--har-file-path"}


class DalfoxAdapter(ToolAdapter):
    default_image = "validate-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        cmd = ["dalfox", "url", invocation.target, "--format", "json",
               "--no-color", "--silence", *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        return cmd

    def validate(self, command: list[str]) -> None:
        super().validate(command)
        for token in command:
            head = token.split("=", 1)[0]
            if token in _DENY or head in _DENY:
                raise ForbiddenFlag(
                    f"dalfox: {token!r} exceeds reflection-only confirmation")

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, exit_code=result.exit_code,
                              error="dalfox timed out")
        pocs = self._pocs(result.stdout)
        if pocs:
            validations = [Validation(
                target=invocation.target, method="reflected-xss",
                result=ValidationResult.CONFIRMED, tool=self.name,
                detail={"type": p.get("type"), "method": p.get("method"),
                        "param": p.get("param") or p.get("data")})
                for p in pocs]
            status = ToolStatus.OK
        else:
            validations = [Validation(
                target=invocation.target, method="reflected-xss",
                result=ValidationResult.INCONCLUSIVE, tool=self.name)]
            status = ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, validations=validations)

    @staticmethod
    def _pocs(stdout: str) -> list[dict]:
        out = stdout.strip()
        if not out:
            return []
        try:
            data = json.loads(out)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pocs = []
            for line in out.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        pocs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return pocs
        return []
