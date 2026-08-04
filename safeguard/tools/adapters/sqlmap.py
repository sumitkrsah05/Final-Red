"""SQLMap adapter — detection-only SQL-injection confirmation.

Runs SQLMap in a strictly non-destructive posture: boolean/time techniques only
(``--technique=BT``), lowest level/risk, non-interactive (``--batch``). Data
extraction, OS/SQL shells, file read/write, and DB enumeration are forbidden —
both by the ToolSpec ``forbidden_flags`` (from tools.yaml) and by an extra
deny-list here, backed again by the global non-destructive profile guard. It
detects the *signal* of injection; it never dumps.

Runs only after named-approver sign-off (enforced by the safety pipeline).
Parses SQLMap's output for a confirmed injection point.
"""

from __future__ import annotations

import re

from safeguard.safety.exceptions import ForbiddenFlag
from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import (
    ToolResult,
    ToolStatus,
    Validation,
    ValidationResult,
)

# Detection-only: nothing that reads/writes data or spawns a shell.
_DENY = {
    "--dump", "--dump-all", "--dumps", "--os-shell", "--os-cmd", "--os-pwn",
    "--sql-shell", "--sql-query", "--file-read", "--file-write", "--file-dest",
    "--passwords", "--dbs", "--tables", "--columns", "--schema", "--users",
    "--all",
}
_CONFIRMED = re.compile(
    r"(sqlmap identified the following injection point|is vulnerable|"
    r"appears to be .* injectable)", re.IGNORECASE)


class SqlmapAdapter(ToolAdapter):
    default_image = "validate-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        cmd = ["sqlmap", "-u", invocation.target, "--batch",
               "--technique=BT", "--level=1", "--risk=1",
               "--disable-coloring", "--flush-session", *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        return cmd

    def validate(self, command: list[str]) -> None:
        super().validate(command)  # tools.yaml forbidden_flags
        for token in command:
            head = token.split("=", 1)[0]
            if token in _DENY or head in _DENY:
                raise ForbiddenFlag(
                    f"sqlmap: {token!r} is beyond detection-only mode")

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, exit_code=result.exit_code,
                              error="sqlmap timed out")
        confirmed = bool(_CONFIRMED.search(result.stdout or ""))
        techniques = re.findall(r"Type:\s*(.+)", result.stdout or "")
        validation = Validation(
            target=invocation.target, method="sqli-detection",
            result=ValidationResult.CONFIRMED if confirmed
            else ValidationResult.INCONCLUSIVE,
            tool=self.name,
            detail={"techniques": [t.strip() for t in techniques]})
        status = ToolStatus.OK if confirmed else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, validations=[validation])
