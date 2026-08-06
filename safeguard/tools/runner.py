"""Sandbox runner abstraction.

In production, tools run in ephemeral, egress-pinned gVisor/Firecracker
microVMs whose firewall is bound to the ROE allowlist, so a tool physically
cannot reach an out-of-scope host. That infrastructure is Phase 10 / deployment.

Phase 1 defines the ``SandboxRunner`` interface plus a ``LocalSubprocessRunner``
reference implementation for development. The local runner is intentionally
conservative: it never runs unless the safety pipeline has already cleared the
action, honours the kill switch via a revocation hook, and enforces a timeout.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


def _as_text(value: object) -> str:
    """Coerce subprocess output to str (it may be bytes on a timeout)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    artifacts: dict[str, str] = field(default_factory=dict)


class SandboxError(RuntimeError):
    pass


class SandboxRunner(ABC):
    """Runs a fully-formed command in an isolated environment."""

    @abstractmethod
    def run(
        self,
        command: list[str],
        *,
        image: str,
        timeout: float = 300.0,
        env: Optional[dict[str, str]] = None,
    ) -> CommandResult:
        ...

    def revoke(self) -> None:  # called by the kill switch
        """Revoke tokens / kill in-flight runs. Default: no-op."""


class LocalSubprocessRunner(SandboxRunner):
    """Development runner: executes the tool as a local subprocess.

    NOTE: this is *not* egress-pinned. It is safe to use only because the
    safety pipeline has already enforced scope, window, class, rate and kill
    checks before ``run`` is ever called. In production this class is replaced
    by a gVisor/Firecracker-backed runner (``sandbox.runtime`` in settings).
    """

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self._revoked = False

    def revoke(self) -> None:
        self._revoked = True

    def run(
        self,
        command: list[str],
        *,
        image: str,
        timeout: float = 300.0,
        env: Optional[dict[str, str]] = None,
    ) -> CommandResult:
        if self._revoked:
            raise SandboxError("sandbox runner revoked (kill switch)")
        if not command:
            raise SandboxError("empty command")
        if self.dry_run:
            return CommandResult(
                exit_code=0,
                stdout="",
                stderr="[dry-run] command not executed",
            )
        if shutil.which(command[0]) is None:
            raise SandboxError(
                f"tool binary not found on PATH: {command[0]!r} "
                "(install it or run with --dry-run)"
            )
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            # On timeout the partial output can come back as bytes even with
            # text=True, so normalise to str — downstream (evidence hashing,
            # parsing) assumes text.
            return CommandResult(
                exit_code=124,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr) + "\n[timeout]",
                timed_out=True,
            )
        return CommandResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
