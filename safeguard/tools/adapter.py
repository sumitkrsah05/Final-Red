"""The ToolAdapter interface.

Every tool implements the same contract:

    build_command(invocation) -> list[str]
    validate(command)         -> None          # raises on forbidden flags etc.
    parse(command_result)     -> ToolResult

`run()` itself is NOT a method the adapter controls — execution is owned by the
safety pipeline, which calls the adapter's build/validate, runs the command in
the sandbox only after every gate passes, then calls parse. This enforces the
"LLM proposes, code disposes" rule at the type level: an adapter cannot execute
anything on its own.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from safeguard.config.models import SafetyClass, ToolSpec
from safeguard.safety.exceptions import ForbiddenFlag
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import ToolResult, ToolStatus


@dataclass
class ToolInvocation:
    """A proposed, not-yet-executed tool run against one target."""

    tool: str
    target: str
    params: dict = field(default_factory=dict)
    extra_flags: tuple[str, ...] = ()
    # For active-validate steps: the approval request that must be granted.
    approval_id: Optional[str] = None
    technique: Optional[str] = None
    rationale: str = ""


class ToolAdapter(ABC):
    """Base class for all tool adapters."""

    #: default sandbox image if the ToolSpec doesn't override
    default_image: str = "recon-runner"

    def __init__(self, spec: ToolSpec) -> None:
        self.spec = spec

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def safety_class(self) -> SafetyClass:
        return self.spec.safety_class

    @property
    def image(self) -> str:
        return self.spec.sandbox if self.spec.sandbox != "none" else self.default_image

    @abstractmethod
    def build_command(self, invocation: ToolInvocation) -> list[str]:
        """Turn a validated invocation into an argv list. No shell strings."""

    def validate(self, command: list[str]) -> None:
        """Reject forbidden flags declared for this tool. Fail-closed.

        Adapters may override to add tool-specific checks, but should call
        ``super().validate(command)`` to keep the forbidden-flag guard."""
        forbidden = set(self.spec.forbidden_flags)
        for token in command:
            # match exact flag or `--flag=value` form
            head = token.split("=", 1)[0]
            if token in forbidden or head in forbidden:
                raise ForbiddenFlag(
                    f"{self.name}: flag {token!r} is forbidden for its safety class"
                )

    @abstractmethod
    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        """Normalise raw tool output into a ToolResult."""

    # Convenience for adapters that produced nothing.
    def _empty_result(
        self, invocation: ToolInvocation, command: list[str], result: CommandResult
    ) -> ToolResult:
        status = ToolStatus.OK if result.exit_code == 0 else ToolStatus.ERROR
        return ToolResult(
            tool=self.name,
            status=ToolStatus.NO_RESULTS if status is ToolStatus.OK else status,
            target=invocation.target,
            command=command,
            exit_code=result.exit_code,
            error=result.stderr.strip() or None if status is ToolStatus.ERROR else None,
        )
