"""Validation sub-flow.

Runs a single approved active-validate tool through the safety pipeline. The
approval is enforced by the pipeline (``active-validate`` requires an approved
``approval_id``); this flow simply constructs the invocation and normalises the
outcome. It never runs anything the pipeline would not.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from safeguard.safety.pipeline import ActionRequest, SafetyPipeline
from safeguard.safety.scope_guard import Target
from safeguard.tools.adapter import ToolInvocation
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.schema import ToolResult, Validation


@dataclass
class ValidateOutcome:
    allowed: bool
    tool: str
    target: str
    validations: list[Validation]
    denial: Optional[str] = None
    result: Optional[ToolResult] = None


class ValidateFlow:
    def __init__(self, pipeline: SafetyPipeline, registry: ToolRegistry) -> None:
        self.pipeline = pipeline
        self.registry = registry

    def run(
        self,
        *,
        tool: str,
        target: str,
        approval_id: Optional[str],
        technique: Optional[str] = None,
        rationale: str = "",
    ) -> ValidateOutcome:
        adapter = self.registry.adapter(tool)
        if adapter is None:
            return ValidateOutcome(allowed=False, tool=tool, target=target,
                                   validations=[], denial="no adapter for tool")
        inv = ToolInvocation(tool=tool, target=target, approval_id=approval_id,
                             technique=technique, rationale=rationale)
        outcome = self.pipeline.execute(
            adapter, ActionRequest(invocation=inv, target=Target(raw=target)))
        res = outcome.result
        return ValidateOutcome(
            allowed=outcome.allowed, tool=tool, target=target,
            validations=res.validations if res else [],
            denial=outcome.denial, result=res)
