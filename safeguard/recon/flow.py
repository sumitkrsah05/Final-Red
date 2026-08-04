"""Recon sub-flow.

Sequences the recon adapters over the in-scope targets, each call passing
through the safety pipeline (scope → window → class → rate → run → audit). The
flow is deliberately a plain, deterministic sequence in Phase 2 — the LLM
planner (Phase 4) will later choose the order; here we run a fixed recon plan so
the pipeline and asset consolidation can be exercised end-to-end.

Results are merged into a single ``AssetInventory``. Denied or errored steps are
recorded, never fatal — the flow continues within the ROE budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from safeguard.recon.assets import AssetInventory
from safeguard.safety.pipeline import ActionRequest, SafetyPipeline
from safeguard.safety.scope_guard import Target
from safeguard.tools.adapter import ToolInvocation
from safeguard.tools.registry import ToolRegistry

# Default black-box recon plan: order matters (discover hosts, then probe web).
DEFAULT_PLAN = ["nmap", "httpx", "whatweb"]


@dataclass
class ReconStep:
    tool: str
    target: str
    allowed: bool
    status: str
    assets: int
    denial: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ReconReport:
    steps: list[ReconStep] = field(default_factory=list)
    inventory: AssetInventory = field(default_factory=AssetInventory)

    @property
    def allowed_steps(self) -> int:
        return sum(1 for s in self.steps if s.allowed)

    @property
    def denied_steps(self) -> int:
        return sum(1 for s in self.steps if not s.allowed)


class ReconFlow:
    def __init__(self, pipeline: SafetyPipeline, registry: ToolRegistry) -> None:
        self.pipeline = pipeline
        self.registry = registry

    def run(
        self,
        targets: list[str],
        *,
        plan: Optional[list[str]] = None,
        params: Optional[dict[str, dict]] = None,
    ) -> ReconReport:
        plan = plan or DEFAULT_PLAN
        params = params or {}
        report = ReconReport()

        for tool in plan:
            adapter = self.registry.adapter(tool)
            if adapter is None:
                report.steps.append(ReconStep(
                    tool=tool, target="-", allowed=False, status="unavailable",
                    assets=0, denial="no adapter registered"))
                continue
            for raw in targets:
                inv = ToolInvocation(tool=tool, target=raw,
                                     params=params.get(tool, {}))
                outcome = self.pipeline.execute(
                    adapter, ActionRequest(invocation=inv, target=Target(raw=raw)))
                res = outcome.result
                if outcome.allowed and res is not None:
                    report.inventory.add_all(res.assets)
                report.steps.append(ReconStep(
                    tool=tool,
                    target=raw,
                    allowed=outcome.allowed,
                    status=res.status.value if res else "denied",
                    assets=len(res.assets) if res else 0,
                    denial=outcome.denial,
                    error=res.error if res else None,
                ))
        return report
