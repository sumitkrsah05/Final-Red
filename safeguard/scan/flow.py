"""Scan sub-flow.

Runs the vulnerability-detection tools (Nuclei safe templates, Nikto) over the
scan targets, each call passing through the safety pipeline. Findings from all
tools are merged into a single ``FindingLedger`` (cross-tool dedup). Like the
recon flow this is a deterministic plan in Phase 3; the Phase 4 planner will
later choose targets and tools from recon output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from safeguard.safety.pipeline import ActionRequest, SafetyPipeline
from safeguard.safety.scope_guard import Target
from safeguard.scan.findings import FindingLedger
from safeguard.tools.adapter import ToolInvocation
from safeguard.tools.registry import ToolRegistry

DEFAULT_PLAN = ["nuclei", "nikto"]


@dataclass
class ScanStep:
    tool: str
    target: str
    allowed: bool
    status: str
    findings: int
    denial: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ScanReport:
    steps: list[ScanStep] = field(default_factory=list)
    ledger: FindingLedger = field(default_factory=FindingLedger)

    @property
    def allowed_steps(self) -> int:
        return sum(1 for s in self.steps if s.allowed)

    @property
    def denied_steps(self) -> int:
        return sum(1 for s in self.steps if not s.allowed)


class ScanFlow:
    def __init__(self, pipeline: SafetyPipeline, registry: ToolRegistry) -> None:
        self.pipeline = pipeline
        self.registry = registry

    def run(
        self,
        targets: list[str],
        *,
        plan: Optional[list[str]] = None,
        params: Optional[dict[str, dict]] = None,
    ) -> ScanReport:
        plan = plan or DEFAULT_PLAN
        params = params or {}
        report = ScanReport()

        for tool in plan:
            adapter = self.registry.adapter(tool)
            if adapter is None:
                report.steps.append(ScanStep(
                    tool=tool, target="-", allowed=False, status="unavailable",
                    findings=0, denial="no adapter registered"))
                continue
            for raw in targets:
                inv = ToolInvocation(tool=tool, target=raw,
                                     params=params.get(tool, {}))
                outcome = self.pipeline.execute(
                    adapter, ActionRequest(invocation=inv, target=Target(raw=raw)))
                res = outcome.result
                if outcome.allowed and res is not None:
                    report.ledger.add_all(res.findings)
                report.steps.append(ScanStep(
                    tool=tool,
                    target=raw,
                    allowed=outcome.allowed,
                    status=res.status.value if res else "denied",
                    findings=len(res.findings) if res else 0,
                    denial=outcome.denial,
                    error=res.error if res else None,
                ))
        return report
