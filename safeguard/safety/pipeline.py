"""The safety pipeline — every tool call passes through here, in order:

    scope guard → time window → safety class / approval → forbidden-flag validate
    → rate limiter → kill switch → sandbox run → parse → audit

Any gate failure raises a ``SafetyViolation`` subclass, is audited, and no tool
runs. This is the single choke point that makes "LLM proposes, code disposes"
true: an adapter is only ever executed from ``execute()`` below, after all gates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Callable, Optional

from safeguard.config.models import RulesOfEngagement, SafetyClass
from safeguard.safety.approvals import ApprovalStore
from safeguard.safety.audit import AuditLog
from safeguard.safety.exceptions import (
    ApprovalRequired,
    KillSwitchEngaged,
    SafetyViolation,
)
from safeguard.safety.killswitch import KillSwitch
from safeguard.safety.rate_limiter import RateLimiter
from safeguard.safety.scope_guard import ScopeGuard, Target
from safeguard.tools.schema import ToolResult, ToolStatus

if TYPE_CHECKING:  # avoids a tools <-> safety import cycle at module load
    from safeguard.tools.adapter import ToolAdapter, ToolInvocation
    from safeguard.tools.runner import SandboxRunner


@dataclass
class ActionRequest:
    invocation: ToolInvocation
    target: Target
    actor: str = "agent"


@dataclass
class ActionOutcome:
    result: Optional[ToolResult]
    allowed: bool
    denial: Optional[str] = None
    audit_head: str = ""


# Clock injection keeps the pipeline deterministic and testable.
NowFn = Callable[[], datetime]
MonotonicFn = Callable[[], float]


class SafetyPipeline:
    def __init__(
        self,
        *,
        roe: RulesOfEngagement,
        scope_guard: ScopeGuard,
        rate_limiter: RateLimiter,
        kill_switch: KillSwitch,
        audit: AuditLog,
        runner: SandboxRunner,
        approvals: Optional[ApprovalStore] = None,
        profile_guard: Optional["ProfileGuard"] = None,
        evidence: Optional["EvidenceStore"] = None,
        now_fn: NowFn,
        monotonic_fn: MonotonicFn,
        run_timeout: float = 300.0,
    ) -> None:
        from safeguard.safety.profile import ProfileGuard

        self.roe = roe
        self.scope = scope_guard
        self.rate = rate_limiter
        self.kill = kill_switch
        self.audit = audit
        self.runner = runner
        self.approvals = approvals or ApprovalStore()
        self.profile = profile_guard or ProfileGuard(roe.profile)
        self.evidence = evidence
        self._now = now_fn
        self._monotonic = monotonic_fn
        self.run_timeout = run_timeout
        # Wire the kill switch to revoke the runner.
        self.kill.register_revocation_hook(runner.revoke)

    def _approver(self, approval_id: Optional[str]) -> Optional[str]:
        if not approval_id:
            return None
        req = self.approvals.get(approval_id)
        return req.approver if req else None

    def _audit(self, actor: str, action: str, **detail) -> str:
        ev = self.audit.append(
            actor=actor,
            action=action,
            ts=self._now().isoformat(),
            params=detail.get("params"),
            detail={k: v for k, v in detail.items() if k != "params"},
        )
        return ev.hash

    def execute(self, adapter: ToolAdapter, req: ActionRequest) -> ActionOutcome:
        """Run one adapter invocation through every gate. Never raises for a
        policy denial — denials are returned as ``ActionOutcome(allowed=False)``
        and audited. Unexpected errors still propagate."""
        inv = req.invocation
        self._audit(
            req.actor,
            "tool.proposed",
            tool=adapter.name,
            target=inv.target,
            safety_class=adapter.safety_class.value,
            params=inv.params,
        )
        try:
            # 1. Kill switch (checked first — a hard stop dominates everything).
            if self.kill.engaged:
                raise KillSwitchEngaged("kill switch engaged")

            # 2. Scope guard: target allowlist + exclusions.
            self.scope.check_target(req.target)

            # 3. Time window.
            self.scope.check_window(self._now())

            # 4. Safety class / approval gate.
            if adapter.safety_class.requires_approval:
                if not self.approvals.is_approved(inv.approval_id):
                    raise ApprovalRequired(
                        f"{adapter.name} is active-validate; a named approver "
                        "must sign off before execution"
                    )

            # 5. Build + validate command (forbidden-flag guard).
            command = adapter.build_command(inv)
            adapter.validate(command)

            # 5b. Non-destructive profile guard (global destructive-token deny).
            self.profile.check(command)

            # 6. Rate / blast-radius limiter.
            self.rate.acquire(inv.target, self._monotonic())
        except SafetyViolation as sv:
            head = self._audit(
                "system",
                "tool.denied",
                tool=adapter.name,
                target=inv.target,
                reason=type(sv).__name__,
                message=str(sv),
            )
            return ActionOutcome(result=None, allowed=False, denial=str(sv), audit_head=head)

        # 7. Execute in the sandbox (only reached after every gate passed).
        started = self._monotonic()
        try:
            self._audit(
                req.actor, "tool.exec", tool=adapter.name, command=command
            )
            cmd_result = self.runner.run(
                command, image=adapter.image, timeout=self.run_timeout
            )
            result = adapter.parse(inv, cmd_result)
            result.command = command
            result.duration_seconds = self._monotonic() - started
            # Capture raw output as content-addressed evidence.
            if self.evidence is not None and cmd_result.stdout:
                ref = self.evidence.put(cmd_result.stdout)
                result.raw_output_ref = ref
                for v in result.validations:
                    v.evidence_ref = v.evidence_ref or ref
                    v.approved_by = v.approved_by or self._approver(inv.approval_id)
        except Exception as exc:  # sandbox / parse failure
            self.rate.release(inv.target)
            head = self._audit(
                "system",
                "tool.error",
                tool=adapter.name,
                target=inv.target,
                error=str(exc),
            )
            err = ToolResult(
                tool=adapter.name,
                status=ToolStatus.ERROR,
                target=inv.target,
                command=command,
                error=str(exc),
            )
            return ActionOutcome(result=err, allowed=True, denial=None, audit_head=head)
        finally:
            self.rate.release(inv.target)

        head = self._audit(
            req.actor,
            "tool.result",
            tool=adapter.name,
            target=inv.target,
            status=result.status.value,
            assets=len(result.assets),
            findings=len(result.findings),
            validations=len(result.validations),
            evidence_ref=result.raw_output_ref,
            invocation_id=result.invocation_id,
        )
        return ActionOutcome(result=result, allowed=True, denial=None, audit_head=head)
