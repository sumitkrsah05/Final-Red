"""Cross-cutting safety layer.

Every tool invocation passes through the pipeline in ``pipeline.py``:
scope guard → safety class / approval → rate limiter → kill switch → run → audit.
All checks are fail-closed.
"""

from safeguard.safety.exceptions import (
    ApprovalRequired,
    BudgetExceeded,
    ForbiddenFlag,
    KillSwitchEngaged,
    OutOfScope,
    OutOfWindow,
    RateLimited,
    SafetyViolation,
)
from safeguard.safety.audit import AuditLog, AuditEvent
from safeguard.safety.killswitch import KillSwitch
from safeguard.safety.rate_limiter import RateLimiter
from safeguard.safety.scope_guard import ScopeGuard, Target
from safeguard.safety.approvals import ApprovalStore, ApprovalRequest, ApprovalDecision
from safeguard.safety.pipeline import SafetyPipeline, ActionRequest, ActionOutcome

__all__ = [
    "ApprovalRequired",
    "BudgetExceeded",
    "ForbiddenFlag",
    "KillSwitchEngaged",
    "OutOfScope",
    "OutOfWindow",
    "RateLimited",
    "SafetyViolation",
    "AuditLog",
    "AuditEvent",
    "KillSwitch",
    "RateLimiter",
    "ScopeGuard",
    "Target",
    "ApprovalStore",
    "ApprovalRequest",
    "ApprovalDecision",
    "SafetyPipeline",
    "ActionRequest",
    "ActionOutcome",
]
