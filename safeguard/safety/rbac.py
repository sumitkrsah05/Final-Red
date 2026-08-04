"""RBAC for the control plane.

Control-plane actions (start / approve / kill / query) are role-gated and every
attempt is auditable. Roles are least-privilege: an approver may sign off but not
start engagements; a viewer may only query. Approval additionally requires the
operator be a *named ROE approver* (checked separately by the pipeline).
"""

from __future__ import annotations

from enum import Enum

from safeguard.safety.exceptions import SafetyViolation


class Role(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    APPROVER = "approver"
    VIEWER = "viewer"


class Action(str, Enum):
    START = "start"
    APPROVE = "approve"
    KILL = "kill"
    QUERY = "query"


_ALLOWED: dict[Role, set[Action]] = {
    Role.ADMIN: {Action.START, Action.APPROVE, Action.KILL, Action.QUERY},
    Role.OPERATOR: {Action.START, Action.KILL, Action.QUERY},
    Role.APPROVER: {Action.APPROVE, Action.QUERY},
    Role.VIEWER: {Action.QUERY},
}


class AccessDenied(SafetyViolation):
    """The operator's role does not permit the control-plane action."""


class RBAC:
    def __init__(self, assignments: dict[str, Role]) -> None:
        self._assignments = assignments

    def role_of(self, operator: str) -> Role:
        if operator not in self._assignments:
            raise AccessDenied(f"unknown operator {operator!r}")
        return self._assignments[operator]

    def can(self, operator: str, action: Action) -> bool:
        try:
            return action in _ALLOWED[self.role_of(operator)]
        except AccessDenied:
            return False

    def require(self, operator: str, action: Action) -> None:
        if not self.can(operator, action):
            raise AccessDenied(
                f"{operator!r} may not perform {action.value!r}")
