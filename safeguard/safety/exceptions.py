"""Safety exceptions. Every one of these denies an action, fail-closed."""

from __future__ import annotations


class SafetyViolation(Exception):
    """Base class for any safety-layer denial."""


class OutOfScope(SafetyViolation):
    """Target is not in the ROE allowlist, or is explicitly excluded."""


class OutOfWindow(SafetyViolation):
    """Current time is outside the permitted engagement window."""


class ApprovalRequired(SafetyViolation):
    """An active-validate step needs a named approver's sign-off first."""


class RateLimited(SafetyViolation):
    """Per-target rate or concurrency ceiling would be exceeded."""


class BudgetExceeded(SafetyViolation):
    """Global engagement action budget is exhausted."""


class KillSwitchEngaged(SafetyViolation):
    """The kill switch is engaged; no new actions may start."""


class ForbiddenFlag(SafetyViolation):
    """A tool invocation contained a flag banned for its safety class."""


class ProfileViolation(SafetyViolation):
    """A command contained a destructive token forbidden by the active profile."""
