"""Phase 5 — Safe Validation (gated, active).

Non-destructive proof-of-signal: Dalfox (reflected-XSS confirmation) and SQLMap
(detection-only). Every validation runs through the safety pipeline, so it only
executes after named-approver sign-off and under the non-destructive profile
guard, with evidence captured.
"""

from safeguard.validate.flow import ValidateFlow, ValidateOutcome

__all__ = ["ValidateFlow", "ValidateOutcome"]
