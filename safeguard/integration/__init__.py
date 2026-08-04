"""Phase 10 — Platform integration.

Closes the purple-team loop: the detection-gap report flows to the **Detect**
loop (new/updated correlation-rule candidates for the missed techniques) and the
**Act** loop (candidate response playbooks; ticket stubs). Handoffs are written
to an outbox (files) in this build; production posts them to the Detect/Act APIs.
"""

from safeguard.integration.detect import DetectIntegration, RuleCandidate
from safeguard.integration.act import ActIntegration, Playbook, Ticket

__all__ = ["DetectIntegration", "RuleCandidate", "ActIntegration", "Playbook",
           "Ticket"]
