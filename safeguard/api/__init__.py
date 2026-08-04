"""Phase 10 — Control plane.

The operator-facing surface: start / approve / kill / audit-query, each RBAC-
gated and audited. This module is the transport-agnostic core; a FastAPI app
(the production control plane) is a thin HTTP wrapper over ``ControlPlane``.
"""

from safeguard.api.control_plane import ControlPlane

__all__ = ["ControlPlane"]
