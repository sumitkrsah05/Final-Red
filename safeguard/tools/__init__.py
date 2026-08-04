"""Phase 1 — Tool Adapter Framework.

A uniform, sandboxed way to run any external security tool and normalise its
heterogeneous output into a single ``Finding`` / ``ToolResult`` schema. Every
adapter runs *only* through the safety pipeline.
"""

from safeguard.tools.schema import (
    Asset,
    AssetType,
    Finding,
    Severity,
    ToolResult,
    ToolStatus,
    Validation,
    ValidationResult,
)
from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import (
    CommandResult,
    LocalSubprocessRunner,
    SandboxRunner,
)
from safeguard.tools.registry import ToolRegistry

__all__ = [
    "Asset",
    "AssetType",
    "Finding",
    "Severity",
    "ToolResult",
    "ToolStatus",
    "Validation",
    "ValidationResult",
    "ToolAdapter",
    "ToolInvocation",
    "CommandResult",
    "LocalSubprocessRunner",
    "SandboxRunner",
    "ToolRegistry",
]
