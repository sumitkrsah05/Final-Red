"""Typed configuration models.

These mirror the YAML contracts in ``config/roe.example.yaml``,
``config/tools.yaml`` and ``config/settings.example.yaml``. Kept as plain
dataclasses (no third-party model lib) so the safety core has a minimal
dependency surface. Validation is explicit and fail-closed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Mode(str, Enum):
    BLACK_BOX = "black_box"
    GRAY_BOX = "gray_box"
    WHITE_BOX = "white_box"


class SafetyClass(str, Enum):
    """Tool safety classes. ``destructive`` is intentionally *not* a member:
    such tools are never loadable, so the enum cannot represent one."""

    PASSIVE = "passive"
    ACTIVE_RECON = "active-recon"
    ACTIVE_VALIDATE = "active-validate"

    @property
    def requires_approval(self) -> bool:
        return self is SafetyClass.ACTIVE_VALIDATE


# The only execution profile enabled by default. Anything else must be an
# explicit, reviewed change — never something LLM output can select.
ALLOWED_PROFILES = frozenset({"non_destructive"})

# Classes that a loaded tool may legally declare. Any other value in tools.yaml
# (notably "destructive") is rejected at load time — fail closed.
_LOADABLE_CLASSES = {c.value for c in SafetyClass}


@dataclass(frozen=True)
class TimeWindow:
    days: tuple[str, ...]
    start: str  # "HH:MM" (24h, ROE timezone)
    end: str

    def __post_init__(self) -> None:
        for label, value in (("start", self.start), ("end", self.end)):
            _parse_hhmm(value, label)


@dataclass(frozen=True)
class Exclusions:
    hosts: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScopeSpec:
    domains: tuple[str, ...] = ()
    cidrs: tuple[str, ...] = ()
    cloud_accounts: tuple[str, ...] = ()
    repos: tuple[str, ...] = ()

    def networks(self) -> list[ipaddress._BaseNetwork]:
        nets: list[ipaddress._BaseNetwork] = []
        for c in self.cidrs:
            nets.append(ipaddress.ip_network(c, strict=False))
        return nets


@dataclass(frozen=True)
class Budget:
    max_requests_per_second_per_target: float = 10.0
    max_concurrency_per_target: int = 4
    max_total_actions: int = 500


@dataclass(frozen=True)
class RulesOfEngagement:
    engagement_id: str
    owner: str
    authorised_by: str
    authorisation_ref: str
    mode: Mode
    profile: str
    scope: ScopeSpec
    exclusions: Exclusions
    timezone: str
    windows: tuple[TimeWindow, ...]
    approvers: tuple[str, ...]
    budget: Budget

    def __post_init__(self) -> None:
        if not self.authorisation_ref:
            raise ValueError("ROE missing authorisation_ref — fail closed")
        if self.profile not in ALLOWED_PROFILES:
            raise ValueError(
                f"profile '{self.profile}' is not enabled; "
                f"allowed: {sorted(ALLOWED_PROFILES)}"
            )
        if not self.approvers:
            raise ValueError("ROE must name at least one approver")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    safety_class: SafetyClass
    sandbox: str = "none"
    default_flags: tuple[str, ...] = ()
    forbidden_flags: tuple[str, ...] = ()
    backend: Optional[str] = None
    template_policy: Optional[str] = None
    mode: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Settings:
    llm_model: str
    llm_base_url: Optional[str]
    llm_api_key_env: str
    correlation_window_seconds: int = 300
    global_kill_switch_enabled: bool = True
    default_max_actions: int = 500
    sandbox_runtime: str = "gvisor"
    sandbox_egress: str = "roe-pinned"
    numeric_verifier_enabled: bool = True
    audit_backend: str = "append_only_hash_chain"
    raw: dict = field(default_factory=dict)


def _parse_hhmm(value: str, label: str) -> tuple[int, int]:
    try:
        h, m = value.split(":")
        hh, mm = int(h), int(m)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{label} must be 'HH:MM', got {value!r}") from exc
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        raise ValueError(f"{label} out of range: {value!r}")
    return hh, mm


def is_loadable_class(value: str) -> bool:
    return value in _LOADABLE_CLASSES
