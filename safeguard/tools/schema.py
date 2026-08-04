"""Unified data schema across all tools.

Heterogeneous tool output (Nmap XML, Nuclei JSONL, Trivy JSON, …) is normalised
into these types so the rest of the system sees one shape. Aligned with the data
model in ``docs/ARCHITECTURE.md`` §5.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "Severity":
        if not value:
            return cls.INFO
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.INFO


class AssetType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    REPO = "repo"
    CLOUD_ACCOUNT = "cloud-account"


class ToolStatus(str, Enum):
    OK = "ok"
    NO_RESULTS = "no-results"
    ERROR = "error"
    BLOCKED = "blocked"  # denied by the safety layer


@dataclass
class Asset:
    address: str
    asset_type: AssetType
    id: str = ""
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    tech: dict[str, Any] = field(default_factory=dict)
    in_scope: bool = True

    def __post_init__(self) -> None:
        if not self.id:
            key = f"{self.asset_type.value}:{self.address}:{self.port}:{self.protocol}"
            self.id = "asset-" + hashlib.sha1(key.encode()).hexdigest()[:12]

    def merge_key(self) -> tuple:
        return (self.asset_type.value, self.address, self.port, self.protocol)


@dataclass
class Finding:
    title: str
    asset_ref: str
    source_tool: str
    severity: Severity = Severity.INFO
    id: str = ""
    description: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    epss: Optional[float] = None
    attack_techniques: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    status: str = "open"
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            key = f"{self.source_tool}:{self.asset_ref}:{self.title}"
            self.id = "find-" + hashlib.sha1(key.encode()).hexdigest()[:12]

    def dedup_key(self) -> tuple:
        return (self.asset_ref, self.title.strip().lower())


class ValidationResult(str, Enum):
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Validation:
    """A non-destructive proof-of-signal outcome (active-validate class)."""

    target: str
    method: str  # e.g. "reflected-xss", "sqli-boolean"
    result: ValidationResult
    tool: str
    finding_ref: Optional[str] = None
    approved_by: Optional[str] = None
    evidence_ref: Optional[str] = None
    non_destructive: bool = True  # always true; enforced in code
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """Normalised output of one adapter run."""

    tool: str
    status: ToolStatus
    target: str
    invocation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    command: list[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    validations: list[Validation] = field(default_factory=list)
    raw_output_ref: Optional[str] = None  # evidence-store pointer
    error: Optional[str] = None
    duration_seconds: Optional[float] = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is ToolStatus.OK
