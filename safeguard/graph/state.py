"""AgentState — the typed, checkpointable state the graph carries.

Accumulators (``inventory``, ``ledger``) use append/merge semantics (the
reducer role from the design): nodes add to them, never overwrite. The state
serialises to a plain dict so any checkpointer (SQLite/JSON) can persist it and
the run can be resumed or replayed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from safeguard.recon.assets import AssetInventory
from safeguard.scan.findings import FindingLedger
from safeguard.tools.schema import Asset, AssetType, Finding, Severity


@dataclass
class PlanDecision:
    """A planner proposal. The planner *proposes*; the graph *disposes*."""

    action: str  # "recon" | "scan" | "validate" | "report" | "done"
    tool: Optional[str] = None
    target: Optional[str] = None
    technique: Optional[str] = None
    rationale: str = ""
    requires_approval: bool = False
    params: dict = field(default_factory=dict)


@dataclass
class AgentState:
    engagement_id: str
    mode: str
    profile: str
    targets: list[str]

    phase: str = "intake"
    actions_spent: int = 0
    max_actions: int = 500

    inventory: AssetInventory = field(default_factory=AssetInventory)
    ledger: FindingLedger = field(default_factory=FindingLedger)

    plan_history: list[dict] = field(default_factory=list)
    last_decision: Optional[PlanDecision] = None
    pending_approval: Optional[dict] = None
    validations: list[dict] = field(default_factory=list)
    attack_paths: list[dict] = field(default_factory=list)
    grounded_tokens: list[str] = field(default_factory=list)
    detections: list[dict] = field(default_factory=list)
    detection_status: dict[str, str] = field(default_factory=dict)

    audit_ref: str = ""
    done: bool = False
    report: Optional[dict] = None

    # -- serialization (checkpoint) --------------------------------------
    def to_checkpoint(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "mode": self.mode,
            "profile": self.profile,
            "targets": list(self.targets),
            "phase": self.phase,
            "actions_spent": self.actions_spent,
            "max_actions": self.max_actions,
            "assets": [_asset_to_dict(a) for a in self.inventory.assets()],
            "findings": [_finding_to_dict(f) for f in self.ledger.findings()],
            "plan_history": self.plan_history,
            "pending_approval": self.pending_approval,
            "validations": self.validations,
            "attack_paths": self.attack_paths,
            "grounded_tokens": self.grounded_tokens,
            "detections": self.detections,
            "detection_status": self.detection_status,
            "audit_ref": self.audit_ref,
            "done": self.done,
            "report": self.report,
        }

    @classmethod
    def from_checkpoint(cls, data: dict) -> "AgentState":
        st = cls(
            engagement_id=data["engagement_id"],
            mode=data["mode"],
            profile=data["profile"],
            targets=list(data.get("targets", [])),
            phase=data.get("phase", "intake"),
            actions_spent=data.get("actions_spent", 0),
            max_actions=data.get("max_actions", 500),
        )
        for a in data.get("assets", []):
            st.inventory.add(_asset_from_dict(a))
        for f in data.get("findings", []):
            st.ledger.add(_finding_from_dict(f))
        st.plan_history = data.get("plan_history", [])
        st.pending_approval = data.get("pending_approval")
        st.validations = data.get("validations", [])
        st.attack_paths = data.get("attack_paths", [])
        st.grounded_tokens = data.get("grounded_tokens", [])
        st.detections = data.get("detections", [])
        st.detection_status = data.get("detection_status", {})
        st.audit_ref = data.get("audit_ref", "")
        st.done = data.get("done", False)
        st.report = data.get("report")
        return st


def _asset_to_dict(a: Asset) -> dict:
    return {"address": a.address, "asset_type": a.asset_type.value, "id": a.id,
            "port": a.port, "protocol": a.protocol, "service": a.service,
            "tech": a.tech, "in_scope": a.in_scope}


def _asset_from_dict(d: dict) -> Asset:
    return Asset(address=d["address"], asset_type=AssetType(d["asset_type"]),
                 id=d.get("id", ""), port=d.get("port"), protocol=d.get("protocol"),
                 service=d.get("service"), tech=d.get("tech", {}),
                 in_scope=d.get("in_scope", True))


def _finding_to_dict(f: Finding) -> dict:
    return {"title": f.title, "asset_ref": f.asset_ref, "source_tool": f.source_tool,
            "severity": f.severity.value, "id": f.id, "description": f.description,
            "cve_ids": f.cve_ids, "cvss": f.cvss, "epss": f.epss,
            "attack_techniques": f.attack_techniques, "evidence_refs": f.evidence_refs,
            "status": f.status, "raw": f.raw}


def _finding_from_dict(d: dict) -> Finding:
    return Finding(title=d["title"], asset_ref=d["asset_ref"],
                   source_tool=d["source_tool"], severity=Severity(d["severity"]),
                   id=d.get("id", ""), description=d.get("description", ""),
                   cve_ids=d.get("cve_ids", []), cvss=d.get("cvss"),
                   epss=d.get("epss"), attack_techniques=d.get("attack_techniques", []),
                   evidence_refs=d.get("evidence_refs", []),
                   status=d.get("status", "open"), raw=d.get("raw", {}))
