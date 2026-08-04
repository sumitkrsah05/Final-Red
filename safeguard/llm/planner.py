"""Planner — decides the next phase. The planner *proposes*; the graph disposes.

Two implementations:
  * ``RulePlanner`` — deterministic, no LLM. The default for offline/dev runs and
    tests: recon → scan → (optional gated validate) → report.
  * ``LLMPlanner`` — asks the sovereign Qwen model for a structured JSON decision,
    then **validates it in code** against the tool registry and safety classes.
    An LLM proposal for an unknown/destructive tool is rejected and downgraded to
    ``report`` — the model can never widen its own authority.

Neither planner executes anything; both only return a ``PlanDecision``.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Optional

from safeguard.config.models import RulesOfEngagement, SafetyClass
from safeguard.graph.state import AgentState, PlanDecision
from safeguard.llm.client import LLMClient, LLMError
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.schema import Severity

_HIGH = {Severity.HIGH, Severity.CRITICAL}


class Planner(ABC):
    @abstractmethod
    def decide(self, state: AgentState, roe: RulesOfEngagement) -> PlanDecision:
        ...


def _already_did(state: AgentState, action: str) -> bool:
    return any(h.get("action") == action for h in state.plan_history)


class RulePlanner(Planner):
    """Deterministic recon → scan → gated-validate → report policy."""

    def __init__(self, registry: Optional[ToolRegistry] = None,
                 propose_validation: bool = True) -> None:
        self.registry = registry
        self.propose_validation = propose_validation

    def decide(self, state: AgentState, roe: RulesOfEngagement) -> PlanDecision:
        if state.actions_spent >= state.max_actions:
            return PlanDecision(action="report", rationale="action budget reached")
        mode = roe.mode.value
        # Network recon only makes sense for black/gray-box; white-box works on
        # provided source, not a live surface.
        if (mode in ("black_box", "gray_box")
                and len(state.inventory) == 0 and not _already_did(state, "recon")):
            return PlanDecision(action="recon",
                                rationale="no assets discovered yet")
        if len(state.ledger) == 0 and not _already_did(state, "scan"):
            return PlanDecision(action="scan",
                                rationale="assets known, no findings yet")
        if len(state.ledger) > 0 and not _already_did(state, "correlate"):
            return PlanDecision(action="correlate",
                                rationale="enrich findings (CVE/ATT&CK/risk) and "
                                          "correlate attack paths")
        # Propose one gated validation for a high/critical finding. Active web
        # validation (Dalfox/SQLMap) applies to black/gray-box, not white-box source.
        if (self.propose_validation and mode != "white_box"
                and not _already_did(state, "validate")
                and roe.profile == "non_destructive"):
            hot = [f for f in state.ledger.findings() if f.severity in _HIGH]
            if hot:
                f = hot[0]
                return PlanDecision(
                    action="validate", tool="dalfox", target=f.asset_ref,
                    technique="reflected-xss-confirmation",
                    rationale=f"confirm signal of '{f.title}' non-destructively",
                    requires_approval=True)
        return PlanDecision(action="report", rationale="engagement complete")


class LLMPlanner(Planner):
    """LLM-driven planner with in-code validation of every proposal."""

    SYSTEM = (
        "You are the planner for an authorised, non-destructive red-team "
        "validation agent. Choose the single next action. You may only propose "
        "tools from the allowed list. You never execute anything; you only "
        "propose. Respond with a JSON object: "
        '{"action": "recon|scan|validate|report", "tool": str|null, '
        '"target": str|null, "technique": str|null, "rationale": str, '
        '"requires_approval": bool}.'
    )

    def __init__(self, client: LLMClient, registry: ToolRegistry,
                 fallback: Optional[Planner] = None) -> None:
        self.client = client
        self.registry = registry
        self.fallback = fallback or RulePlanner(registry)

    def decide(self, state: AgentState, roe: RulesOfEngagement) -> PlanDecision:
        try:
            raw = self.client.chat(self._messages(state, roe), node="planner",
                                   response_json=True)
            data = json.loads(raw)
        except (LLMError, json.JSONDecodeError):
            return self.fallback.decide(state, roe)
        return self._validate(data, state, roe)

    def _messages(self, state: AgentState, roe: RulesOfEngagement) -> list[dict]:
        summary = {
            "phase": state.phase,
            "assets": len(state.inventory),
            "findings": len(state.ledger),
            "severity_counts": state.ledger.by_severity(),
            "allowed_tools": self.registry.runnable(),
            "profile": roe.profile,
            "history": [h.get("action") for h in state.plan_history],
        }
        return [
            {"role": "system", "content": self.SYSTEM},
            {"role": "user", "content": json.dumps(summary)},
        ]

    def _validate(self, data: dict, state: AgentState,
                  roe: RulesOfEngagement) -> PlanDecision:
        action = str(data.get("action", "report"))
        if action not in {"recon", "scan", "correlate", "validate", "report"}:
            return PlanDecision(action="report",
                                rationale="planner returned unknown action")
        tool = data.get("tool")
        requires_approval = bool(data.get("requires_approval"))
        if action == "validate":
            # Deterministic guard: tool must be registered and active-validate.
            spec = self.registry.spec(tool) if tool else None
            if spec is None or spec.safety_class is not SafetyClass.ACTIVE_VALIDATE:
                return PlanDecision(
                    action="report",
                    rationale=f"rejected invalid validate proposal for tool={tool!r}")
            requires_approval = True
        return PlanDecision(
            action=action, tool=tool, target=data.get("target"),
            technique=data.get("technique"),
            rationale=str(data.get("rationale", "")),
            requires_approval=requires_approval)
