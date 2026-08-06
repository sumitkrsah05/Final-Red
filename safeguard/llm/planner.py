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
        "validation agent operating against an explicitly in-scope target. "
        "You drive the engagement one step at a time through this loop: "
        "recon (discover hosts/services) -> scan (find vulnerabilities) -> "
        "correlate (enrich findings with CVE/ATT&CK/risk) -> validate "
        "(optionally confirm ONE high/critical finding non-destructively, "
        "approval-gated) -> report. "
        "Rules: (1) do recon before scan, and scan before correlate; "
        "(2) only propose 'validate' after findings exist, choosing an "
        "active-validate tool (e.g. dalfox) and a 'target' copied verbatim "
        "from one of the listed findings' 'asset' value; "
        "(3) only propose 'report' once scanning and correlation are done, or "
        "when there is nothing useful left to do; "
        "(4) you may only propose tools from allowed_tools; "
        "(5) you never execute anything — you only propose. "
        "Respond with a JSON object: "
        '{"action": "recon|scan|correlate|validate|report", "tool": str|null, '
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
        decision = self._validate(data, state, roe)
        # Anti-loop guard: recon/scan/correlate are one-shot pipeline stages. If
        # the model re-proposes a stage that already ran (common when a stage
        # yields nothing, e.g. dry-run recon finds 0 assets), advance the
        # pipeline via the deterministic fallback instead of repeating forever.
        if decision.action in {"recon", "scan", "correlate"} and _already_did(
                state, decision.action):
            return self.fallback.decide(state, roe)
        # Anti-premature-report guard: a live black/gray-box surface must be
        # reconned and scanned before a report is meaningful. If the model
        # *deliberately* jumps straight to 'report' with the pipeline unfinished,
        # defer to the deterministic policy so the engagement still does real
        # work. Only applies when the model actually chose 'report' — not when an
        # invalid proposal was downgraded to 'report' by _validate above.
        if data.get("action") == "report" and decision.action == "report":
            unfinished_recon = (
                roe.mode.value in ("black_box", "gray_box")
                and not _already_did(state, "recon"))
            unfinished_scan = not _already_did(state, "scan")
            if unfinished_recon or unfinished_scan:
                return self.fallback.decide(state, roe)
        return decision

    def _messages(self, state: AgentState, roe: RulesOfEngagement) -> list[dict]:
        # Ground the decision in what was actually discovered: real asset
        # addresses and the highest-severity findings (with the exact 'asset'
        # string the model must copy into a validate 'target').
        assets = [
            (f"{a.address}:{a.port}" if a.port else a.address)
            for a in state.inventory.assets()
        ][:20]
        top_findings = [
            {"title": f.title, "severity": f.severity.value, "asset": f.asset_ref}
            for f in sorted(
                state.ledger.findings(),
                key=lambda f: (f.severity not in _HIGH, f.title),
            )
        ][:15]
        summary = {
            "target_scope": list(roe.scope.domains) + list(roe.scope.cidrs),
            "mode": roe.mode.value,
            "phase": state.phase,
            "assets_count": len(state.inventory),
            "assets": assets,
            "findings_count": len(state.ledger),
            "severity_counts": state.ledger.by_severity(),
            "top_findings": top_findings,
            "allowed_tools": self.registry.runnable(),
            "profile": roe.profile,
            "history": [h.get("action") for h in state.plan_history],
            "actions_spent": state.actions_spent,
            "max_actions": state.max_actions,
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
