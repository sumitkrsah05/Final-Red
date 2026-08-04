"""Engagement assembly — wires the ROE, tool registry, safety layer, and runner
into a ready-to-use :class:`SafetyPipeline`. This is the seam the Phase 4
LangGraph orchestrator will drive; for Phase 1 the CLI drives it directly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

from safeguard.config.loader import load_roe, load_settings
from safeguard.config.models import RulesOfEngagement, Settings
from safeguard.evidence import EvidenceStore
from safeguard.safety.approvals import ApprovalStore
from safeguard.safety.profile import ProfileGuard
from safeguard.safety.audit import AuditLog
from safeguard.safety.killswitch import KillSwitch
from safeguard.safety.pipeline import SafetyPipeline
from safeguard.safety.rate_limiter import RateLimiter
from safeguard.safety.scope_guard import ScopeGuard
from safeguard.tools.registry import ToolRegistry
from safeguard.tools.runner import LocalSubprocessRunner, SandboxRunner


@dataclass
class Engagement:
    roe: RulesOfEngagement
    settings: Settings
    registry: ToolRegistry
    pipeline: SafetyPipeline
    kill_switch: KillSwitch
    approvals: ApprovalStore
    audit: AuditLog

    @classmethod
    def build(
        cls,
        *,
        roe_path: str,
        tools_path: str,
        settings_path: str,
        runs_dir: str = "runs",
        dry_run: bool = False,
        runner: Optional[SandboxRunner] = None,
    ) -> "Engagement":
        roe = load_roe(roe_path)
        settings = load_settings(settings_path)
        registry = ToolRegistry.from_yaml(tools_path)

        run_path = Path(runs_dir) / roe.engagement_id
        audit = AuditLog(roe.engagement_id, path=run_path / "audit.log.jsonl")

        tz = ZoneInfo(roe.timezone)
        approvals = ApprovalStore()
        kill = KillSwitch()
        runner = runner or LocalSubprocessRunner(dry_run=dry_run)
        evidence = EvidenceStore(run_path / "evidence")

        pipeline = SafetyPipeline(
            roe=roe,
            scope_guard=ScopeGuard(roe),
            rate_limiter=RateLimiter(roe.budget),
            kill_switch=kill,
            audit=audit,
            runner=runner,
            approvals=approvals,
            profile_guard=ProfileGuard(roe.profile),
            evidence=evidence,
            now_fn=lambda: datetime.now(tz),
            monotonic_fn=time.monotonic,
        )
        return cls(
            roe=roe,
            settings=settings,
            registry=registry,
            pipeline=pipeline,
            kill_switch=kill,
            approvals=approvals,
            audit=audit,
        )
