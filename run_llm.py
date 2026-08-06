"""Drive a full Safeguard engagement with the *LLM* planner.

The CLI's `engage` command always uses the deterministic RulePlanner; there is
no flag to select the sovereign LLM planner. This driver wires LLMPlanner into
the same Orchestrator the CLI builds, so the Qwen endpoint actually drives the
recon -> scan -> correlate -> (gated validate) -> report loop.
"""
from __future__ import annotations

import sys
from pathlib import Path

from safeguard.engagement import Engagement
from safeguard.graph.checkpoint import SqliteCheckpointer
from safeguard.llm.client import LLMClient
from safeguard.llm.planner import LLMPlanner, RulePlanner
from safeguard.orchestrator import Orchestrator
from safeguard.safety.approvals import ApprovalDecision

ROE = "roe.yaml"
TOOLS = "tools.yaml"
SETTINGS = "settings.example.yaml"
RUNS_DIR = "runs-llm"
APPROVE = "void"          # auto-approve any parked active-validate step


def main() -> int:
    eng = Engagement.build(
        roe_path=ROE, tools_path=TOOLS, settings_path=SETTINGS,
        runs_dir=RUNS_DIR, dry_run=True,
    )

    client = LLMClient.from_settings(eng.settings)
    if not client.configured:
        print("LLM base_url not configured; set SAFEGUARD_LLM_BASE_URL", file=sys.stderr)
        return 1
    print(f"LLM planner -> model={client.model} base_url={client.base_url}")

    planner = LLMPlanner(client, eng.registry, fallback=RulePlanner(eng.registry))

    cp_path = Path(RUNS_DIR) / eng.roe.engagement_id / "checkpoints.db"
    orch = Orchestrator.build(eng, planner=planner, checkpointer=SqliteCheckpointer(cp_path))

    result = orch.run()
    print(f"\nengagement: {eng.roe.engagement_id}  status={result.status}")
    print("plan history (LLM-driven):")
    for h in result.state.plan_history:
        print(f"  plan -> {h['action']}: {h['rationale']}")

    if result.status == "interrupted":
        pa = result.state.pending_approval
        print(f"\n[PARKED] approval needed: {pa['tool']} on {pa['target']} ({pa['technique']})")
        orch.approve(pa["request_id"], approver=APPROVE, decision=ApprovalDecision.APPROVED)
        print(f"   approved by {APPROVE}; resuming...")
        result = orch.resume()

    rep = result.state.report or {}
    print(f"\nreport: {rep.get('assets', 0)} assets, {rep.get('findings', 0)} findings, "
          f"severity={rep.get('severity_counts', {})}")
    cov = rep.get("detection_coverage", {})
    print(f"detection coverage: {cov.get('coverage_pct', 0)}%  gaps: {len(cov.get('gaps', []))}")
    print(f"validations: {len(result.state.validations)}")
    print(f"\naudit: head={eng.audit.head[:16]}...  events={len(eng.audit.events())}  "
          f"intact={eng.audit.verify()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
