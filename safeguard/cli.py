"""Minimal CLI.

    safeguard run  --roe config/roe.yaml --phase recon [--plan ...] [--dry-run]
    safeguard scope-check --roe config/roe.yaml <target> [--path /p]
    safeguard audit-verify --roe config/roe.yaml

The ``run`` command drives the recon plan (nmap -> httpx -> whatweb by default)
through the full safety pipeline against every in-scope target and consolidates
the results into a deduplicated asset inventory.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from safeguard.engagement import Engagement

_DEFAULT_TOOLS = "tools.yaml"
_DEFAULT_SETTINGS = "settings.example.yaml"


def _resolve(path: str) -> str:
    return str(Path(path))


def _run_scan(eng, targets, args) -> int:
    from safeguard.scan.flow import DEFAULT_PLAN, ScanFlow

    plan = args.plan.split(",") if args.plan else DEFAULT_PLAN
    report = ScanFlow(eng.pipeline, eng.registry).run(targets, plan=plan)

    for step in report.steps:
        tag = step.status if step.allowed else "DENIED"
        extra = f" - {step.denial}" if step.denial else (
            f" (error: {step.error})" if step.error else "")
        print(f"[{tag}] {step.tool} {step.target}: {step.findings} findings{extra}")

    ledger = report.ledger
    print(f"\nfindings: {len(ledger)} unique  severity={ledger.by_severity()}")
    for f in ledger.findings():
        sources = ",".join(f.raw.get("sources", []))
        cves = f" {f.cve_ids}" if f.cve_ids else ""
        print(f"  - [{f.severity.value}] {f.title}  ({f.asset_ref}) "
              f"via {sources}{cves}")

    print(f"\nsteps: {report.allowed_steps} run / {report.denied_steps} denied")
    print(f"audit head: {eng.audit.head[:16]}...  "
          f"events: {len(eng.audit.events())}  intact: {eng.audit.verify()}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    eng = Engagement.build(
        roe_path=_resolve(args.roe),
        tools_path=_resolve(args.tools),
        settings_path=_resolve(args.settings),
        runs_dir=args.runs_dir,
        dry_run=args.dry_run,
    )
    print(f"engagement: {eng.roe.engagement_id}  mode={eng.roe.mode.value}  "
          f"profile={eng.roe.profile}")
    print(f"runnable adapters: {', '.join(eng.registry.runnable()) or '(none)'}")

    if args.phase not in ("recon", "scan"):
        print(f"phase '{args.phase}' not implemented yet (recon | scan).",
              file=sys.stderr)
        return 2

    targets = list(eng.roe.scope.domains) + list(eng.roe.scope.cidrs)
    if not targets:
        print("no in-scope targets in ROE", file=sys.stderr)
        return 1

    if args.phase == "scan":
        return _run_scan(eng, targets, args)

    from safeguard.recon.flow import DEFAULT_PLAN, ReconFlow

    plan = args.plan.split(",") if args.plan else DEFAULT_PLAN
    params = {}
    if args.wordlist:
        params["gobuster"] = {"wordlist": args.wordlist}

    flow = ReconFlow(eng.pipeline, eng.registry)
    report = flow.run(targets, plan=plan, params=params)

    for step in report.steps:
        tag = step.status if step.allowed else "DENIED"
        extra = ""
        if step.denial:
            extra = f" - {step.denial}"
        elif step.error:
            extra = f" (error: {step.error})"
        print(f"[{tag}] {step.tool} {step.target}: {step.assets} assets{extra}")

    inv = report.inventory
    print(f"\ninventory: {len(inv)} unique assets across {len(inv.hosts())} hosts")
    for a in inv.assets():
        loc = f":{a.port}" if a.port else ""
        svc = f" {a.service}" if a.service else ""
        print(f"  - [{a.asset_type.value}] {a.address}{loc}{svc}")

    print(f"\nsteps: {report.allowed_steps} run / {report.denied_steps} denied")
    print(f"audit head: {eng.audit.head[:16]}...  "
          f"events: {len(eng.audit.events())}  intact: {eng.audit.verify()}")
    return 0


def _cmd_engage(args: argparse.Namespace) -> int:
    """Planner-driven engagement: recon -> scan -> (gated validate) -> report."""
    from safeguard.graph.checkpoint import SqliteCheckpointer
    from safeguard.orchestrator import Orchestrator
    from safeguard.safety.approvals import ApprovalDecision

    eng = Engagement.build(
        roe_path=_resolve(args.roe), tools_path=_resolve(args.tools),
        settings_path=_resolve(args.settings), runs_dir=args.runs_dir,
        dry_run=args.dry_run)
    cp_path = Path(args.runs_dir) / eng.roe.engagement_id / "checkpoints.db"
    orch = Orchestrator.build(eng, checkpointer=SqliteCheckpointer(cp_path))

    result = orch.run()
    print(f"engagement: {eng.roe.engagement_id}")
    for h in result.state.plan_history:
        print(f"  plan -> {h['action']}: {h['rationale']}")

    if result.status == "interrupted":
        pa = result.state.pending_approval
        print(f"\n[PARKED] for approval: {pa['tool']} on {pa['target']} "
              f"({pa['technique']})")
        print(f"   request_id={pa['request_id']}")
        if args.approve:
            orch.approve(pa["request_id"], approver=args.approve,
                         decision=ApprovalDecision.APPROVED)
            print(f"   approved by {args.approve}; resuming...\n")
            result = orch.resume()
        else:
            print("   re-run with --approve <named-approver> to sign off and resume.")
            return 0

    rep = result.state.report or {}
    print(f"\nreport: {rep.get('assets', 0)} assets, {rep.get('findings', 0)} findings, "
          f"severity={rep.get('severity_counts', {})}")
    cov = rep.get("detection_coverage", {})
    print(f"detection coverage: {cov.get('coverage_pct', 0)}%  "
          f"gaps: {len(cov.get('gaps', []))}")
    print(f"validations: {len(result.state.validations)}")

    if result.status == "complete":
        from safeguard.continuous.baseline import BaselineStore
        from safeguard.continuous.runner import ContinuousRunner
        from safeguard.integration.act import ActIntegration
        from safeguard.integration.detect import DetectIntegration
        from safeguard.reporting.report import Reporter

        bundle = Reporter().build(result.state)
        eng_dir = Path(args.runs_dir) / eng.roe.engagement_id
        paths = bundle.write(eng_dir / "report")
        print("\nreport bundle:")
        for name in sorted(paths):
            print(f"  {paths[name]}")

        # Continuous mode: baseline diff (regressions vs the prior run).
        cycle = ContinuousRunner(BaselineStore(args.runs_dir)).record(
            eng.roe.engagement_id, bundle.data)
        reg = cycle.regression
        if reg.has_baseline:
            print(f"\ncontinuous: cycle {cycle.cycle_index}, "
                  f"coverage delta {reg.coverage_delta:+}%  "
                  f"regressions={len(reg.regressions)} new_gaps={len(reg.new_gaps)}")
            for r in reg.regressions:
                print(f"  REGRESSION {r['key']}: {r['was']} -> {r['now']}")
        else:
            print(f"\ncontinuous: baseline established (cycle {cycle.cycle_index})")

        # Detect/Act handoff.
        outbox = eng_dir / "handoff"
        DetectIntegration().push(bundle.data, outbox)
        ActIntegration().push(bundle.data, outbox)
        print(f"handoff written: {outbox}")

    print(f"audit head: {eng.audit.head[:16]}...  intact: {eng.audit.verify()}")
    return 0


def _cmd_scope_check(args: argparse.Namespace) -> int:
    from safeguard.config.loader import load_roe
    from safeguard.safety.scope_guard import ScopeGuard
    from safeguard.safety.exceptions import SafetyViolation

    roe = load_roe(_resolve(args.roe))
    guard = ScopeGuard(roe)
    target = Target(raw=args.target, path=args.path)
    try:
        guard.check_target(target)
        print(f"IN SCOPE: {args.target}")
        return 0
    except SafetyViolation as sv:
        print(f"OUT OF SCOPE: {args.target} - {sv}")
        return 1


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    from safeguard.config.loader import load_roe
    from safeguard.safety.audit import AuditLog, AuditEvent, GENESIS_HASH

    roe = load_roe(_resolve(args.roe))
    log_path = Path(args.runs_dir) / roe.engagement_id / "audit.log.jsonl"
    if not log_path.is_file():
        print(f"no audit log at {log_path}", file=sys.stderr)
        return 1
    prev = GENESIS_HASH
    ok = True
    count = 0
    with log_path.open(encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            rec = json.loads(line)
            ev = AuditEvent(**rec)
            if ev.seq != i or ev.prev_hash != prev or ev.compute_hash() != ev.hash:
                ok = False
                break
            prev = ev.hash
            count += 1
    print(f"audit chain: {'INTACT' if ok else 'BROKEN'} ({count} events)")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="safeguard",
                                description="RedBlueAI Safeguard (Phase 1)")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--roe", required=True, help="path to roe.yaml")
    common.add_argument("--tools", default=_DEFAULT_TOOLS)
    common.add_argument("--settings", default=_DEFAULT_SETTINGS)
    common.add_argument("--runs-dir", default="runs")

    r = sub.add_parser("run", parents=[common], help="run an engagement phase")
    r.add_argument("--phase", default="recon")
    r.add_argument("--plan", default=None,
                   help="comma-separated recon plan, e.g. nmap,httpx,whatweb,gobuster")
    r.add_argument("--wordlist", default=None,
                   help="wordlist path for gobuster content discovery")
    r.add_argument("--dry-run", action="store_true",
                   help="build/validate/gate everything but don't execute tools")
    r.set_defaults(func=_cmd_run)

    e = sub.add_parser("engage", parents=[common],
                       help="run a planner-driven engagement (recon->scan->report)")
    e.add_argument("--dry-run", action="store_true")
    e.add_argument("--approve", default=None,
                   help="named approver to auto-sign-off a parked active step")
    e.set_defaults(func=_cmd_engage)

    s = sub.add_parser("scope-check", parents=[common],
                       help="check a single target against the ROE")
    s.add_argument("target")
    s.add_argument("--path", default=None)
    s.set_defaults(func=_cmd_scope_check)

    a = sub.add_parser("audit-verify", parents=[common],
                       help="verify the audit hash-chain on disk")
    a.set_defaults(func=_cmd_audit_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
