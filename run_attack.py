"""Real (non-dry-run) authorised engagement against demo.testfire.net.

Runs the full safety-gated loop for real: nmap (scoped to web ports) -> nuclei
(safe-only templates) + nikto -> correlate -> report bundle. Non-destructive
profile; single in-scope domain (roe.demo.yaml). Writes the report bundle and
Detect/Act handoff under runs-attack/.
"""
from __future__ import annotations

from pathlib import Path

from safeguard.continuous.baseline import BaselineStore
from safeguard.continuous.runner import ContinuousRunner
from safeguard.engagement import Engagement
from safeguard.graph.checkpoint import SqliteCheckpointer
from safeguard.integration.act import ActIntegration
from safeguard.integration.detect import DetectIntegration
from safeguard.orchestrator import Orchestrator
from safeguard.reporting.report import Reporter

ROE = "roe.demo.yaml"
TOOLS = "tools.yaml"
SETTINGS = "settings.example.yaml"
RUNS_DIR = "runs-attack"


def main() -> int:
    eng = Engagement.build(
        roe_path=ROE, tools_path=TOOLS, settings_path=SETTINGS,
        runs_dir=RUNS_DIR, dry_run=False,          # REAL execution
    )
    print(f"engagement: {eng.roe.engagement_id}  mode={eng.roe.mode.value}  "
          f"profile={eng.roe.profile}")
    print(f"targets: {list(eng.roe.scope.domains)}")

    cp_path = Path(RUNS_DIR) / eng.roe.engagement_id / "checkpoints.db"
    orch = Orchestrator.build(
        eng,
        checkpointer=SqliteCheckpointer(cp_path),
        recon_plan=["nmap"],                        # whatweb broken / httpx wrong-bin here
        recon_params={"nmap": {"ports": "80,443"}}, # scope to web ports -> fast
        scan_plan=["nuclei", "nikto"],              # the actual web attack
    )

    result = orch.run()
    st = result.state
    print(f"\nstatus={result.status}")
    print("plan history:")
    for h in st.plan_history:
        print(f"  -> {h['action']}: {h['rationale']}")

    print(f"\ninventory: {len(st.inventory)} assets")
    for a in st.inventory.assets():
        loc = f":{a.port}" if a.port else ""
        svc = f" {a.service or ''} {a.tech or ''}".rstrip()
        print(f"  - [{a.asset_type.value}] {a.address}{loc}{svc}")

    print(f"\nfindings: {len(st.ledger)}  severity={st.ledger.by_severity()}")
    for f in st.ledger.findings():
        cves = f" {f.cve_ids}" if f.cve_ids else ""
        print(f"  - [{f.severity.value}] {f.title}  ({f.asset_ref}){cves}")

    rep = st.report or {}
    print(f"\nreport summary: assets={rep.get('assets')} findings={rep.get('findings')} "
          f"top_risk={rep.get('top_risk')} "
          f"attack_paths={len(rep.get('attack_paths', []))} "
          f"numeric_ok={rep.get('numeric_verification', {}).get('ok')}")

    # Full report bundle + Detect/Act handoff.
    bundle = Reporter().build(st)
    eng_dir = Path(RUNS_DIR) / eng.roe.engagement_id
    paths = bundle.write(eng_dir / "report")
    print("\nreport bundle:")
    for name in sorted(paths):
        print(f"  {paths[name]}")

    outbox = eng_dir / "handoff"
    print(f"  {DetectIntegration().push(bundle.data, outbox)}")
    act_paths = ActIntegration().push(bundle.data, outbox)
    for p in act_paths.values():
        print(f"  {p}")

    ContinuousRunner(BaselineStore(RUNS_DIR)).record(eng.roe.engagement_id, bundle.data)

    print(f"\naudit: head={eng.audit.head[:16]}...  events={len(eng.audit.events())}  "
          f"intact={eng.audit.verify()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
