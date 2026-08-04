# Implementation — Phases 0–10 (complete)

This document covers the **code** in `safeguard/`. The design docs
(`README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `SAFETY.md`, `WORKFLOW.md`) are
unchanged; this is the first executable slice.

Per `ROADMAP.md`, **Phase 1 (Tool Adapter Framework) depends on Phase 0
(Foundations & Safety Rails)** — "no offensive tool ships before the safety
layer that governs it." So this milestone implements the Phase 0 safety
primitives *and* the Phase 1 adapter framework, with **Nmap** as the reference
adapter driven end-to-end through the safety pipeline.

## What's implemented

### Phase 0 — safety rails
| Module | Responsibility |
|--------|----------------|
| `config/models.py`, `config/loader.py` | Typed ROE / tools / settings, `${VAR}` env expansion, **fail-closed load** (a `destructive` class in `tools.yaml` raises). |
| `safety/scope_guard.py` | Allowlist (domains + subdomains, CIDRs, CIDR-subset targets), exclusions win, path exclusions, time-window enforcement. Fail-closed. |
| `safety/rate_limiter.py` | Per-target token-bucket rate + concurrency ceilings + global action budget. Deterministic (injected clock). |
| `safety/killswitch.py` | One-call halt with revocation hooks (wired to the runner). |
| `safety/audit.py` | Append-only, **SHA-256 hash-chained** audit log; `verify()` is tamper-evident; JSONL on disk. |
| `safety/approvals.py` | HITL approval store for `active-validate` steps (the Phase 4 LangGraph `interrupt()` seam). |

### Phase 1 — tool adapter framework
| Module | Responsibility |
|--------|----------------|
| `tools/schema.py` | Unified `Asset` / `Finding` / `ToolResult` + `Severity` / `SafetyClass`. |
| `tools/adapter.py` | `ToolAdapter` ABC: `build_command → validate → parse`. Adapters **cannot execute** — only the pipeline runs them. |
| `tools/runner.py` | `SandboxRunner` interface + `LocalSubprocessRunner` (dev). Production swaps in gVisor/Firecracker egress-pinned runner. |
| `tools/registry.py` | Binds `tools.yaml` specs to adapters; safety class is a property of the binding, not LLM-assertable. |
| `tools/adapters/nmap.py` | Reference adapter: XML parse → `Asset`s, plus a class-ceiling flag deny-list. |
| `safety/pipeline.py` | **The choke point.** Order: kill → scope → window → class/approval → forbidden-flag → rate → run → parse → audit. |
| `engagement.py`, `cli.py` | Assemble everything; `safeguard run / scope-check / audit-verify`. |

### Phase 2 — recon & asset discovery
| Module | Responsibility |
|--------|----------------|
| `tools/adapters/httpx.py` | Live-host probing + tech fingerprint (JSONL → `endpoint` assets). |
| `tools/adapters/whatweb.py` | Web tech fingerprinting (plugin map → tech); aggression levels 3/4 blocked by the class ceiling. |
| `tools/adapters/gobuster.py` | Content/dir discovery → `endpoint` assets; requires a wordlist (fail-closed). |
| `recon/assets.py` | `AssetInventory` — dedup/merge on `(type, address, port, protocol)`, deep-merges tech fingerprints from multiple tools. |
| `recon/flow.py` | `ReconFlow` — fixed black-box recon plan (`nmap → httpx → whatweb`), each step through the safety pipeline; denials/errors recorded, never fatal. |

**Phase 2 exit criteria:** `safeguard run --phase recon` yields a deduplicated
asset list with fingerprints, within budget — see `test_recon.py`
(`test_recon_flow_merges_across_tools`). CLI now takes `--plan` (e.g.
`nmap,httpx,whatweb,gobuster`) and `--wordlist` (for gobuster). The Phase 4 LLM
planner will later choose the plan order; Phase 2 uses a deterministic plan so
the pipeline + consolidation are exercisable now.

> Subdomain enumeration (a Phase 2 task) is deferred: no subdomain tool
> (subfinder/amass) is declared in `tools.yaml` yet. Adding one is a
> two-step change — a `tools.yaml` entry + a small adapter — and it slots
> into the existing `ReconFlow` plan with no framework changes.

### Phase 3 — vulnerability detection
| Module | Responsibility |
|--------|----------------|
| `tools/adapters/nuclei.py` | Templated detection (JSONL → `Finding`s, severity + CVE/CVSS). **Safe-only policy**: intrusive/DoS/fuzz/brute-force tags excluded via `-etags`, and `validate()` blocks re-enabling them (`-tags dos`, `-itags`). |
| `tools/adapters/nikto.py` | Web server hygiene checks (JSON → `Finding`s, default `low`). |
| `scan/findings.py` | `FindingLedger` — cross-tool dedup on `(asset_ref, title)`; keeps highest severity, unions CVEs/evidence/techniques, records contributing tools in `raw['sources']`. |
| `scan/flow.py` | `ScanFlow` — deterministic plan (`nuclei → nikto`), each step through the safety pipeline; findings merged into one ledger. |

Also in this phase: the scope guard now decomposes **URL targets**
(`https://host/path`) — host matched against the allowlist, path against
exclusions — since scan tools operate on URLs.

**Phase 3 exit criteria:** end-to-end **recon → scan → findings** with normalised,
deduplicated `Finding`s and evidence refs; intrusive templates provably excluded
(`test_nuclei_excludes_banned_tags_by_default`,
`test_nuclei_blocks_reenabling_banned_tags`). Run: `safeguard run --phase scan`.

### Phase 4 — LLM planner & orchestration
| Module | Responsibility |
|--------|----------------|
| `graph/state.py` | `AgentState` — typed state with append/merge accumulators (`inventory`, `ledger`) and full checkpoint (de)serialization. |
| `graph/engine.py` | LangGraph-shaped `StateGraph`: `add_node` / `add_edge` / `add_conditional_edges` / `GraphInterrupt` / `compile` / `invoke` / `resume`. |
| `graph/checkpoint.py` | `InMemoryCheckpointer` + `SqliteCheckpointer` (stdlib, sovereign-local); full per-node history for replay. |
| `graph/build.py` | Assembles the engagement graph: `planner → (recon \| scan \| approval_gate→validate \| report)`; the gate parks at an interrupt until a named approver resolves the request. |
| `llm/client.py` | Sovereign Qwen client — OpenAI-compatible over stdlib `urllib` (no foreign SDK), env-driven key, per-node reasoning profiles. Offline-safe: raises clearly if unconfigured. |
| `llm/planner.py` | `RulePlanner` (deterministic default) + `LLMPlanner` (Qwen JSON decision **validated in code** against the registry/safety classes — an invalid or destructive proposal is downgraded to `report`). |
| `llm/verifier.py` | Numeric-claim verifier skeleton (flags ungrounded CVEs; wired to intel in P6). |
| `orchestrator.py` | Drives the graph over an `Engagement`; `run` / `approve` (RBAC-checked named approver) / `resume`. |

**The golden rule at the graph level:** the planner only ever returns a
`PlanDecision`; nodes execute tools solely through the Phase-0 safety pipeline,
and every active step is gated by an `interrupt()` + named-approver sign-off.

**Phase 4 exit criteria:** a full passive engagement runs planner-driven
(`test_passive_engagement_completes`); an active step parks for approval and
resumes after sign-off (`test_active_step_parks_for_approval_and_resumes`),
denial skips it (`test_denied_approval_skips_validation`); the run is replayable
from checkpoints (`test_checkpoint_replay_records_each_node`,
`test_sqlite_checkpointer_roundtrip`). Run: `safeguard engage --roe roe.yaml
[--approve <name>]`.

> LangGraph is the production orchestration backend; `graph/engine.py` mirrors
> its `StateGraph` API so the swap is mechanical. The in-repo engine exists so
> the graph runs offline and is unit-testable without the heavy dependency or a
> live LLM/checkpoint DB. Likewise the `LLMPlanner` needs a configured
> `SAFEGUARD_LLM_BASE_URL`; without one, runs use the deterministic
> `RulePlanner` (the default).

### Phase 5 — safe validation (gated, active)
| Module | Responsibility |
|--------|----------------|
| `tools/adapters/dalfox.py` | Reflected-XSS **confirmation** (benign marker); blind/OOB/exploit flags rejected by the class ceiling → `Validation`. |
| `tools/adapters/sqlmap.py` | SQLi **detection-only** (`--technique=BT`, low level/risk, `--batch`); dump/shell/enumeration flags denied (tools.yaml + adapter). |
| `safety/profile.py` | `ProfileGuard` — code-level global denylist of destructive tokens applied to **every** command; only `non_destructive` enables execution, all else fails closed. |
| `evidence.py` | `EvidenceStore` — content-addressed (SHA-256) raw-output capture; every validation carries a stable `evidence_ref`. |
| `validate/flow.py` | `ValidateFlow` — runs one approved active-validate tool through the safety pipeline and normalises the outcome. |
| `tools/schema.py` | `Validation` / `ValidationResult`; `ToolResult.validations`. |

Defence in depth on destructive actions: (1) the `destructive` class is not
loadable; (2) per-tool `forbidden_flags`; (3) per-adapter mode ceilings; (4) the
global `ProfileGuard` in the pipeline. The pipeline now also captures evidence
and stamps the approving operator onto each `Validation`.

**Phase 5 exit criteria:** a validation without approval is blocked; an approved
validation confirms a signal and captures evidence; no destructive action is
reachable (`test_validate.py`, `test_active_step_runs_real_validation_with_evidence`).
The graph's `validate` node now runs the real `ValidateFlow` after sign-off.

### Phase 6 — intelligence & correlation (sovereign, offline)
| Module | Responsibility |
|--------|----------------|
| `intel/nvd.py` | `LocalNVDMirror` — CVE lookups against a local JSON mirror (`config/intel/nvd.sample.json`); **no nvd.nist.gov at runtime**. |
| `intel/attack.py` | `AttackMap` — MITRE ATT&CK technique mapping via local keyword rules (`config/intel/attack_map.yaml`); the offline STIX stand-in. |
| `intel/risk.py` | `RiskScorer` — CVSS + EPSS + asset criticality **+ detection status**; an undetected medium can outrank a detected high. |
| `intel/enrich.py` | `Enricher` — attaches CVE detail + ATT&CK + risk to each finding and returns the **grounded-token set** for the verifier. Numbers come only from artifacts. |
| `intel/correlate.py` | `AttackPathCorrelator` — chains findings per asset along the ATT&CK tactic order into candidate kill-chains, each step carrying its detection verdict (`UNKNOWN` until the Oracle, P7). |
| `llm/verifier.py` | Numeric-claim verifier now **active** in the report node: any CVE not in the grounded set is flagged. |

New graph node `correlate` (planner: recon → scan → **correlate** → gated-validate
→ report). The report now includes attack paths, top risk, and the numeric
verification verdict. `AgentState` gained `attack_paths` + `grounded_tokens`
(checkpointed).

**Phase 6 exit criteria:** every numeric claim traces to a tool/DB artifact
(`test_enricher_grounds_cvss_from_mirror`, `test_numeric_verifier_flags_ungrounded_cve`);
no external CVE call in the default build (mirror is local-file only). Detection-
aware scoring proven by `test_undetected_medium_can_outrank_detected_high`.

> Also fixed a latent `tools ↔ safety` import cycle by moving `pipeline.py`'s
> adapter/runner imports under `TYPE_CHECKING` (they were type-hint-only).

### Phase 7 — Detection Oracle ★ (the differentiator)
| Module | Responsibility |
|--------|----------------|
| `oracle/models.py` | `DetectionEvent`, `DetectionResult`, `Verdict` (BLOCKED/DETECTED/PARTIAL/MISSED) + best-first aggregation. |
| `oracle/telemetry.py` | `TelemetryBackend` (read-only query contract) + `InMemoryTelemetryBackend` for dev/tests; real Wazuh/Coraza/EDR/PAM/DAM sources slot in behind the same contract. |
| `oracle/connectors.py` | Read-only `Wazuh/WAF/EDR/PAM/DAM` connectors; WAF/EDR can return `BLOCKED`, others observe only. `read_only=True` by construction. |
| `oracle/scorer.py` | `CoverageScorer` — aggregate verdict (best across sources) + **MTTD** (earliest detection relative to action time). |
| `oracle/oracle.py` | `DetectionOracle.observe(...)` — queries every connector over the action's time window + target and scores one verdict. |
| `oracle/coverage.py` | `CoverageMatrix` — coverage %, mean MTTD, per-technique matrix, and the **gap report** (every MISSED/PARTIAL) for Detect/Act. |

The Oracle runs **after every action** (recon/scan/validate) in the graph;
verdicts land in `state.detections` and `state.detection_status`, which the
`correlate` node feeds into risk scoring — closing the loop where *an undetected
finding outranks a detected one*. The report now carries `detection_coverage`
(coverage %, MTTD, gaps). `AgentState` gained `detections` + `detection_status`
(checkpointed).

**Phase 7 exit criteria:** each emulated action gets a verdict validated against
the (simulated) SIEM/WAF state — `test_wazuh_detected_with_mttd`,
`test_waf_block_beats_siem_detect`, `test_missed_when_no_telemetry`,
`test_event_outside_window_ignored`, and the graph integration
`test_oracle_wired_into_graph_marks_missed` (empty telemetry → 0% coverage, gap
report populated, MISSED status boosts finding risk).

> The connectors query a `TelemetryBackend`; Phase 7 ships the in-memory backend
> for deterministic runs. Production supplies real read-only Wazuh/WAF/EDR/PAM/DAM
> backends (dedicated read-only service accounts) behind the same `query`
> contract — no other code changes. The risk scorer/correlator already consumed
> a `detection_status` map from Phase 6; the Oracle simply fills it.

### Phase 8 — reporting & evidence
| Module | Responsibility |
|--------|----------------|
| `reporting/heatmap.py` | `AttackHeatmap` — technique × verdict matrix from the Oracle's detections + technique-coverage %. |
| `reporting/report.py` | `Reporter.build(state)` → `ReportBundle`: `report.json` + executive summary, technical report, ATT&CK heatmap, and **detection-gap report** (each MISSED/PARTIAL with the expected detection to add). `ReportBundle.write()` emits the bundle to `runs/<id>/report/`. |
| `evidence.py` (P5) | Content-addressed evidence, referenced by hash from findings/validations. |

Narratives are grounded: the numeric-claim verifier checks every CVE against the
grounded-token set, and the executive summary flags any ungrounded figure.
`safeguard engage` now writes the bundle automatically on completion.

**Phase 8 exit criteria:** a stakeholder can read posture, coverage %, and the
exact gaps with expected detections; every figure is grounded
(`test_reporting.py` — heatmap, gap report, grounded/ungrounded narrative, bundle
writer).

### Phase 9 — gray-box & white-box modes
| Module | Responsibility |
|--------|----------------|
| `tools/adapters/semgrep.py` | White-box SAST (passive) → findings with file:line + severity. |
| `tools/adapters/gitleaks.py` | White-box secret detection (passive); **secret value never stored** (DPDP). |
| `tools/adapters/checkov.py` | White-box IaC misconfig scanning (passive). |
| `tools/adapters/trivy.py` | Dependency/container/config scanning (active-recon) → CVE + CVSS. |
| `tools/adapters/prowler.py` | Gray-box cloud posture (active-recon, read-only IAM); mutating/remediation flags rejected. |

All five fold into the **same** `FindingLedger`/enrichment/oracle/report
pipeline — no new plumbing. Mode awareness:
- **Scope guard** now matches `repos` and `cloud_accounts` allowlists (gray/white-box targets aren't network hosts).
- **Planner** skips network recon for white-box and skips active web validation for white-box source.
- **Scan node** picks a mode-default plan/targets: black-box `nuclei,nikto` over endpoints; gray-box `prowler,trivy` over cloud accounts; white-box `semgrep,gitleaks,checkov,trivy` over repos.

**Phase 9 exit criteria:** a white-box run yields SAST/secret/IaC findings folded
into the pipeline, ATT&CK-mapped and Oracle-checked where applicable — mode-aware
(no recon), see `test_modes.py` (`test_white_box_engagement_scans_source_no_recon`)
plus per-adapter parsing and the read-only/DPDP guards.

All 13 tools declared in `tools.yaml` now have working adapters.

### Phase 10 — hardening, continuous mode & platform integration
| Module | Responsibility |
|--------|----------------|
| `continuous/baseline.py` | `BaselineStore` + `diff_reports` — **regression detection**: a (technique, host) that was DETECTED/BLOCKED and is now MISSED/PARTIAL, plus improvements, new/resolved gaps & findings, and coverage delta. |
| `continuous/runner.py` | `ContinuousRunner.record()` — one cycle: diff the fresh bundle vs the stored baseline, then save it as the new baseline. |
| `integration/detect.py` | `DetectIntegration` — turns gaps into SIEM/WAF **rule candidates** for the Detect loop; writes an outbox. |
| `integration/act.py` | `ActIntegration` — candidate response **playbooks** + Jira-style **ticket** stubs for the Act loop. |
| `safety/rbac.py` | `RBAC` — least-privilege roles (admin/operator/approver/viewer) over start/approve/kill/query. |
| `api/control_plane.py` | `ControlPlane` — RBAC-gated, audited façade over the orchestrator (start/approve/kill/audit-query); the FastAPI app is a thin wrapper over this. |
| `observability/metrics.py` | `Metrics` — dependency-free counters/gauges with labels; export to Prometheus/OTel in deployment. |
| `reporting/report.py` | Report now emits a `detection_index` ({technique|host → verdict}) — the key regression diffing keys on. |

`safeguard engage` now closes the loop each run: writes the bundle, records a
continuous cycle (prints regressions/coverage delta vs the prior run), and writes
the Detect/Act handoff to `runs/<id>/handoff/`.

**Phase 10 exit criteria:** scheduled runs produce trend + regression reports
(`test_diff_detects_regression`, `test_continuous_runner_cycles`); gaps auto-flow
to Detect/Act (`test_detect_rule_candidates`, `test_act_playbooks_and_tickets`);
control plane is RBAC-gated and audited (`test_rbac_matrix`, control-plane smoke
test). See `test_phase10.py`.

> **Security posture of Safeguard itself:** RBAC on every control-plane action;
> secrets only from env/secret-store (never config/model output); the four-layer
> destructive-action defence (class-not-loadable → forbidden_flags → adapter mode
> ceilings → global profile guard); fail-closed scope/window/approval gates; and
> the hash-chained audit log. What remains for a production cutover is
> infrastructure, not logic: swap the in-repo `StateGraph`→LangGraph,
> `LocalSubprocessRunner`→gVisor/Firecracker egress-pinned runner, and
> `InMemoryTelemetryBackend`→live read-only Wazuh/WAF/EDR/PAM/DAM — each behind an
> interface already in place.

## Exit criteria (from ROADMAP Phase 1)
> *Nmap runs only against in-scope targets, in a sandbox that cannot reach
> out-of-scope hosts, fully audited.*

- **In-scope only** — enforced by `ScopeGuard` before the command is built; out-of-scope → `tool.denied` audit event, no execution (`test_pipeline_blocks_out_of_scope`).
- **Sandbox** — `LocalSubprocessRunner` for dev; `SandboxRunner` interface is the seam for the egress-pinned production runner (`sandbox.runtime` in settings). *Real egress-pinning is deployment/Phase 10; noted, not faked.*
- **Fully audited** — every proposal, exec, result, and denial is hash-chained; `safeguard audit-verify` re-checks the chain on disk.

## Run it

```bash
pip install -e .          # or: pip install pyyaml tzdata pytest
pytest -q                 # 96 tests

# Gate demonstrations (no nmap binary needed):
python -m safeguard.cli scope-check --roe roe.example.yaml 10.20.30.44      # IN SCOPE
python -m safeguard.cli scope-check --roe roe.example.yaml 8.8.8.8          # OUT OF SCOPE
python -m safeguard.cli scope-check --roe roe.example.yaml 10.20.30.5       # excluded
python -m safeguard.cli run --roe roe.example.yaml --dry-run                # full pipeline

# A real recon run additionally needs the nmap binary on PATH and the current
# time inside the ROE window (02:00–04:00 IST in the example).
```

> Note: the example ROE window is 02:00–04:00 IST, so an out-of-window `run`
> is *correctly* blocked — that is the fail-closed time gate working, not a bug.
> Widen `windows.allowed` in your `roe.yaml` to run interactively.

## Production cutover (infrastructure, not logic)
All 11 phases (P0–P10) are implemented and tested. What remains is swapping three
dev implementations for their production backends — each behind an interface
already in the codebase, so it is a wiring change, not a rewrite:

| Dev (in-repo) | Production | Interface |
|---|---|---|
| `StateGraph` engine | LangGraph `StateGraph` + Postgres checkpointer | `graph/engine.py`, `Checkpointer` |
| `LocalSubprocessRunner` | gVisor/Firecracker egress-pinned runner | `SandboxRunner` |
| `InMemoryTelemetryBackend` | live read-only Wazuh/WAF/EDR/PAM/DAM | `TelemetryBackend` |
| `RulePlanner` | `LLMPlanner` on sovereign Qwen | `Planner` (set `SAFEGUARD_LLM_BASE_URL`) |
| `ControlPlane` core | FastAPI app over it | `api/control_plane.py` |

Also for hardening: load/soak testing, OTel/Prometheus export of `Metrics`, and
operator runbooks.
