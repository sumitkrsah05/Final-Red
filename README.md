# RedBlueAI — Safeguard (Autonomous Red Team Agent)

> The **Safeguard** loop of the RedBlueAI platform. An autonomous, safety-gated adversary-emulation agent that continuously and **non-destructively** simulates real attacker behaviour against ESDS's authorised estate to **validate whether the existing defensive stack (SIEM, WAF, PAM, DAM, EDR) actually detects and responds** — then feeds the gaps back into the Detect and Act loops.

This is **not** a mass-exploitation tool. It is a **breach-and-attack-simulation / continuous security-validation** engine. Every offensive capability is a thin orchestration layer over standard open-source security tools (Nmap, Nuclei, Nikto, Prowler, Trivy, Semgrep, …), wrapped in scope enforcement, human-in-the-loop approval, immutable audit, and a kill switch.

---

## 1. Where Safeguard sits

RedBlueAI has three cooperating loops:

| Loop | Role | This repo |
|------|------|-----------|
| **Safeguard** | Red-team validation — emulate attacker TTPs against our own estate to test controls | ✅ **This repo** |
| **Detect** | Correlate live signals from SIEM / PAM / DAM / WAF / EDR into incidents | consumer of our findings |
| **Act** | Automated / approved response (block IP, WAF rule, isolate host, raise ticket) | consumer of our findings |

Safeguard is the **purple-team engine**: it is the only loop that *generates* attacker activity on purpose, precisely so Detect and Act can be measured against ground truth.

The defining question Safeguard answers is not *"is this host vulnerable?"* — plenty of scanners answer that. It is:

> **"When we perform technique T against asset A, does our Blue Team stack see it, alert on it, and stop it — and if not, why not?"**

That control-validation focus (the **Detection Oracle**, §3) is what separates Safeguard from an off-the-shelf pentest agent like Strix.

---

## 2. What it does (capability summary)

- **Attack-surface discovery** — passive + active recon (Nmap, WhatWeb, httpx, subdomain/dir enumeration).
- **Vulnerability detection** — Nuclei, Nikto, Trivy, Prowler; SAST/secrets/IaC (Semgrep, Gitleaks, Checkov) for white-box mode.
- **Safe validation** — non-destructive proof-of-signal (e.g. reflected-XSS confirmation via Dalfox, boolean/time SQLi *detection* via SQLMap in read-only mode) — **only** on authorised targets and behind approval gates.
- **Adversary emulation** — chains findings into MITRE ATT&CK-mapped attack paths; can run curated technique playbooks (e.g. Atomic Red Team-style) to test specific detections.
- **Detection Oracle (the differentiator)** — after each emulated action, queries Wazuh/SIEM, WAF, EDR, PAM and DAM to determine whether the action produced the *expected* telemetry, alert, or block; computes **detection coverage** and **time-to-detect**.
- **Intelligence & scoring** — CVE enrichment from a **local NVD mirror**, EPSS/CVSS-grounded risk scoring, ATT&CK technique mapping.
- **Reporting** — technical report (evidence + severity), executive summary, ATT&CK coverage heatmap, and a **detection-gap report** consumed by Detect/Act.

Operating modes mirror standard assessment postures: **black-box** (URL/IP only), **gray-box** (read-only creds / cloud IAM / k8s), **white-box** (source, IaC, CI/CD).

---

## 3. High-level architecture (1-minute version)

```
                ┌────────────────────────────────────────────────────────┐
                │                 Control Plane (FastAPI)                 │
                │   engagements · approvals · audit query · kill switch   │
                └───────────────┬────────────────────────────────────────┘
                                │
                 ┌──────────────▼───────────────┐        ┌───────────────────────┐
                 │   LangGraph Orchestrator     │◄──────►│  Qwen LLM (sovereign) │
                 │   (planner + state machine)  │        │  planning · triage ·  │
                 │   HITL interrupts + checkpt  │        │  ATT&CK map · report  │
                 └───┬──────────┬──────────┬────┘        └───────────────────────┘
                     │          │          │
     ┌───────────────▼──┐  ┌────▼──────┐  ┌▼──────────────────┐
     │  Tool Orchestr.  │  │  Intel    │  │ Detection Oracle  │
     │  (adapters +     │  │  CVE/NVD  │  │ Wazuh · WAF · EDR │
     │  sandbox runner) │  │  ATT&CK   │  │ PAM · DAM         │
     └───────┬──────────┘  └───────────┘  └───────────────────┘
             │
   ┌─────────▼─────────────────────────────────────────┐
   │  Cross-cutting Safety Layer (applies to every node) │
   │  scope guard · rate limiter · approval gate ·      │
   │  immutable audit · kill switch · non-destructive   │
   └─────────────────────────────────────────────────────┘
```

Full detail, component responsibilities, state schema and diagrams: **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

---

## 4. Proposed repository layout

```
redblueai-safeguard/
├── README.md                     # this file
├── docs/
│   ├── ARCHITECTURE.md           # components, state graph, data model, diagrams
│   ├── WORKFLOW.md               # the operational red-team loop, HITL, worked example
│   ├── ROADMAP.md                # phase-wise task distribution (the build plan)
│   └── SAFETY.md                 # rules of engagement, guardrails, compliance
├── config/
│   ├── roe.example.yaml          # rules of engagement / scope allowlist
│   ├── tools.yaml                # tool registry + safety classification
│   └── settings.example.yaml     # LLM endpoint, oracle connectors, limits
├── safeguard/
│   ├── graph/                    # LangGraph: state.py, build.py, nodes/
│   ├── tools/                    # adapter framework + per-tool adapters + sandbox runner
│   ├── safety/                   # scope guard, rate limiter, approvals, audit, killswitch
│   ├── intel/                    # local CVE/NVD mirror, ATT&CK STIX, risk scoring
│   ├── oracle/                   # detection connectors (wazuh/waf/edr/pam/dam)
│   ├── llm/                      # Qwen client wrapper, prompts, numeric-claim verifier
│   ├── reporting/                # technical/exec reports, ATT&CK heatmap, evidence bundle
│   └── api/                      # FastAPI control plane
├── sandbox/                      # Dockerfiles for tool runners (gVisor/Firecracker)
└── tests/
```

---

## 5. Configuration

Nothing sensitive is hard-coded. All secrets come from the environment / a sovereign secret store (ESDS Nandi / Vault-compatible).

```bash
# --- LLM (Qwen, ESDS sovereign inference) ---
export SAFEGUARD_LLM_MODEL="qwen3-32b"                  # production target
export SAFEGUARD_LLM_BASE_URL="https://<sovereign-inference-endpoint>/v1"
export SAFEGUARD_LLM_API_KEY="<injected-from-secret-store>"

# --- Engagement defaults ---
export SAFEGUARD_MODE="black_box"                       # black_box | gray_box | white_box
export SAFEGUARD_PROFILE="non_destructive"              # only profile enabled by default

# --- Detection Oracle connectors (read-only service accounts) ---
export SAFEGUARD_WAZUH_URL="https://wazuh.internal:55000"
export SAFEGUARD_WAF_LOG_SOURCE="..."      # ModSecurity/Coraza log endpoint
# ... EDR / PAM (Nandi) / DAM (Jatayoo) read-only endpoints
```

The OpenAI-compatible client used for testing points at the Modal-hosted Qwen endpoint; in the codebase it is read from `SAFEGUARD_LLM_*` env vars, never inlined. See §"Two notes before you build" below.

---

## 6. Quick start (developer)

```bash
# 1. Bring up the tool sandbox images (recon/scan/validate runners)
make sandbox-build

# 2. Define your engagement scope — targets, exclusions, windows, approvals
cp config/roe.example.yaml config/roe.yaml && $EDITOR config/roe.yaml

# 3. Dry run (recon only, non-destructive, no active validation)
safeguard run --roe config/roe.yaml --mode black_box --phase recon --dry-run

# 4. Full engagement (headless) — active steps pause for approval
safeguard run --roe config/roe.yaml --mode black_box -n
```

Results, evidence bundle, and the detection-gap report are written to `runs/<engagement-id>/`.

---

## 7. Safety posture (read this)

Safeguard is an offensive-capability system operated **only against assets ESDS owns or is explicitly authorised to test**. The guardrails below are not optional and are enforced in code, not policy:

- **Scope guard** — every action is checked against the ROE allowlist (CIDRs, domains, cloud accounts). Out-of-scope → hard block + audit event. Fail-closed.
- **Non-destructive by default** — the only shipped execution profile forbids data-modifying, DoS, or persistence actions. Destructive techniques are disabled and cannot be enabled from LLM output.
- **Human-in-the-loop** — any *active* step (validation, exploitation-class techniques, anything touching auth) pauses via a LangGraph `interrupt` for named-approver sign-off.
- **Rate & blast-radius limits** — per-target concurrency and request-rate ceilings; global engagement budget.
- **Immutable audit** — every plan, tool invocation, and result is written to an append-only, hash-chained log.
- **Kill switch** — one control-plane call halts all in-flight actions and revokes sandbox tokens.
- **Sovereign / India-resident** — LLM inference, CVE data, and all telemetry stay on ESDS sovereign infrastructure; no foreign API dependency in the default build.

Full rules of engagement, approval model, and compliance mapping (CERT-In, DPDP): **[`docs/SAFETY.md`](docs/SAFETY.md)**.

---

## 8. Documentation map

| Read this | For |
|-----------|-----|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components, LangGraph state machine, data model, diagrams |
| [`docs/WORKFLOW.md`](docs/WORKFLOW.md) | The end-to-end operational loop, HITL gates, a worked black-box run |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | **Phase-wise task distribution** — how we build this in stages |
| [`docs/SAFETY.md`](docs/SAFETY.md) | Rules of engagement, guardrails, legal/compliance |

---

## Two notes before you build

1. **LLM model naming.** Your brief says *Qwen-32B*, but the test endpoint/model string is `qwen3.5-9b` (the Modal URL). These are different models. The design is model-agnostic and config-driven, so this is not blocking — but decide the production target explicitly. Recommendation: **Qwen3-32B for production** (better tool-call planning and attack-path reasoning), **9B for local/dev** on the Modal endpoint. Whatever you pick, keep hybrid-thinking (reasoning) mode **on for the planner node** and off for cheap extraction nodes — carry the per-node inference profile through, don't set it once globally.
2. **The test key is a placeholder.** `api_key="dummy"` carries no secret, so nothing was exposed. In code it is always read from `SAFEGUARD_LLM_API_KEY`; never commit a real key.
