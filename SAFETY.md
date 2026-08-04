# RedBlueAI Safeguard — Safety, Rules of Engagement & Compliance

Safeguard is an offensive-capability system. It is safe to build and operate **only** because of the controls below. These are engineering requirements, not policy suggestions — most are enforced in code and fail closed.

---

## 1. First principle: authorised, non-destructive, in-scope

Safeguard runs **only** against assets ESDS owns or is contractually authorised to test, **only** in non-destructive mode, and **only** within the declared scope and time window. There is no supported configuration that violates any of these three at once, and the destructive action class is disabled and unreachable from model output.

If any of scope, authorisation, or non-destructive guarantee is uncertain for a given action, the action is **denied**.

---

## 2. Rules of Engagement (ROE)

Every engagement is defined by a signed `roe.yaml`. The scope guard validates it before the graph starts and re-checks every target at runtime.

Required fields:
- **Authorisation** — engagement owner, authorising manager, ticket reference.
- **In-scope targets** — explicit CIDRs, domains, cloud accounts, repos. (Allowlist; anything not listed is out of scope.)
- **Exclusions** — hosts/paths/accounts that must never be touched even if in a listed range.
- **Time windows** — permitted execution windows (IST); outside → blocked.
- **Mode** — black-box / gray-box / white-box.
- **Profile** — `non_destructive` (only default-enabled profile).
- **Approvers** — named humans who may authorise active steps.
- **Budget** — max requests/sec per target, max concurrency, total action ceiling.

The scope guard is **fail-closed**: unresolvable target, expired window, or missing authorisation halts the action and writes an audit event.

---

## 3. Guardrails (enforced in code)

| Guardrail | Enforcement |
|-----------|-------------|
| **Scope guard** | every target checked against ROE allowlist + exclusions before any packet; out-of-scope → hard block. |
| **Non-destructive profile** | data-modifying, exfil, DoS, and persistence actions are absent from enabled tool bindings; cannot be enabled by LLM output. |
| **Destructive class disabled** | tools/actions in the `destructive` class are not loaded; the planner cannot propose them. |
| **Human-in-the-loop** | any `active-validate` step pauses via LangGraph `interrupt()` for a *named* approver; deny/timeout → skip. |
| **Rate & blast-radius limits** | per-target rate + concurrency ceilings; global engagement budget; exceeding → throttle/stop. |
| **Sandbox egress pinning** | tool containers can only reach in-scope targets; egress firewall bound to ROE. |
| **Kill switch** | one control-plane call halts all in-flight actions and revokes sandbox tokens. |
| **Immutable audit** | every plan, proposal, approval, tool call, and result is hash-chained and append-only. |
| **Numeric-claim verifier** | no CVE/CVSS/EPSS/count enters a report unless backed by a tool/DB artifact. |
| **LLM cannot execute** | the model only *proposes*; deterministic code binds, checks, and runs. Prompt-injected "run X" from a scanned page/target has no path to execution. |

### 3.1 Prompt-injection resistance
Safeguard reads untrusted content (web pages, source, tool output). None of it is treated as instructions. Tool proposals come only from the planner over trusted state; scanned content is data. An attacker-controlled page cannot cause an out-of-scope or destructive action because (a) the model can't execute, and (b) the scope/class/approval gates sit between any proposal and execution.

---

## 4. Separation & least privilege

- Safeguard runs in its **own tenant/project**, isolated from the production workloads it tests.
- Detection Oracle connectors use **dedicated read-only** service accounts (query telemetry, never mutate).
- Secrets (LLM key, connector creds) come from the sovereign secret store (Nandi/Vault-compatible), never from config files or model output.
- Control-plane actions (start/approve/kill) are RBAC-gated and audited per operator.

---

## 5. Sovereignty & data residency

- **Inference**: Qwen on ESDS sovereign GPU; no foreign LLM API in the default build.
- **CVE data**: local NVD mirror; **ATT&CK**: local STIX bundle. No outbound calls to NVD/MITRE at runtime.
- **Evidence, audit, telemetry**: India-resident on ESDS cloud.
- The default build has **zero foreign API dependencies** — this is a structural requirement, not a config toggle.

---

## 6. Compliance mapping (India / sector)

Safeguard's controls align with obligations ESDS and its regulated customers (BFSI, government) carry:

- **CERT-In** — audit trail, incident-relevant logging, and the detection-gap output support directed security-testing and reporting expectations. Safeguard's own actions are fully logged with timestamps.
- **DPDP Act** — testing is non-destructive and read-only w.r.t. data; the agent does not exfiltrate or copy personal data. Evidence capture excludes payload data content by default.
- **RBI / sector cyber frameworks** — continuous control validation and coverage reporting map to periodic security-assessment and control-effectiveness requirements for regulated workloads.
- **ISO 27001 / SOC 2** — engagement reports and evidence bundles are structured for control-effectiveness evidence.

(Confirm exact obligations with ESDS compliance before customer-facing use; the above is the design intent, not legal advice.)

---

## 7. Operator responsibilities

Even with the controls above, humans own the outcomes:
- Only load ROEs for assets you are authorised to test; keep the authorising reference on file.
- Review the approval queue; do not blanket-approve active steps.
- Prefer the smallest scope and shortest window that achieves the objective.
- Watch the kill switch during first runs against any new environment.
- Treat the detection-gap report as sensitive: it is a map of what your defenders miss.

> Safeguard makes authorised, non-destructive security validation faster and repeatable. It does not remove the operator's duty to test only what they may, and to act on the gaps it finds.
