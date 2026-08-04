# Running RedBlueAI Safeguard

How to set up and run the Safeguard (Red Team) agent locally. For what the system
*is* and how it's built, see [`README.md`](README.md) and
[`IMPLEMENTATION.md`](IMPLEMENTATION.md).

The project root is `c:\Users\rahul.rathaur\Desktop\red`. All commands are shown
for **PowerShell** (Windows); Bash equivalents are listed at the end.

---

## 1. Prerequisites

- **Python 3.11+** (developed on 3.13).
- Dependencies: `PyYAML`, `tzdata` (Windows), `pytest` — installed in step 2.
- **Optional (for real, non-dry-run scans):** the external tool binaries on your
  `PATH` — `nmap`, `httpx`, `whatweb`, `gobuster`, `nuclei`, `nikto`, `dalfox`,
  `sqlmap`, `semgrep`, `gitleaks`, `checkov`, `trivy`, `prowler`. Not needed for
  `--dry-run` or the test suite.

---

## 2. Setup (one time)

```powershell
cd c:\Users\rahul.rathaur\Desktop\red

# create + activate a virtualenv (recommended)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# install the package + dev deps (pyyaml, tzdata, pytest)
pip install -e ".[dev]"
```

**Without installing** — run via the module path instead. Set `PYTHONPATH` once
per shell, then use `python -m safeguard.cli ...` in place of `safeguard ...`:

```powershell
$env:PYTHONPATH = "."
```

---

## 3. Verify the install

```powershell
pytest -q            # expected: 96 passed
```

---

## 4. Configure the engagement (Rules of Engagement)

```powershell
Copy-Item roe.example.yaml roe.yaml
notepad roe.yaml
```

Set your in-scope targets, exclusions, approvers, and time window.

> ⚠️ **Time window.** The example ROE only permits runs **02:00–04:00 IST**.
> Outside that window every action is *correctly* blocked by the fail-closed time
> gate (this is not a bug). To run interactively now, widen the window:
>
> ```yaml
> windows:
>   allowed:
>     - days: ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
>       start: "00:00"
>       end: "23:59"
> ```

---

## 5. Run the application

### Scope check (no scanning)

```powershell
safeguard scope-check --roe roe.yaml 10.20.30.44      # -> IN SCOPE
safeguard scope-check --roe roe.yaml 8.8.8.8          # -> OUT OF SCOPE
safeguard scope-check --roe roe.yaml 10.20.30.5       # -> excluded by ROE
```

### Recon phase (nmap → httpx → whatweb)

```powershell
# gate everything through the safety pipeline but don't execute tools
safeguard run --roe roe.yaml --phase recon --dry-run

# choose the tool plan; --wordlist enables gobuster content discovery
safeguard run --roe roe.yaml --phase recon --plan nmap,httpx,whatweb,gobuster --wordlist words.txt
```

### Scan phase (nuclei → nikto)

```powershell
safeguard run --roe roe.yaml --phase scan --dry-run
```

### Full autonomous engagement

Runs planner-driven **recon → scan → correlate → (gated validate) → report**,
then records a continuous baseline and writes the Detect/Act handoff.

```powershell
# passive end-to-end (parks at any active-validation step)
safeguard engage --roe roe.yaml --dry-run

# auto-approve a parked active-validation step as a named approver
safeguard engage --roe roe.yaml --approve void
```

### Verify the audit trail

```powershell
safeguard audit-verify --roe roe.yaml
```

> **`--dry-run`** exercises the full safety pipeline (scope → window → class →
> approval → rate → kill) and writes the complete audit trail, but does **not**
> execute the external tools. Drop it for a real run (requires the tool binaries
> on `PATH`).

---

## 6. Output

Everything is written under `runs/<engagement-id>/`:

```
runs/eng-2026-demo-001/
├── audit.log.jsonl        # hash-chained, append-only audit trail
├── checkpoints.db         # resumable graph state (SQLite)
├── evidence/              # content-addressed raw tool output
├── report/
│   ├── report.json                 # machine-readable bundle
│   ├── executive_summary.md
│   ├── technical_report.md
│   ├── attack_heatmap.md           # ATT&CK technique × detection verdict
│   └── detection_gap_report.md     # every MISSED/PARTIAL + expected detection
├── baselines/             # continuous-mode snapshots (regression diffing)
└── handoff/
    ├── detect_rule_candidates.json # -> Detect loop (SIEM/WAF rule candidates)
    ├── act_playbooks.json          # -> Act loop (response playbooks)
    └── act_tickets.json            # -> Jira-style ticket stubs
```

Run `engage` twice to see continuous mode: the first run establishes the
baseline; the second diffs against it and reports **regressions** (a technique
that was DETECTED last run and is now MISSED) and coverage delta.

---

## 7. Optional: drive planning with the sovereign LLM

Without these env vars, the agent uses the deterministic `RulePlanner` (fully
functional offline). To use the sovereign Qwen planner instead:

```powershell
$env:SAFEGUARD_LLM_BASE_URL = "https://<sovereign-inference-endpoint>/v1"
$env:SAFEGUARD_LLM_API_KEY  = "<from-secret-store>"
$env:SAFEGUARD_LLM_MODEL    = "qwen3-32b"
```

Secrets are read from the environment only — never inline them in config files.

---

## 8. Command reference

| Command | Purpose |
|---|---|
| `safeguard scope-check --roe roe.yaml <target> [--path /p]` | Check one target against the ROE allowlist/exclusions |
| `safeguard run --roe roe.yaml --phase recon [--plan ...] [--wordlist ...] [--dry-run]` | Run the recon phase |
| `safeguard run --roe roe.yaml --phase scan [--plan ...] [--dry-run]` | Run the vulnerability-scan phase |
| `safeguard engage --roe roe.yaml [--approve <name>] [--dry-run]` | Full planner-driven engagement + report + handoff |
| `safeguard audit-verify --roe roe.yaml` | Verify the hash-chained audit log on disk |

Common flags: `--tools tools.yaml`, `--settings settings.example.yaml`,
`--runs-dir runs`. Run any command with `-h` for full help.

---

## 9. Bash equivalents

Same commands, Unix syntax (Git Bash / the Bash tool):

```bash
cd /c/Users/rahul.rathaur/Desktop/red
python -m venv .venv && source .venv/Scripts/activate
pip install -e ".[dev]"
pytest -q

cp roe.example.yaml roe.yaml
export PYTHONPATH=.                       # if not pip-installed

python -m safeguard.cli scope-check --roe roe.yaml 10.20.30.44
python -m safeguard.cli run --roe roe.yaml --phase recon --dry-run
python -m safeguard.cli engage --roe roe.yaml --dry-run
python -m safeguard.cli audit-verify --roe roe.yaml

export SAFEGUARD_LLM_BASE_URL="https://<endpoint>/v1"
export SAFEGUARD_LLM_API_KEY="<from-secret-store>"
```

---

## 10. Notes & caveats

- Real (non-`--dry-run`) scans require the external tool binaries installed.
- The **Detection Oracle** uses an in-memory telemetry backend by default, so a
  local run shows `detection coverage: 0%` with no gaps until a live read-only
  Wazuh/WAF/EDR/PAM/DAM backend is wired.
- The sandbox is a local subprocess runner in this build (not yet the
  egress-pinned gVisor/Firecracker runner).

These are documented deployment seams, not missing features — see the
*Production cutover* section of [`IMPLEMENTATION.md`](IMPLEMENTATION.md).
