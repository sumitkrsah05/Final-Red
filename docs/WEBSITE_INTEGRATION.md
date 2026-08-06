# RedAgent API — Website Integration Guide

The RedAgent HTTP API lets a website launch safety-gated red-team engagements in
all three box-testing modes and retrieve the resulting report bundle.

Engagements run **real** scanners (nuclei, nikto, semgrep, gitleaks, trivy, …)
and can take from a few seconds (white-box) to a couple of minutes (black-box
network scan). So a scan is submitted as a **background job** the website polls.

---

## 1. Running the API

```bash
cd redAgent
python serve_api.py                                   # 0.0.0.0:8000
SAFEGUARD_API_HOST=127.0.0.1 SAFEGUARD_API_PORT=9000 python serve_api.py
```

Requirements already satisfied in the project venv: `starlette`, `uvicorn`,
`pydantic`. The scanner binaries must be on `PATH` (including `/home/sumit/go/bin`
for nuclei). Missing tools are **skipped gracefully**, not fatal.

Health check: `GET /health` → `{"status":"ok", ...}`.

---

## 2. Endpoints

| Method | Path                          | Purpose                                             |
|--------|-------------------------------|-----------------------------------------------------|
| GET    | `/health`                     | Liveness.                                            |
| GET    | `/api/v1/modes`               | Per-mode input contract — **use this to build the form**. |
| POST   | `/api/v1/scans`               | Start a scan. Returns `202 {job_id, status:"queued"}`. |
| GET    | `/api/v1/scans/{job_id}`      | Poll job status; includes the summary when finished. |
| GET    | `/api/v1/scans/{job_id}/report` | Full `report.json` bundle (findings, attack paths, coverage). |

---

## 3. What each mode expects from the user

This is the core of the integration — the fields the website must collect.
`GET /api/v1/modes` returns this same contract as JSON so the front end can
render its form dynamically.

### 3.1 Black-box — external / network  (`mode: "black_box"`)
Attack a **running** web target from the outside. No source, no credentials.

| Field | Required | Meaning |
|-------|----------|---------|
| `target` | **yes** | URL or `host[:port]` of the running app. e.g. `https://demo.testfire.net`, `http://localhost:3000`, `10.0.0.5:8080`. A non-standard port is carried through to the scanners automatically. |
| `exclusions_hosts` | no | Hosts to never touch (list of strings). |
| `exclusions_paths` | no | URL paths to never touch, e.g. `"/billing/*"`. |

Tools: `nmap` (recon) → `nuclei`, `nikto`.
**User provides: the website/URL.**

### 3.2 Gray-box — cloud / config  (`mode: "gray_box"`)
Assess cloud accounts and their configuration with partial knowledge.

| Field | Required | Meaning |
|-------|----------|---------|
| `cloud_accounts` | **yes** | List of cloud account IDs / CLI profiles to assess, e.g. `["123456789012"]`. |
| `domains` | no | In-scope domains (list). |
| `cidrs` | no | In-scope network ranges (CIDR list). |

Tools: `prowler`, `trivy`.
**User provides: the cloud account(s).**
> Needs the `prowler` binary + valid provider credentials in the **server**
> environment. Without them the run completes cleanly with zero findings.

### 3.3 White-box — source / SAST  (`mode: "white_box"`)
Static analysis of source code the server can read. Nothing needs to be running.

| Field | Required | Meaning |
|-------|----------|---------|
| `repos` | **yes** | List of **local filesystem paths** to the source under test, e.g. `["/srv/checkouts/my-app"]`. |

Tools: `semgrep`, `gitleaks`, `checkov`, `trivy`.
**User provides: the source code.** The website must place the code server-side
(upload/extract or `git clone` into a directory the API process can read) and
pass that path in `repos`. Paths are matched **exactly** against the scope.

### 3.4 Fields common to every mode
| Field | Default | Meaning |
|-------|---------|---------|
| `authorised_by` | `"operator"` | Who authorised the test (recorded in the ROE + audit chain). |
| `authorisation_ref` | auto | Ticket / approval reference. |
| `planner` | `"llm"` | `"llm"` = AI-driven rationale (needs `SAFEGUARD_LLM_BASE_URL`; **auto-falls back to `rule` if no LLM is configured**); `"rule"` = deterministic. The job result echoes which planner actually ran under `result.planner`. |
| `max_approvals` | `5` | Cap on auto-signed active-validate steps. |

---

## 4. Request / response examples

### Start a black-box scan
```bash
curl -s -XPOST http://localhost:8000/api/v1/scans \
  -H 'content-type: application/json' \
  -d '{"mode":"black_box","target":"http://localhost:3000"}'
```
```json
{ "job_id":"ea2b7f05...", "mode":"black_box", "status":"queued",
  "poll":"/api/v1/scans/ea2b7f05..." }
```

### White-box
```bash
curl -s -XPOST http://localhost:8000/api/v1/scans -H 'content-type: application/json' \
  -d '{"mode":"white_box","repos":["/srv/checkouts/my-app"]}'
```

### Gray-box
```bash
curl -s -XPOST http://localhost:8000/api/v1/scans -H 'content-type: application/json' \
  -d '{"mode":"gray_box","cloud_accounts":["123456789012"]}'
```

### Poll until done
```bash
curl -s http://localhost:8000/api/v1/scans/<job_id>
```
Status flows: `queued → running → complete` (or `interrupted` / `error`).
When `complete`, the response carries a `result` object:
```json
{
  "job_id": "ea2b7f05...",
  "mode": "black_box",
  "status": "complete",
  "result": {
    "engagement_id": "eng-api-black_box-11854d5a",
    "planner": {
      "requested": "llm", "used": "llm", "llm_configured": true,
      "model": "qwen3-32b", "reason": "LLM planner active against qwen3-32b"
    },
    "summary": {
      "findings": 19,
      "severity_counts": {"medium":1,"low":11,"info":7},
      "top_risk": 53.0,
      "attack_paths": 3,
      "validations": 0,
      "detection_coverage_pct": 0.0,
      "unavailable_tools": []
    },
    "report_paths": { "report.json":"runs-api/.../report/report.json", "...":"..." },
    "handoff_dir": "runs-api/.../handoff",
    "plan_history": [ ... ],
    "audit": { "head":"0aa9400480f8b1a5", "events":17, "intact":true }
  }
}
```

### Fetch the full report
```bash
curl -s http://localhost:8000/api/v1/scans/<job_id>/report
```
Returns the complete `report.json`: `findings[]`, `attack_paths[]`,
`detection_coverage`, `posture`, `gaps[]`, `numeric_verification`.

---

## 5. Errors

| Status | When |
|--------|------|
| `400` | Body isn't a JSON object, or contains unknown fields. |
| `422` | Missing mode-specific input (e.g. `black_box` without `target`). The message states exactly what's missing. |
| `404` | Unknown `job_id`. |
| `409` | Report requested before the job finished. |

Example:
```json
{ "error": "black_box requires 'target' (a URL or host[:port])",
  "modes": ["black_box","gray_box","white_box"] }
```

---

## 5.1 Troubleshooting

**"The scan isn't using the AI."** Check `result.planner` on a finished job.
If `used` is `"rule"` while you requested `"llm"`, `reason` says why — almost
always no LLM endpoint. Set it in the API process's environment (or the project
`.env` that `serve_api.py` loads):
```bash
export SAFEGUARD_LLM_BASE_URL="https://<sovereign-endpoint>/v1"
export SAFEGUARD_LLM_API_KEY="<key>"
```
When configured, `result.planner.used == "llm"` and `model` names the endpoint.

**"Findings are always 0."** Check `result.summary.unavailable_tools`. If it
lists a scanner (e.g. `["nuclei"]`), that binary isn't on the API process's
`PATH`, so its checks silently produced nothing. `serve_api.py` now prepends the
usual Go bin dirs (`~/go/bin`, `$GOBIN`, `$GOPATH/bin`) so nuclei is found even
under systemd/docker; if you launch the app another way, put the scanners on
`PATH` yourself. An empty `unavailable_tools` with 0 findings means the target
was genuinely clean (or unreachable from the server).

---

## 6. Safety model (what the API guarantees)

- Every request synthesises a **non-destructive** Rules-of-Engagement (ROE)
  scoped to exactly the target/repos/accounts supplied; the **scope guard
  fail-closes** on anything else at runtime.
- Only authorised targets should be submitted — the ROE is the authorisation
  contract and is recorded in a tamper-evident **audit chain** (`audit.intact`).
- Active-validate steps are approval-gated; the API auto-signs off up to
  `max_approvals` of them under the `operator` approver, and never enables any
  destructive tool class.
- Artifacts for every run are written under `runs-api/<engagement_id>/`
  (`report/`, `handoff/`, `audit.log.jsonl`, `roe.generated.yaml`).

---

## 7. Suggested website flow

1. `GET /api/v1/modes` → render a mode picker + the required field(s) for the
   chosen mode.
2. Collect input (URL / cloud accounts / repo path) → `POST /api/v1/scans`.
3. Poll `GET /api/v1/scans/{job_id}` every few seconds; show a spinner while
   `running`.
4. On `complete`, show `result.summary`; link "View full report" to
   `GET /api/v1/scans/{job_id}/report`.
5. For white-box, clone/upload the user's repo **server-side** first and pass the
   resulting path — never trust a client-supplied path to point at other data.
