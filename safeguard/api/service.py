"""Engagement service — turn a website request into a real, safety-gated run.

This is the framework-agnostic core behind the HTTP API. Given a validated
:class:`ScanRequest` it (1) synthesises an authorisation ROE from the request,
(2) builds the safety-gated engagement, (3) drives the planner→recon→scan→
correlate→(gated validate)→report graph for the requested box-testing mode, and
(4) returns a compact, JSON-serialisable summary plus the on-disk report bundle.

Mode → what the caller must supply (see ``MODE_SPECS`` — also served verbatim
at ``GET /api/v1/modes`` so the website can render its own form):

* ``black_box``  — a target URL or ``host[:port]`` (network scan: nuclei, nikto)
* ``gray_box``   — one or more cloud accounts (config scan: prowler, trivy)
* ``white_box``  — one or more local source paths (SAST/secrets/IaC: semgrep,
                   gitleaks, checkov, trivy)

Nothing here trusts the caller for authorisation beyond the ROE it generates:
the scope guard still fail-closes on any target outside the synthesised scope.
"""
from __future__ import annotations

import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from safeguard.engagement import Engagement
from safeguard.graph.checkpoint import SqliteCheckpointer
from safeguard.integration.act import ActIntegration
from safeguard.integration.detect import DetectIntegration
from safeguard.orchestrator import Orchestrator
from safeguard.reporting.report import Reporter
from safeguard.safety.approvals import ApprovalDecision

def configure_llm_env() -> None:
    """Load the nearest ``.env`` and normalise the LLM base URL to end in ``/v1``.

    This is why the CLI driver (``run_agent.py``) reaches the sovereign LLM but a
    bare ``uvicorn safeguard.api.server:app`` did not: the CLI loads ``.env`` and
    fixes the URL itself, while the API used to rely on ``serve_api.py`` having
    done it. Doing it here — at import of the ASGI app — makes the API configure
    the LLM identically no matter how it is launched (uvicorn, gunicorn, tests).

    ``os.environ`` already set wins (an explicit export overrides the file), so
    this never clobbers a deliberately-configured environment.
    """
    here = Path(__file__).resolve()
    for base in (here.parent, *here.parents):
        env_path = base / ".env"
        if not env_path.is_file():
            continue
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))
        break
    # vLLM serves the OpenAI API under /v1; a base_url without it 404s every call
    # (LLMError -> silent rule fallback), which reads as "the agent isn't running".
    base_url = os.environ.get("SAFEGUARD_LLM_BASE_URL", "").rstrip("/")
    if base_url and not base_url.endswith("/v1"):
        os.environ["SAFEGUARD_LLM_BASE_URL"] = base_url + "/v1"


TOOLS = "tools.yaml"
SETTINGS = "settings.example.yaml"
RUNS_DIR = "runs-api"
APPROVER = "operator"            # named ROE approver used to auto-sign-off validate

# ---------------------------------------------------------------------------
# Self-describing contract — this is what the website needs from the user.
# Served as-is at GET /api/v1/modes so the front end can build its form.
# ---------------------------------------------------------------------------
MODE_SPECS: dict[str, dict[str, Any]] = {
    "black_box": {
        "title": "Black-box (external, network)",
        "summary": "Attack a running web target from the outside — no source, "
                   "no credentials.",
        "required": {
            "target": "URL or host[:port] of the running app, e.g. "
                      "'https://demo.testfire.net' or 'localhost:3000'.",
        },
        "optional": {
            "exclusions_hosts": "hosts to never touch (list of str)",
            "exclusions_paths": "URL paths to never touch, e.g. '/billing/*'",
        },
        "tools": ["nmap (recon)", "nuclei", "nikto"],
        "example": {"mode": "black_box", "target": "http://localhost:3000"},
    },
    "gray_box": {
        "title": "Gray-box (cloud / config)",
        "summary": "Assess cloud accounts and their configuration with partial "
                   "knowledge (account identifiers / profiles).",
        "required": {
            "cloud_accounts": "list of cloud account IDs or CLI profiles to "
                              "assess, e.g. ['123456789012'].",
        },
        "optional": {
            "domains": "in-scope domains (list of str)",
            "cidrs": "in-scope network ranges (list of CIDR str)",
        },
        "tools": ["prowler", "trivy"],
        "note": "Requires the prowler binary and valid provider credentials in "
                "the server environment; missing tools are skipped gracefully.",
        "example": {"mode": "gray_box", "cloud_accounts": ["123456789012"]},
    },
    "white_box": {
        "title": "White-box (source / SAST)",
        "summary": "Analyse source code the server can read — SAST, secret and "
                   "IaC scanning. No target needs to be running.",
        "required": {
            "repos": "list of local filesystem paths to the source under test, "
                     "e.g. ['/srv/checkouts/my-app'].",
        },
        "optional": {},
        "tools": ["semgrep", "gitleaks", "checkov", "trivy"],
        "note": "Paths must be readable by the server process. The website "
                "should upload/clone the repo server-side and pass its path.",
        "example": {"mode": "white_box", "repos": ["/srv/checkouts/my-app"]},
    },
}

_VALID_MODES = tuple(MODE_SPECS)

# Scanner binaries each mode drives — used for a preflight availability check so
# a scan that returns zero findings because a tool is missing from the server's
# PATH is *reported as such*, instead of silently looking like a clean target.
_MODE_TOOLS: dict[str, list[str]] = {
    "black_box": ["nmap", "nuclei", "nikto"],
    "gray_box": ["prowler", "trivy"],
    "white_box": ["semgrep", "gitleaks", "checkov", "trivy"],
}


def _unavailable_tools(mode: str) -> list[str]:
    """Scanner binaries the mode needs that are not on the server's PATH."""
    return [t for t in _MODE_TOOLS.get(mode, []) if shutil.which(t) is None]


# ---------------------------------------------------------------------------
# Request / result value objects (plain dataclasses — the HTTP layer validates).
# ---------------------------------------------------------------------------
@dataclass
class ScanRequest:
    mode: str
    target: Optional[str] = None
    repos: list[str] = field(default_factory=list)
    cloud_accounts: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    exclusions_hosts: list[str] = field(default_factory=list)
    exclusions_paths: list[str] = field(default_factory=list)
    authorised_by: str = "operator"
    authorisation_ref: Optional[str] = None
    planner: str = "llm"                 # "llm" (AI-driven; auto-falls back to rule) | "rule"
    max_approvals: int = 5

    def validate(self) -> None:
        """Fail closed on missing mode-specific inputs (raises ValueError)."""
        if self.mode not in _VALID_MODES:
            raise ValueError(
                f"mode must be one of {list(_VALID_MODES)}, got {self.mode!r}")
        if self.mode == "black_box" and not self.target:
            raise ValueError("black_box requires 'target' (a URL or host[:port])")
        if self.mode == "gray_box" and not self.cloud_accounts:
            raise ValueError("gray_box requires 'cloud_accounts' (non-empty list)")
        if self.mode == "white_box" and not self.repos:
            raise ValueError("white_box requires 'repos' (non-empty list of paths)")
        if self.planner not in ("rule", "llm"):
            raise ValueError("planner must be 'rule' or 'llm'")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "target"


def _yaml_list(items: list[str], indent: int) -> str:
    pad = " " * indent
    if not items:
        return " []"
    return "\n" + "\n".join(f'{pad}- "{i}"' for i in items)


def _build_roe(req: ScanRequest, engagement_id: str) -> str:
    """Synthesise a single, non-destructive ROE for exactly this request."""
    return f"""# AUTO-GENERATED by the RedAgent API — authorisation contract for this run.
engagement:
  id: "{engagement_id}"
  owner: "{APPROVER}"
  authorised_by: "{req.authorised_by}"
  authorisation_ref: "{req.authorisation_ref or ('AUTO-' + engagement_id)}"
  mode: "{req.mode}"
  profile: "non_destructive"

scope:
  in_scope:
    domains:{_yaml_list(req.domains, 6)}
    cidrs:{_yaml_list(req.cidrs, 6)}
    cloud_accounts:{_yaml_list(req.cloud_accounts, 6)}
    repos:{_yaml_list(req.repos, 6)}
  exclusions:
    hosts:{_yaml_list(req.exclusions_hosts, 6)}
    paths:{_yaml_list(req.exclusions_paths, 6)}

windows:
  timezone: "Asia/Kolkata"
  allowed:
    - days: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
      start: "00:00"
      end: "23:59"

approvers:
  - "{APPROVER}"

budget:
  max_requests_per_second_per_target: 10
  max_concurrency_per_target: 4
  max_total_actions: 500
"""


def _prepare_black_box(req: ScanRequest) -> tuple[str, str, str]:
    """Return (scope_host, scan_target, nmap_ports) for a black-box target.

    The ROE scope stays keyed on the bare host; the scope guard strips the
    :port from a target before matching, so ``http://host:port`` stays in scope
    while the web scanners still hit the right port.
    """
    raw = req.target or ""
    parsed = urlparse(raw if "://" in raw else "//" + raw)
    host = parsed.hostname
    if not host:
        raise ValueError(f"could not parse a hostname from target {raw!r}")
    if parsed.port:
        return host, f"http://{host}:{parsed.port}", f"{parsed.port},80,443"
    return host, host, "80,443"


@dataclass
class EngagementResult:
    status: str
    engagement_id: str
    mode: str
    summary: dict[str, Any]
    report_paths: dict[str, str]
    handoff_dir: str
    plan_history: list[dict[str, Any]]
    audit: dict[str, Any]
    planner: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "engagement_id": self.engagement_id,
            "mode": self.mode,
            "planner": self.planner,
            "summary": self.summary,
            "report_paths": self.report_paths,
            "handoff_dir": self.handoff_dir,
            "plan_history": self.plan_history,
            "audit": self.audit,
        }


def _make_planner(req: ScanRequest, eng: Engagement) -> tuple[Any, dict[str, Any]]:
    """Build the planner and a report of *which* one is actually driving the run.

    The LLM planner degrades to the deterministic rule planner when no endpoint
    is configured. That fallback used to be silent, which looked like "the AI is
    never called". The returned ``info`` makes it explicit (surfaced on the job
    result) so a caller can see the LLM was requested but not wired.
    """
    from safeguard.llm.planner import LLMPlanner, RulePlanner

    rule = RulePlanner(eng.registry)
    info: dict[str, Any] = {"requested": req.planner, "used": "rule",
                            "llm_configured": False, "reason": ""}
    if req.planner != "llm":
        info["reason"] = "rule planner requested"
        return rule, info

    from safeguard.llm.client import LLMClient

    client = LLMClient.from_settings(eng.settings)
    info["llm_configured"] = client.configured
    if not client.configured:      # LLM not wired -> graceful deterministic run
        info["reason"] = (
            "LLM planner requested but no endpoint is configured — set "
            "SAFEGUARD_LLM_BASE_URL (and SAFEGUARD_LLM_API_KEY); "
            "fell back to the deterministic rule planner")
        return rule, info

    info["used"] = "llm"
    info["model"] = client.model
    info["reason"] = f"LLM planner active against {client.model}"
    return LLMPlanner(client, eng.registry, fallback=rule), info


def run_engagement(req: ScanRequest, *, runs_dir: str = RUNS_DIR) -> EngagementResult:
    """Execute one engagement end-to-end and return a serialisable result.

    Blocking (spawns real scanner subprocesses); the HTTP layer runs it in a
    worker thread and exposes it as a polled job.
    """
    req.validate()

    # Black-box: carry an explicit port through to the scanners.
    scan_target = nmap_ports = None
    if req.mode == "black_box":
        host, scan_target, nmap_ports = _prepare_black_box(req)
        req.domains = [host]                       # scope = the bare host

    engagement_id = f"eng-api-{req.mode}-{_slug(uuid.uuid4().hex[:8])}"
    eng_dir = Path(runs_dir) / engagement_id
    eng_dir.mkdir(parents=True, exist_ok=True)
    roe_path = eng_dir / "roe.generated.yaml"
    roe_path.write_text(_build_roe(req, engagement_id), encoding="utf-8")

    eng = Engagement.build(
        roe_path=str(roe_path), tools_path=TOOLS, settings_path=SETTINGS,
        runs_dir=runs_dir, dry_run=False,
    )
    planner, planner_info = _make_planner(req, eng)

    # Mode-specific plans. Black-box pins the fast web path; gray/white use the
    # graph's mode defaults (prowler/trivy and semgrep/gitleaks/checkov/trivy).
    build_kwargs: dict[str, Any] = {}
    if req.mode == "black_box":
        build_kwargs.update(
            recon_plan=["nmap"],
            recon_params={"nmap": {"ports": nmap_ports}},
            scan_plan=["nuclei", "nikto"],
        )

    orch = Orchestrator.build(
        eng, planner=planner,
        checkpointer=SqliteCheckpointer(eng_dir / "checkpoints.db"),
        **build_kwargs,
    )

    init = orch.initial_state()
    if scan_target and scan_target != (req.domains[0] if req.domains else None):
        init.targets = [scan_target]

    result = orch.run(init)

    # Auto-sign-off any parked active-validate step (bounded).
    approvals = 0
    while result.status == "interrupted" and approvals < req.max_approvals:
        pa = result.state.pending_approval or {}
        orch.approve(pa["request_id"], approver=APPROVER,
                     decision=ApprovalDecision.APPROVED)
        approvals += 1
        result = orch.resume()

    st = result.state
    bundle = Reporter().build(st)
    paths = bundle.write(eng_dir / "report")
    outbox = eng_dir / "handoff"
    DetectIntegration().push(bundle.data, outbox)
    ActIntegration().push(bundle.data, outbox)

    rep = st.report or {}
    cov = rep.get("detection_coverage", {})
    unavailable = _unavailable_tools(req.mode)
    summary = {
        "assets": rep.get("assets", 0),
        "findings": rep.get("findings", 0),
        "severity_counts": rep.get("severity_counts", {}),
        "top_risk": rep.get("top_risk", 0),
        "attack_paths": len(rep.get("attack_paths", [])),
        "validations": len(st.validations),
        "detection_coverage_pct": cov.get("coverage_pct", 0),
        # Empty on a healthy server; non-empty explains a zero-finding scan
        # (a required scanner is missing from the API process's PATH).
        "unavailable_tools": unavailable,
    }
    return EngagementResult(
        status=result.status,
        engagement_id=engagement_id,
        mode=req.mode,
        summary=summary,
        report_paths={k: str(v) for k, v in paths.items()},
        handoff_dir=str(outbox),
        plan_history=list(st.plan_history),
        audit={"head": eng.audit.head[:16], "events": len(eng.audit.events()),
               "intact": eng.audit.verify()},
        planner=planner_info,
    )
