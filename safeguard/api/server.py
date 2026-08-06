"""HTTP API for website integration — all three box-testing modes.

Engagements take seconds-to-minutes (real scanners, LLM cold-starts), so scans
run as background jobs the website polls:

    POST /api/v1/scans          -> 202 {job_id, status: "queued"}
    GET  /api/v1/scans/{job_id}  -> job status; when done, the summary + report
    GET  /api/v1/scans/{job_id}/report  -> the full report.json bundle
    GET  /api/v1/modes           -> per-mode input contract (drives the UI form)
    GET  /health                 -> liveness

Only already-installed deps are used (Starlette + uvicorn). Run it with:

    python serve_api.py                 # 0.0.0.0:8000
    SAFEGUARD_API_PORT=9000 python serve_api.py
"""
from __future__ import annotations

import json
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import os

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from safeguard.api.service import (
    MODE_SPECS,
    ScanRequest,
    configure_llm_env,
    run_engagement,
)

# Configure the sovereign LLM the moment the ASGI app is imported, so the API
# reaches it exactly like run_agent.py regardless of launcher (uvicorn/gunicorn/
# serve_api.py). Without this a bare `uvicorn safeguard.api.server:app` never
# loads .env and silently falls back to the deterministic planner.
configure_llm_env()

# ---- in-memory job registry (single-process; swap for Redis/db if scaled) ----
_JOBS: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()
_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="engagement")

_ALLOWED_FIELDS = set(ScanRequest.__dataclass_fields__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set(job_id: str, **updates: Any) -> None:
    with _LOCK:
        _JOBS[job_id].update(updates)


def _execute(job_id: str, req: ScanRequest) -> None:
    _set(job_id, status="running", started_at=_now())
    try:
        result = run_engagement(req)
        _set(job_id, status=result.status, finished_at=_now(),
             result=result.as_dict())
    except Exception as exc:                       # surface, don't crash the pool
        _set(job_id, status="error", finished_at=_now(),
             error=f"{type(exc).__name__}: {exc}",
             traceback=traceback.format_exc())


# ------------------------------- routes -------------------------------------
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "redagent-api",
                         "modes": list(MODE_SPECS)})


async def modes(_: Request) -> JSONResponse:
    """The contract the website renders its form from."""
    return JSONResponse({"modes": MODE_SPECS})


async def create_scan(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return JSONResponse({"error": "request body must be valid JSON"},
                            status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "request body must be a JSON object"},
                            status_code=400)

    unknown = set(body) - _ALLOWED_FIELDS
    if unknown:
        return JSONResponse(
            {"error": f"unknown field(s): {sorted(unknown)}",
             "allowed": sorted(_ALLOWED_FIELDS)}, status_code=400)

    try:
        req = ScanRequest(**body)
        req.validate()
    except (TypeError, ValueError) as exc:
        return JSONResponse({"error": str(exc), "modes": list(MODE_SPECS)},
                            status_code=422)

    job_id = uuid.uuid4().hex
    with _LOCK:
        _JOBS[job_id] = {"job_id": job_id, "mode": req.mode,
                         "status": "queued", "created_at": _now()}
    _POOL.submit(_execute, job_id, req)
    return JSONResponse(
        {"job_id": job_id, "mode": req.mode, "status": "queued",
         "poll": f"/api/v1/scans/{job_id}"}, status_code=202)


async def get_scan(request: Request) -> JSONResponse:
    job_id = request.path_params["job_id"]
    with _LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return JSONResponse({"error": "unknown job_id"}, status_code=404)
    return JSONResponse(job)


async def get_report(request: Request) -> JSONResponse:
    job_id = request.path_params["job_id"]
    with _LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return JSONResponse({"error": "unknown job_id"}, status_code=404)
    result = job.get("result")
    if not result:
        return JSONResponse(
            {"error": f"report not ready (status={job['status']})"},
            status_code=409)
    report_json = Path(result["report_paths"].get("report.json", ""))
    if not report_json.is_file():
        return JSONResponse({"error": "report.json missing on disk"},
                            status_code=500)
    return JSONResponse(json.loads(report_json.read_text(encoding="utf-8")))


routes = [
    Route("/health", health, methods=["GET"]),
    Route("/api/v1/modes", modes, methods=["GET"]),
    Route("/api/v1/scans", create_scan, methods=["POST"]),
    Route("/api/v1/scans/{job_id}", get_scan, methods=["GET"]),
    Route("/api/v1/scans/{job_id}/report", get_report, methods=["GET"]),
]

# The website is a separate origin (its own dev server / static host), so the
# browser preflights every request here — the client sends an application/json
# content-type, which is not CORS-safelisted. Without this the integration is
# blocked client-side before a request ever reaches a route.
#
# Pinning exact ports is too brittle for local work: a dev server hops to the
# next free port (5173 -> 5174 -> ...) and the website's API base URL is
# operator-configurable. So any loopback origin is allowed by default, which
# still refuses arbitrary remote pages. Set SAFEGUARD_API_CORS_ORIGINS
# (comma-separated, or "*") to pin real origins for a deployment.
_LOOPBACK_ORIGIN_RE = r"https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?"

_configured = os.environ.get("SAFEGUARD_API_CORS_ORIGINS", "").strip()
_cors_kwargs: dict[str, Any] = (
    {"allow_origins": [o.strip() for o in _configured.split(",") if o.strip()]}
    if _configured
    else {"allow_origin_regex": _LOOPBACK_ORIGIN_RE}
)

middleware = [
    Middleware(
        CORSMiddleware,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["content-type"],
        **_cors_kwargs,
    )
]

app = Starlette(routes=routes, middleware=middleware)
