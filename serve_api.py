"""Launch the RedAgent HTTP API for website integration.

    python serve_api.py                       # 0.0.0.0:8000
    SAFEGUARD_API_HOST=127.0.0.1 SAFEGUARD_API_PORT=9000 python serve_api.py

Loads the nearest .env (so the optional LLM planner is configured if present),
then serves the Starlette app defined in ``safeguard.api.server``.
"""
from __future__ import annotations

import os
from pathlib import Path

import uvicorn


def load_dotenv() -> None:
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
        return


def ensure_scanner_path() -> None:
    """Make Go-installed scanners (e.g. nuclei in ~/go/bin) discoverable.

    Launched from an interactive shell the user's PATH already has them, but
    under systemd / docker / cron the process inherits a minimal PATH and the
    binary lookup fails — which the engine reports as a *clean* scan (zero
    findings) rather than an error. Prepend the usual Go bin dirs so black-box
    scans actually run nuclei/nikto/nmap.
    """
    candidates = [
        os.environ.get("GOBIN"),
        f"{os.environ['GOPATH']}/bin" if os.environ.get("GOPATH") else None,
        os.path.expanduser("~/go/bin"),
        "/usr/local/go/bin",
        "/usr/local/bin",
    ]
    parts = os.environ.get("PATH", "").split(os.pathsep)
    for cand in candidates:
        if cand and os.path.isdir(cand) and cand not in parts:
            parts.insert(0, cand)
    os.environ["PATH"] = os.pathsep.join(parts)


def main() -> None:
    load_dotenv()
    ensure_scanner_path()
    base = os.environ.get("SAFEGUARD_LLM_BASE_URL", "").rstrip("/")
    if base and not base.endswith("/v1"):
        os.environ["SAFEGUARD_LLM_BASE_URL"] = base + "/v1"

    host = os.environ.get("SAFEGUARD_API_HOST", "0.0.0.0")
    port = int(os.environ.get("SAFEGUARD_API_PORT", "8000"))
    print(f"RedAgent API on http://{host}:{port}  (modes: black_box, gray_box, white_box)")
    uvicorn.run("safeguard.api.server:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
