"""Load and validate the YAML contracts into typed models.

Supports ``${VAR}`` and ``${VAR:-default}`` environment expansion so secrets are
never inlined. Loading is fail-closed: any unknown tool safety class (e.g.
``destructive``) raises rather than being silently dropped.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from safeguard.config.models import (
    Budget,
    Exclusions,
    Mode,
    RulesOfEngagement,
    SafetyClass,
    ScopeSpec,
    Settings,
    TimeWindow,
    ToolSpec,
    is_loadable_class,
)

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: Any) -> Any:
    """Recursively expand ${VAR} / ${VAR:-default} in strings."""
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            var, default = m.group(1), m.group(2)
            return os.environ.get(var, default if default is not None else "")
        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _read_yaml(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"config file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"expected a mapping at top level of {p}")
    return _expand(data)


def load_roe(path: str | Path) -> RulesOfEngagement:
    data = _read_yaml(path)
    eng = data.get("engagement", {})
    scope_raw = data.get("scope", {})
    in_scope = scope_raw.get("in_scope", {}) or {}
    excl_raw = scope_raw.get("exclusions", {}) or {}
    windows_raw = (data.get("windows", {}) or {})
    budget_raw = data.get("budget", {}) or {}

    scope = ScopeSpec(
        domains=tuple(in_scope.get("domains", []) or []),
        cidrs=tuple(in_scope.get("cidrs", []) or []),
        cloud_accounts=tuple(in_scope.get("cloud_accounts", []) or []),
        repos=tuple(in_scope.get("repos", []) or []),
    )
    exclusions = Exclusions(
        hosts=tuple(excl_raw.get("hosts", []) or []),
        paths=tuple(excl_raw.get("paths", []) or []),
    )
    windows = tuple(
        TimeWindow(
            days=tuple(w.get("days", []) or []),
            start=str(w.get("start")),
            end=str(w.get("end")),
        )
        for w in (windows_raw.get("allowed", []) or [])
    )
    budget = Budget(
        max_requests_per_second_per_target=float(
            budget_raw.get("max_requests_per_second_per_target", 10)
        ),
        max_concurrency_per_target=int(
            budget_raw.get("max_concurrency_per_target", 4)
        ),
        max_total_actions=int(budget_raw.get("max_total_actions", 500)),
    )
    return RulesOfEngagement(
        engagement_id=str(eng.get("id", "")),
        owner=str(eng.get("owner", "")),
        authorised_by=str(eng.get("authorised_by", "")),
        authorisation_ref=str(eng.get("authorisation_ref", "")),
        mode=Mode(eng.get("mode", "black_box")),
        profile=str(eng.get("profile", "non_destructive")),
        scope=scope,
        exclusions=exclusions,
        timezone=str(windows_raw.get("timezone", "Asia/Kolkata")),
        windows=windows,
        approvers=tuple(data.get("approvers", []) or []),
        budget=budget,
    )


def load_tool_registry(path: str | Path) -> dict[str, ToolSpec]:
    data = _read_yaml(path)
    tools_raw = data.get("tools", {}) or {}
    known = {
        "class", "sandbox", "default_flags", "forbidden_flags",
        "backend", "template_policy", "mode",
    }
    registry: dict[str, ToolSpec] = {}
    for name, spec in tools_raw.items():
        spec = spec or {}
        cls = spec.get("class")
        if cls is None:
            raise ValueError(f"tool '{name}' has no safety class")
        if not is_loadable_class(cls):
            # Fail closed: destructive or unknown classes are never loaded.
            raise ValueError(
                f"tool '{name}' declares non-loadable class '{cls}'; "
                "only passive / active-recon / active-validate are permitted"
            )
        registry[name] = ToolSpec(
            name=name,
            safety_class=SafetyClass(cls),
            sandbox=str(spec.get("sandbox", "none")),
            default_flags=tuple(spec.get("default_flags", []) or []),
            forbidden_flags=tuple(spec.get("forbidden_flags", []) or []),
            backend=spec.get("backend"),
            template_policy=spec.get("template_policy"),
            mode=spec.get("mode"),
            extra={k: v for k, v in spec.items() if k not in known},
        )
    return registry


def load_settings(path: str | Path) -> Settings:
    data = _read_yaml(path)
    llm = data.get("llm", {}) or {}
    oracle = data.get("detection_oracle", {}) or {}
    sandbox = data.get("sandbox", {}) or {}
    limits = data.get("limits", {}) or {}
    audit = data.get("audit", {}) or {}
    nv = (llm.get("numeric_verifier", {}) or {})
    return Settings(
        llm_model=str(llm.get("model", "qwen3-32b")),
        llm_base_url=llm.get("base_url") or None,
        llm_api_key_env=str(llm.get("api_key_env", "SAFEGUARD_LLM_API_KEY")),
        correlation_window_seconds=int(oracle.get("correlation_window_seconds", 300)),
        global_kill_switch_enabled=bool(limits.get("global_kill_switch_enabled", True)),
        default_max_actions=int(limits.get("default_max_actions", 500)),
        sandbox_runtime=str(sandbox.get("runtime", "gvisor")),
        sandbox_egress=str(sandbox.get("egress", "roe-pinned")),
        numeric_verifier_enabled=bool(nv.get("enabled", True)),
        audit_backend=str(audit.get("backend", "append_only_hash_chain")),
        raw=data,
    )
