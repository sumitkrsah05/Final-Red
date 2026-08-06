"""Sovereign LLM client — OpenAI-compatible, env-driven, offline-safe.

Talks to the ESDS sovereign Qwen endpoint (``SAFEGUARD_LLM_*``). Uses only the
standard library (``urllib``) so there is no foreign SDK dependency in the
default build. Per-node inference profiles carry reasoning on/off and
temperature (planner reasons; extraction nodes are cheap and deterministic).

The client never runs tools and never sees secrets from config files — the API
key is read from the environment at call time.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from safeguard.config.models import Settings


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class NodeProfile:
    reasoning: bool = False
    temperature: float = 0.0
    max_tokens: int = 1024


# Sensible defaults mirroring settings.example.yaml per_node_profiles.
PROFILES = {
    "planner": NodeProfile(reasoning=True, temperature=0.2, max_tokens=4096),
    "extract": NodeProfile(reasoning=False, temperature=0.0, max_tokens=1024),
    "reporter": NodeProfile(reasoning=True, temperature=0.3, max_tokens=2048),
}


class LLMClient:
    def __init__(
        self,
        *,
        model: str,
        base_url: Optional[str],
        api_key_env: str = "SAFEGUARD_LLM_API_KEY",
        timeout: float = 180.0,   # tolerate serverless cold starts (Modal scale-to-zero)
    ) -> None:
        self.model = model
        self.base_url = (base_url or "").rstrip("/")
        self.api_key_env = api_key_env
        self.timeout = timeout

    @classmethod
    def from_settings(cls, settings: Settings) -> "LLMClient":
        return cls(model=settings.llm_model, base_url=settings.llm_base_url,
                   api_key_env=settings.llm_api_key_env)

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    def chat(
        self,
        messages: list[dict],
        *,
        node: str = "planner",
        profile: Optional[NodeProfile] = None,
        response_json: bool = False,
    ) -> str:
        if not self.configured:
            raise LLMError(
                "LLM base_url not configured (set SAFEGUARD_LLM_BASE_URL); "
                "use RulePlanner for offline/dev runs"
            )
        prof = profile or PROFILES.get(node, PROFILES["extract"])
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": prof.temperature,
            "max_tokens": prof.max_tokens,
        }
        # Qwen hybrid-thinking toggle. vLLM applies it via the top-level
        # ``chat_template_kwargs`` field (the older ``extra_body`` form is
        # silently ignored by the server, which is why it must live here).
        payload["chat_template_kwargs"] = {"enable_thinking": prof.reasoning}
        if response_json:
            payload["response_format"] = {"type": "json_object"}

        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.environ.get(self.api_key_env, '')}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise LLMError(f"LLM request failed: {exc}") from exc
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected LLM response shape: {exc}") from exc
        # Reasoning models can return a null/empty content when the token budget
        # is spent on the thinking trace (finish_reason == "length"). Treat that
        # as a failed call so callers fall back rather than crash on json.loads.
        if not content:
            finish = (body["choices"][0] or {}).get("finish_reason")
            raise LLMError(f"empty LLM content (finish_reason={finish})")
        return content
