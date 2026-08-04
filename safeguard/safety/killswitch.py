"""Kill switch.

One control-plane call engages it; thereafter every action in the safety
pipeline is denied and (in a full deployment) sandbox tokens are revoked. In
this Phase-1 build the token-revocation hook is a registered callback so the
sandbox runner can wire in real revocation later.
"""

from __future__ import annotations

import threading
from typing import Callable


class KillSwitch:
    def __init__(self) -> None:
        self._engaged = False
        self._lock = threading.Lock()
        self._revocation_hooks: list[Callable[[], None]] = []

    @property
    def engaged(self) -> bool:
        with self._lock:
            return self._engaged

    def register_revocation_hook(self, hook: Callable[[], None]) -> None:
        """Register a callback invoked when the switch is engaged
        (e.g. revoke sandbox egress tokens, cancel in-flight runs)."""
        with self._lock:
            self._revocation_hooks.append(hook)

    def engage(self, reason: str = "") -> None:
        with self._lock:
            if self._engaged:
                return
            self._engaged = True
            hooks = list(self._revocation_hooks)
        for hook in hooks:
            try:
                hook()
            except Exception:  # never let a hook failure block the halt
                pass

    def reset(self) -> None:
        """Explicit operator reset (control-plane, RBAC-gated in production)."""
        with self._lock:
            self._engaged = False
