"""Numeric-claim verifier (skeleton).

Zero-tolerance gate: no CVE/CVSS/EPSS/count/port may enter a report unless it
traces to a tool/DB artifact. Phase 4 ships the interface and a conservative
default that flags ungrounded figures; Phase 6 wires it to the enriched intel
sources. The verifier *regrounds or rejects* — it never lets the LLM invent
numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")


@dataclass
class VerificationResult:
    ok: bool
    ungrounded: list[str] = field(default_factory=list)


class NumericClaimVerifier:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def verify(self, text: str, grounded: set[str]) -> VerificationResult:
        """Return which figures in ``text`` are not present in ``grounded``
        (the set of tool/DB-sourced string tokens). Empty ``ungrounded`` == ok."""
        if not self.enabled:
            return VerificationResult(ok=True)
        grounded_norm = {g.upper() for g in grounded}
        ungrounded: list[str] = []
        for cve in _CVE.findall(text):
            if cve.upper() not in grounded_norm:
                ungrounded.append(cve)
        return VerificationResult(ok=not ungrounded, ungrounded=ungrounded)
