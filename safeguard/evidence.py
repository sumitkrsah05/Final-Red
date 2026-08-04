"""Content-addressed evidence store.

Raw tool output, request/response captures and validation proof are stored by
SHA-256 of their content, so a `Finding`/`Validation` can carry a stable,
tamper-evident pointer (the ref changes if the content changes). In-memory by
default; if a directory is given, artifacts are also written to disk
(India-resident evidence store in the full deployment).

DPDP note: captures are raw tool output. Callers must avoid storing personal
data payloads; evidence is proof-of-signal, not data exfiltration.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional


class EvidenceStore:
    def __init__(self, directory: Optional[str | Path] = None) -> None:
        self._dir = Path(directory) if directory else None
        self._mem: dict[str, str] = {}
        if self._dir is not None:
            self._dir.mkdir(parents=True, exist_ok=True)

    def put(self, content: str) -> str:
        ref = "ev-" + hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        self._mem[ref] = content
        if self._dir is not None:
            path = self._dir / f"{ref}.txt"
            if not path.exists():
                path.write_text(content, encoding="utf-8")
        return ref

    def get(self, ref: str) -> Optional[str]:
        if ref in self._mem:
            return self._mem[ref]
        if self._dir is not None:
            path = self._dir / f"{ref}.txt"
            if path.is_file():
                return path.read_text(encoding="utf-8")
        return None
