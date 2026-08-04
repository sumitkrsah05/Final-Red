"""Local NVD/CVE mirror.

CVE lookups hit an internal, India-resident mirror — never nvd.nist.gov at
runtime. The mirror is a JSON map ``{cve_id: {cvss, epss, cwe, description,
references}}`` kept fresh by an out-of-band sync job (not part of the agent's
runtime path). Lookups are the only interface the agent uses, preserving
sovereignty and offline operation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_DEFAULT_PATH = Path("config/intel/nvd.sample.json")


@dataclass(frozen=True)
class CVERecord:
    cve_id: str
    cvss: Optional[float] = None
    epss: Optional[float] = None
    cwe: Optional[str] = None
    description: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)


class LocalNVDMirror:
    def __init__(self, records: Optional[dict[str, CVERecord]] = None) -> None:
        self._records = records or {}

    @classmethod
    def from_file(cls, path: str | Path = _DEFAULT_PATH) -> "LocalNVDMirror":
        p = Path(path)
        if not p.is_file():
            return cls({})
        data = json.loads(p.read_text(encoding="utf-8"))
        records = {
            cid.upper(): CVERecord(
                cve_id=cid.upper(),
                cvss=rec.get("cvss"),
                epss=rec.get("epss"),
                cwe=rec.get("cwe"),
                description=rec.get("description", ""),
                references=tuple(rec.get("references", []) or []),
            )
            for cid, rec in data.items()
        }
        return cls(records)

    def lookup(self, cve_id: str) -> Optional[CVERecord]:
        return self._records.get(cve_id.upper())

    def contains(self, cve_id: str) -> bool:
        return cve_id.upper() in self._records

    def __len__(self) -> int:
        return len(self._records)
