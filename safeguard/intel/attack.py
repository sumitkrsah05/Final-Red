"""MITRE ATT&CK technique mapping (local).

Maps a finding to ATT&CK techniques using local keyword rules (the offline STIX
bundle stand-in). No runtime call to attack.mitre.org. Rules load from
``config/intel/attack_map.yaml``; a built-in default set is used if the file is
absent so the mapper always works.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from safeguard.tools.schema import Finding

_DEFAULT_PATH = Path("config/intel/attack_map.yaml")

_BUILTIN_RULES = [
    {"match": ["exposed", "manager", "public-facing", "default credential"],
     "technique_id": "T1190", "name": "Exploit Public-Facing Application",
     "tactic": "Initial Access"},
    {"match": ["xss", "cross-site scripting", "reflected"],
     "technique_id": "T1189", "name": "Drive-by Compromise",
     "tactic": "Initial Access"},
    {"match": ["sql injection", "sqli", "injection point"],
     "technique_id": "T1190", "name": "Exploit Public-Facing Application",
     "tactic": "Initial Access"},
    {"match": ["port", "service", "nmap"], "technique_id": "T1046",
     "name": "Network Service Discovery", "tactic": "Discovery"},
    {"match": ["directory", "content discovery", "gobuster"],
     "technique_id": "T1595", "name": "Active Scanning",
     "tactic": "Reconnaissance"},
    {"match": ["rce", "remote code execution", "log4shell", "ghostcat"],
     "technique_id": "T1203", "name": "Exploitation for Client Execution",
     "tactic": "Execution"},
]

# Ordering of ATT&CK tactics along a kill chain (for path ordering).
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str

    def as_dict(self) -> dict:
        return {"technique_id": self.technique_id, "name": self.name,
                "tactic": self.tactic}


class AttackMap:
    def __init__(self, rules: Optional[list[dict]] = None) -> None:
        self._rules = rules or _BUILTIN_RULES

    @classmethod
    def from_file(cls, path: str | Path = _DEFAULT_PATH) -> "AttackMap":
        p = Path(path)
        if not p.is_file():
            return cls(_BUILTIN_RULES)
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(data.get("rules", _BUILTIN_RULES))

    def map_finding(self, finding: Finding) -> list[Technique]:
        haystack = " ".join([
            finding.title or "", finding.description or "",
            " ".join(str(t) for t in (finding.raw.get("tags") or [])),
            finding.source_tool or "",
        ]).lower()
        seen: dict[str, Technique] = {}
        for rule in self._rules:
            if any(kw.lower() in haystack for kw in rule.get("match", [])):
                t = Technique(rule["technique_id"], rule["name"], rule["tactic"])
                seen[t.technique_id] = t
        return list(seen.values())

    @staticmethod
    def tactic_rank(tactic: str) -> int:
        return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)
