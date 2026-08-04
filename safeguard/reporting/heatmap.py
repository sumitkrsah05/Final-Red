"""ATT&CK coverage heatmap — technique × detection verdict.

Built from the Oracle's per-action detection results: for each ATT&CK technique
exercised, how often was it DETECTED / PARTIAL / MISSED / BLOCKED. This is the
one-glance answer to "which attacker behaviours would we catch?".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from safeguard.intel.attack import AttackMap

_VERDICTS = ["BLOCKED", "DETECTED", "PARTIAL", "MISSED"]


@dataclass
class AttackHeatmap:
    #: technique_id -> {verdict: count}
    cells: dict[str, dict[str, int]] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    tactics: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_detections(cls, detections: list[dict],
                        attack: AttackMap | None = None) -> "AttackHeatmap":
        hm = cls()
        # Best-effort technique names from the local ATT&CK rules.
        rule_names, rule_tactics = _rule_index(attack or AttackMap())
        for d in detections:
            tech = d.get("technique") or "unknown"
            verdict = d.get("verdict", "MISSED")
            cell = hm.cells.setdefault(tech, {v: 0 for v in _VERDICTS})
            cell[verdict] = cell.get(verdict, 0) + 1
            if tech in rule_names:
                hm.names[tech] = rule_names[tech]
                hm.tactics[tech] = rule_tactics[tech]
        return hm

    def covered_pct(self) -> float:
        total = covered = 0
        for cell in self.cells.values():
            for v, n in cell.items():
                total += n
                if v in ("DETECTED", "BLOCKED"):
                    covered += n
        return round(100.0 * covered / total, 1) if total else 0.0

    def to_markdown(self) -> str:
        if not self.cells:
            return "_No emulated actions to score._"
        lines = ["| Technique | Tactic | " + " | ".join(_VERDICTS) + " |",
                 "|---|---|" + "|".join(["---"] * len(_VERDICTS)) + "|"]
        for tech in sorted(self.cells):
            cell = self.cells[tech]
            name = self.names.get(tech, "")
            label = f"{tech} {name}".strip()
            tactic = self.tactics.get(tech, "-")
            row = " | ".join(str(cell.get(v, 0)) for v in _VERDICTS)
            lines.append(f"| {label} | {tactic} | {row} |")
        return "\n".join(lines)


def _rule_index(attack: AttackMap) -> tuple[dict, dict]:
    names, tactics = {}, {}
    for rule in getattr(attack, "_rules", []):
        tid = rule.get("technique_id")
        if tid:
            names[tid] = rule.get("name", "")
            tactics[tid] = rule.get("tactic", "")
    return names, tactics
