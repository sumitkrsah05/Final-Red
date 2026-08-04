"""Finding enrichment — grounded, sovereign.

For each finding: attach CVE detail from the local NVD mirror (CVSS/EPSS/CWE),
map ATT&CK techniques, and compute a risk score that folds in detection status.
Returns the set of **grounded tokens** (every CVE and numeric figure sourced
from a tool or the mirror) so the numeric-claim verifier can reject anything the
LLM invents later.

Numbers only ever come from artifacts here: CVSS/EPSS from the mirror, CVE IDs
from the tool that reported them. The enricher never fabricates a figure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from safeguard.intel.attack import AttackMap
from safeguard.intel.nvd import LocalNVDMirror
from safeguard.intel.risk import RiskScorer
from safeguard.tools.schema import Finding, Severity


@dataclass
class EnrichmentResult:
    grounded_tokens: set[str] = field(default_factory=set)
    enriched: int = 0
    cve_hits: int = 0
    cve_misses: list[str] = field(default_factory=list)


class Enricher:
    def __init__(self, nvd: Optional[LocalNVDMirror] = None,
                 attack: Optional[AttackMap] = None,
                 scorer: Optional[RiskScorer] = None) -> None:
        self.nvd = nvd or LocalNVDMirror.from_file()
        self.attack = attack or AttackMap.from_file()
        self.scorer = scorer or RiskScorer()

    def enrich(
        self,
        findings: list[Finding],
        *,
        detection_status: Optional[dict[str, str]] = None,
        asset_criticality: Optional[dict[str, float]] = None,
    ) -> EnrichmentResult:
        detection_status = detection_status or {}
        asset_criticality = asset_criticality or {}
        res = EnrichmentResult()

        for f in findings:
            # CVE enrichment (grounded by the mirror).
            best_cvss = f.cvss
            best_epss = f.epss
            for cve in f.cve_ids:
                res.grounded_tokens.add(cve.upper())  # CVE came from a tool
                rec = self.nvd.lookup(cve)
                if rec is None:
                    res.cve_misses.append(cve.upper())
                    continue
                res.cve_hits += 1
                if rec.cvss is not None:
                    best_cvss = rec.cvss if best_cvss is None else max(best_cvss, rec.cvss)
                    res.grounded_tokens.add(_fmt(rec.cvss))
                if rec.epss is not None:
                    best_epss = rec.epss if best_epss is None else max(best_epss, rec.epss)
                    res.grounded_tokens.add(_fmt(rec.epss))
                if rec.description and not f.description:
                    f.description = rec.description
            f.cvss = best_cvss
            f.epss = best_epss

            # ATT&CK mapping.
            techniques = self.attack.map_finding(f)
            for t in techniques:
                if t.technique_id not in f.attack_techniques:
                    f.attack_techniques.append(t.technique_id)
                res.grounded_tokens.add(t.technique_id)

            # Risk (detection-aware).
            status = detection_status.get(f.asset_ref, "UNKNOWN")
            crit = asset_criticality.get(f.asset_ref, 0.5)
            risk = self.scorer.score(cvss=f.cvss, epss=f.epss, severity=f.severity,
                                     asset_criticality=crit, detection_status=status)
            f.raw["risk"] = {"score": risk.score, "priority": risk.priority,
                             "factors": risk.factors}
            f.raw["attack_techniques"] = [t.as_dict() for t in techniques]
            res.enriched += 1

        return res


def _fmt(x: float) -> str:
    # Normalise numeric grounding tokens (trailing-zero agnostic).
    return ("%g" % x)
