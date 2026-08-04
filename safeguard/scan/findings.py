"""Finding ledger — cross-tool deduplication and merge.

The same weakness is often reported by more than one tool (e.g. Nuclei and Nikto
both flag a missing security header). The ledger dedups on
``(asset_ref, title)`` and, on collision, keeps the **highest severity**, unions
CVE IDs and evidence refs, keeps the first non-null CVSS, and records every
contributing tool in ``raw['sources']``.
"""

from __future__ import annotations

from typing import Iterable

from safeguard.tools.schema import Finding, Severity

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingLedger:
    def __init__(self) -> None:
        self._findings: dict[tuple, Finding] = {}

    def add(self, finding: Finding) -> Finding:
        key = finding.dedup_key()
        existing = self._findings.get(key)
        if existing is None:
            finding.raw.setdefault("sources", [finding.source_tool])
            self._findings[key] = finding
            return finding
        self._merge_into(existing, finding)
        return existing

    def add_all(self, findings: Iterable[Finding]) -> None:
        for f in findings:
            self.add(f)

    @staticmethod
    def _merge_into(target: Finding, other: Finding) -> None:
        if _SEVERITY_ORDER[other.severity] > _SEVERITY_ORDER[target.severity]:
            target.severity = other.severity
        for cve in other.cve_ids:
            if cve not in target.cve_ids:
                target.cve_ids.append(cve)
        for ref in other.evidence_refs:
            if ref not in target.evidence_refs:
                target.evidence_refs.append(ref)
        for tech in other.attack_techniques:
            if tech not in target.attack_techniques:
                target.attack_techniques.append(tech)
        if target.cvss is None:
            target.cvss = other.cvss
        if target.epss is None:
            target.epss = other.epss
        sources = target.raw.setdefault("sources", [target.source_tool])
        if other.source_tool not in sources:
            sources.append(other.source_tool)

    def findings(self) -> list[Finding]:
        return sorted(
            self._findings.values(),
            key=lambda f: (-_SEVERITY_ORDER[f.severity], f.asset_ref, f.title),
        )

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self._findings.values():
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def __len__(self) -> int:
        return len(self._findings)
