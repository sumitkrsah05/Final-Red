"""Report bundle builder & writer.

Consumes the final ``AgentState`` and produces the deliverable bundle:
``report.json`` plus four Markdown documents (executive summary, technical
report, ATT&CK coverage heatmap, detection-gap report). Written to
``runs/<engagement-id>/report/``. Narratives are grounded — every CVE is checked
by the numeric-claim verifier — and evidence is referenced by content hash.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from safeguard.intel.attack import AttackMap
from safeguard.intel.correlate import _asset_root as _root
from safeguard.llm.verifier import NumericClaimVerifier
from safeguard.oracle.coverage import CoverageMatrix
from safeguard.oracle.models import DetectionResult, Verdict
from safeguard.reporting.heatmap import AttackHeatmap

# Expected-but-absent detection guidance, per technique — the Detect/Act hint.
EXPECTED_DETECTION = {
    "T1046": "SIEM rule for port-scan bursts (e.g. Wazuh rule 86601)",
    "T1595": "SIEM/WAF rule for content-discovery (bursts of 404s / dir brute)",
    "T1190": "WAF CRS rule + SIEM alert for public-facing app exploitation",
    "T1189": "WAF/CRS rule + SIEM alert for reflected-XSS patterns",
    "T1203": "EDR behavioural rule + SIEM alert for exploitation/RCE",
}


@dataclass
class ReportBundle:
    data: dict = field(default_factory=dict)
    documents: dict[str, str] = field(default_factory=dict)  # filename -> content

    def write(self, out_dir: str | Path) -> dict[str, str]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        import json
        paths: dict[str, str] = {}
        (out / "report.json").write_text(
            json.dumps(self.data, indent=2, default=str), encoding="utf-8")
        paths["report.json"] = str(out / "report.json")
        for name, content in self.documents.items():
            (out / name).write_text(content, encoding="utf-8")
            paths[name] = str(out / name)
        return paths


class Reporter:
    def __init__(self, attack: Optional[AttackMap] = None,
                 verifier: Optional[NumericClaimVerifier] = None) -> None:
        self.attack = attack or AttackMap.from_file()
        self.verifier = verifier or NumericClaimVerifier()

    def build(self, state) -> ReportBundle:
        findings = state.ledger.findings()
        status = state.detection_status
        coverage = self._coverage(state.detections)
        heatmap = AttackHeatmap.from_detections(state.detections, self.attack)

        grounded = set(state.grounded_tokens)
        cve_text = " ".join(c for f in findings for c in f.cve_ids)
        verdict = self.verifier.verify(cve_text, grounded)

        rows = [self._finding_row(f, status) for f in findings]
        gaps = self._gap_rows(coverage)
        # Per (technique, host) verdict index — the key for regression diffing.
        detection_index = {
            f"{d.get('technique') or 'unknown'}|{_root(d['target'])}": d["verdict"]
            for d in state.detections}

        data = {
            "engagement_id": state.engagement_id,
            "mode": state.mode,
            "posture": {
                "assets": len(state.inventory),
                "findings": len(findings),
                "severity_counts": state.ledger.by_severity(),
                "top_risk": max((r["risk"] for r in rows), default=0.0),
            },
            "detection_coverage": coverage.summary(),
            "detection_index": detection_index,
            "attack_coverage_pct": heatmap.covered_pct(),
            "findings": rows,
            "attack_paths": state.attack_paths,
            "validations": state.validations,
            "gaps": gaps,
            "numeric_verification": {"ok": verdict.ok,
                                     "ungrounded": verdict.ungrounded},
        }
        documents = {
            "executive_summary.md": self._executive(data),
            "technical_report.md": self._technical(data),
            "attack_heatmap.md": self._heatmap_doc(heatmap),
            "detection_gap_report.md": self._gap_doc(gaps, coverage),
        }
        return ReportBundle(data=data, documents=documents)

    # -- assembly --------------------------------------------------------
    @staticmethod
    def _coverage(detections: list[dict]) -> CoverageMatrix:
        m = CoverageMatrix()
        for d in detections:
            m.add(DetectionResult(
                action_ref=d["action_ref"], target=d["target"],
                technique=d.get("technique"), verdict=Verdict(d["verdict"]),
                source=d.get("source", "aggregate"), rule_id=d.get("rule_id"),
                ttd_seconds=d.get("ttd_seconds")))
        return m

    def _finding_row(self, f, status: dict) -> dict:
        risk = (f.raw.get("risk") or {})
        return {
            "id": f.id, "title": f.title, "severity": f.severity.value,
            "asset": f.asset_ref, "cve_ids": f.cve_ids, "cvss": f.cvss,
            "epss": f.epss, "techniques": f.attack_techniques,
            "detection": status.get(_root(f.asset_ref), "UNKNOWN"),
            "risk": risk.get("score", 0.0), "priority": risk.get("priority", "info"),
            "sources": f.raw.get("sources", [f.source_tool]),
        }

    def _gap_rows(self, coverage: CoverageMatrix) -> list[dict]:
        rows = []
        for g in coverage.gaps():
            tech = g.get("technique") or "unknown"
            rows.append({**g, "expected_detection":
                         EXPECTED_DETECTION.get(tech,
                                                "author a detection for this technique")})
        return rows

    # -- markdown --------------------------------------------------------
    @staticmethod
    def _executive(d: dict) -> str:
        cov = d["detection_coverage"]
        p = d["posture"]
        lines = [
            f"# Executive Summary — {d['engagement_id']}",
            "",
            f"**Mode:** {d['mode']} · **Profile:** non-destructive",
            "",
            "## Posture",
            f"- Assets discovered: **{p['assets']}**",
            f"- Findings: **{p['findings']}** (by severity: {p['severity_counts']})",
            f"- Highest risk score: **{p['top_risk']}**",
            "",
            "## Detection posture (the purple-team result)",
            f"- Detection coverage: **{cov['coverage_pct']}%** "
            f"of {cov['total_actions']} emulated actions",
            f"- Mean time-to-detect: **{cov['mean_ttd_seconds']} s**",
            f"- ATT&CK technique coverage: **{d['attack_coverage_pct']}%**",
            f"- Detection gaps (MISSED/PARTIAL): **{len(d['gaps'])}**",
            "",
            "> The value is not just the findings — it is *which attacker "
            "behaviours your stack would miss*, with the rules to add "
            "(see the detection-gap report).",
        ]
        if not d["numeric_verification"]["ok"]:
            lines += ["", f"> ⚠ ungrounded figures flagged: "
                      f"{d['numeric_verification']['ungrounded']}"]
        return "\n".join(lines)

    @staticmethod
    def _technical(d: dict) -> str:
        lines = [f"# Technical Report — {d['engagement_id']}", "",
                 "## Findings", ""]
        if not d["findings"]:
            lines.append("_No findings._")
        else:
            lines += ["| Severity | Priority | Risk | Detection | Title | Asset | "
                      "CVEs | ATT&CK | Sources |",
                      "|---|---|---|---|---|---|---|---|---|"]
            for f in sorted(d["findings"], key=lambda x: -x["risk"]):
                lines.append(
                    f"| {f['severity']} | {f['priority']} | {f['risk']} | "
                    f"{f['detection']} | {f['title']} | {f['asset']} | "
                    f"{', '.join(f['cve_ids']) or '-'} | "
                    f"{', '.join(f['techniques']) or '-'} | "
                    f"{', '.join(f['sources'])} |")
        if d["validations"]:
            lines += ["", "## Validations (gated, non-destructive)", ""]
            for v in d["validations"]:
                lines.append(
                    f"- **{v.get('tool')}** on `{v.get('target')}` — "
                    f"{v.get('result')} (approved by {v.get('approved_by')}, "
                    f"evidence: `{v.get('evidence_ref')}`)")
        if d["attack_paths"]:
            lines += ["", "## Candidate attack paths", ""]
            for p in d["attack_paths"]:
                steps = " → ".join(
                    f"{s.get('technique_id') or '?'}({s.get('detection')})"
                    for s in p["steps"])
                lines.append(f"- `{p['asset']}` (risk {p['overall_risk']}): {steps}")
        return "\n".join(lines)

    @staticmethod
    def _heatmap_doc(heatmap: AttackHeatmap) -> str:
        return "\n".join([
            "# ATT&CK Coverage Heatmap",
            "",
            f"Technique coverage: **{heatmap.covered_pct()}%** "
            "(DETECTED or BLOCKED).",
            "",
            heatmap.to_markdown(),
        ])

    @staticmethod
    def _gap_doc(gaps: list[dict], coverage: CoverageMatrix) -> str:
        lines = ["# Detection-Gap Report", "",
                 "The Detect/Act handoff: every action the Blue Team stack did "
                 "**not** fully catch, with the expected detection to add.", "",
                 f"Coverage: **{coverage.coverage_pct()}%** · "
                 f"gaps: **{len(gaps)}**", ""]
        if not gaps:
            lines.append("_No gaps — every emulated action was detected or blocked._")
            return "\n".join(lines)
        lines += ["| Verdict | Technique | Target | Action | Expected detection |",
                  "|---|---|---|---|---|"]
        for g in gaps:
            lines.append(
                f"| {g['verdict']} | {g.get('technique') or '-'} | {g['target']} | "
                f"{g['action_ref']} | {g['expected_detection']} |")
        return "\n".join(lines)
