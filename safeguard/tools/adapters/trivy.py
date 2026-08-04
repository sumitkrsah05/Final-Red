"""Trivy adapter — dependency / container / IaC scanning (active-recon).

Scans a filesystem, image, or config target (``params['scan_type']`` ∈
``fs|image|config``, default ``fs``) and normalises vulnerabilities into
``Finding`` records with CVE IDs and severity. Non-destructive: it inspects, it
does not exploit.
"""

from __future__ import annotations

import json

from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Finding, Severity, ToolResult, ToolStatus

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNKNOWN": Severity.INFO}
_SCAN_TYPES = {"fs", "image", "config", "repo"}


class TrivyAdapter(ToolAdapter):
    default_image = "scan-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        scan_type = str(invocation.params.get("scan_type", "fs"))
        if scan_type not in _SCAN_TYPES:
            scan_type = "fs"
        cmd = ["trivy", scan_type, "--format", "json", "--quiet",
               *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        cmd.append(invocation.target)
        return cmd

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, error="trivy timed out")
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            data = {}
        findings: list[Finding] = []
        for res in data.get("Results", []) or []:
            where = res.get("Target", invocation.target)
            for vuln in res.get("Vulnerabilities", []) or []:
                cve = vuln.get("VulnerabilityID", "")
                sev = _SEV.get(str(vuln.get("Severity", "UNKNOWN")).upper(),
                               Severity.INFO)
                cvss = _cvss(vuln)
                findings.append(Finding(
                    title=f"{cve} in {vuln.get('PkgName', where)}",
                    asset_ref=f"{invocation.target}:{vuln.get('PkgName', '')}",
                    source_tool=self.name, severity=sev,
                    description=vuln.get("Title", ""),
                    cve_ids=[cve] if cve.upper().startswith("CVE-") else [],
                    cvss=cvss,
                    raw={"pkg": vuln.get("PkgName"),
                         "installed": vuln.get("InstalledVersion"),
                         "fixed": vuln.get("FixedVersion")}))
        status = ToolStatus.OK if findings else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, findings=findings)


def _cvss(vuln: dict):
    cvss = vuln.get("CVSS") or {}
    for src in ("nvd", "redhat"):
        entry = cvss.get(src) or {}
        score = entry.get("V3Score") or entry.get("V2Score")
        if score is not None:
            return float(score)
    return None
