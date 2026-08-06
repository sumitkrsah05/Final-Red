"""Nikto adapter — web server misconfiguration / exposure checks.

Runs Nikto and normalises each reported item into a ``Finding``. Nikto does not
emit a severity, so findings default to ``low`` (informational server-hygiene
issues) with the OSVDB/reference carried in ``raw``. Tuning is left at Nikto's
default (non-destructive) checks, bounded by ``-maxtime`` from tools.yaml.

Output format: Nikto's JSON writer needs Perl's ``JSON.pm``, which is often
absent, so we drive the always-available XML writer (``-Format xml -output -``)
and parse that. Legacy JSON output is still parsed if present, so fixtures and
JSON-capable installs keep working.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Finding, Severity, ToolResult, ToolStatus

# Nikto v2.1.x can leak stringified Perl references (e.g. "HASH(0x55...)",
# "SCALAR(0x...)") into host/URI fields. Strip them so asset refs stay clean.
_PERL_REF = re.compile(r"(?:HASH|SCALAR|ARRAY|CODE|REF|GLOB)\(0x[0-9a-fA-F]+\)")


def _clean(value: str) -> str:
    return _PERL_REF.sub("", value or "").strip()


class NiktoAdapter(ToolAdapter):
    default_image = "scan-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        cmd = ["nikto", "-Format", "xml", "-output", "-", "-nointeractive",
               *self.spec.default_flags]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        cmd += ["-host", invocation.target]
        return cmd

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, exit_code=result.exit_code,
                              error="nikto timed out")
        out = result.stdout.strip()
        findings: list[Finding] = []
        if out.startswith("<"):
            findings = self._parse_xml(out, invocation.target)
        elif out:
            data = self._load(out)
            for host in self._hosts(data):
                target_host = host.get("host") or invocation.target
                for vuln in host.get("vulnerabilities", []) or []:
                    findings.append(self._to_finding(target_host, vuln))
        status = ToolStatus.OK if findings else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, findings=findings)

    def _parse_xml(self, out: str, target: str) -> list[Finding]:
        try:
            root = ET.fromstring(out)
        except ET.ParseError:
            return []
        findings: list[Finding] = []
        for details in root.iter("scandetails"):
            host = _clean(details.get("targethostname") or details.get("sitename")
                          or target) or target
            for item in details.iter("item"):
                findings.append(self._to_finding(host, {
                    "msg": (item.findtext("description") or "").strip(),
                    "url": (item.findtext("uri") or "").strip(),
                    "id": item.get("id"),
                    "OSVDB": item.get("osvdbid"),
                    "method": item.get("method"),
                }))
        # Some builds put <item> at the top level rather than under scandetails.
        if not findings:
            for item in root.iter("item"):
                findings.append(self._to_finding(target, {
                    "msg": (item.findtext("description") or "").strip(),
                    "url": (item.findtext("uri") or "").strip(),
                    "id": item.get("id"), "OSVDB": item.get("osvdbid"),
                    "method": item.get("method"),
                }))
        return [f for f in findings if f.title]

    @staticmethod
    def _load(out: str):
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            # Some Nikto builds emit one JSON object per scanned host per line.
            objs = []
            for line in out.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        objs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return objs

    @staticmethod
    def _hosts(data):
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("host") if isinstance(data.get("host"), list) else [data]
        return []

    @staticmethod
    def _to_finding(host: str, vuln: dict) -> Finding:
        msg = vuln.get("msg") or vuln.get("message") or "nikto finding"
        host = _clean(host)
        url = _clean(vuln.get("url") or vuln.get("uri") or "")
        asset_ref = f"{host}{url}" if url and not url.startswith("http") else (url or host)
        return Finding(
            title=msg[:120],
            asset_ref=asset_ref or host,
            source_tool="nikto",
            severity=Severity.LOW,
            description=msg,
            raw={"id": vuln.get("id"), "osvdb": vuln.get("OSVDB"),
                 "method": vuln.get("method"), "url": url},
        )
