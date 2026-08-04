"""Nuclei adapter — templated vulnerability detection (non-destructive).

Enforces the ``safe-only`` template policy from ``tools.yaml``: intrusive, DoS,
fuzzing and brute-force templates are excluded at the command level (``-etags``)
*and* the class ceiling rejects any attempt to re-enable them (``-tags dos`` etc.
or ``-itags``). The planner cannot widen the template set past the policy.

Parses Nuclei JSONL (``-jsonl``) into normalised ``Finding`` records with
severity taken from the template's ``info.severity``.
"""

from __future__ import annotations

import json

from safeguard.safety.exceptions import ForbiddenFlag
from safeguard.tools.adapter import ToolAdapter, ToolInvocation
from safeguard.tools.runner import CommandResult
from safeguard.tools.schema import Finding, Severity, ToolResult, ToolStatus

# Templates carrying any of these tags may modify state, exhaust resources, or
# brute-force credentials — outside the non-destructive active-recon class.
BANNED_TAGS = frozenset({
    "dos", "intrusive", "fuzz", "fuzzing", "brute-force", "bruteforce",
})
# Flags that could re-introduce banned templates or destructive behaviour.
_TAG_INCLUDE_FLAGS = {"-tags", "-itags", "-include-tags"}


class NucleiAdapter(ToolAdapter):
    default_image = "scan-runner"

    def build_command(self, invocation: ToolInvocation) -> list[str]:
        cmd = ["nuclei", "-jsonl", "-silent", "-no-color", "-duc",
               *self.spec.default_flags]
        # Safe-only policy → exclude banned tags at source.
        if self.spec.template_policy in (None, "safe-only"):
            cmd += ["-etags", ",".join(sorted(BANNED_TAGS))]
        for flag in invocation.extra_flags:
            cmd.append(flag)
        cmd += ["-u", invocation.target]
        return cmd

    def validate(self, command: list[str]) -> None:
        super().validate(command)
        for i, token in enumerate(command):
            head, _, value = token.partition("=")
            if head in _TAG_INCLUDE_FLAGS:
                if head == "-itags":
                    raise ForbiddenFlag(
                        "nuclei: -itags can re-enable excluded templates")
                tags = value or (command[i + 1] if i + 1 < len(command) else "")
                requested = {t.strip().lower() for t in tags.split(",") if t.strip()}
                bad = requested & BANNED_TAGS
                if bad:
                    raise ForbiddenFlag(
                        f"nuclei: tags {sorted(bad)} are banned by the safe-only policy")

    def parse(self, invocation: ToolInvocation, result: CommandResult) -> ToolResult:
        if result.timed_out:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              target=invocation.target, exit_code=result.exit_code,
                              error="nuclei timed out")
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(self._to_finding(invocation.target, rec))
        status = ToolStatus.OK if findings else ToolStatus.NO_RESULTS
        return ToolResult(tool=self.name, status=status, target=invocation.target,
                          exit_code=result.exit_code, findings=findings)

    def _to_finding(self, target: str, rec: dict) -> Finding:
        info = rec.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        cvss = classification.get("cvss-score")
        asset_ref = rec.get("matched-at") or rec.get("host") or target
        return Finding(
            title=info.get("name") or rec.get("template-id", "nuclei finding"),
            asset_ref=asset_ref,
            source_tool=self.name,
            severity=Severity.from_str(info.get("severity")),
            description=info.get("description", ""),
            cve_ids=[c.upper() for c in cves],
            cvss=float(cvss) if isinstance(cvss, (int, float, str))
            and str(cvss).replace(".", "", 1).isdigit() else None,
            raw={"template_id": rec.get("template-id"),
                 "matched_at": rec.get("matched-at"),
                 "tags": info.get("tags")},
        )
