"""Act-loop integration — candidate response playbooks and ticket stubs.

Turns gaps and high-risk findings into candidate response actions (a WAF rule, a
SIEM alert, host isolation) and Jira-style ticket stubs. Nothing here executes a
response — Act owns that, behind its own approval. This produces *candidates*.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

_TECHNIQUE_PLAYBOOK = {
    "T1046": "Tune SIEM port-scan correlation; consider rate-based firewall rule.",
    "T1595": "Add WAF rule for content-discovery bursts; alert on 404 spikes.",
    "T1190": "Deploy WAF CRS rule for the exploited endpoint; SIEM alert.",
    "T1189": "Add WAF/CRS rule for reflected-XSS patterns; SIEM alert.",
    "T1203": "EDR behavioural rule for exploitation; isolate host on match.",
}


@dataclass
class Playbook:
    technique: str
    target: str
    action: str
    priority: str = "medium"

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Ticket:
    title: str
    severity: str
    body: str
    labels: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


class ActIntegration:
    def playbooks(self, report_data: dict) -> list[Playbook]:
        out: list[Playbook] = []
        for g in report_data.get("gaps", []) or []:
            tech = g.get("technique") or "unknown"
            out.append(Playbook(
                technique=tech, target=g.get("target", ""),
                action=_TECHNIQUE_PLAYBOOK.get(tech, "Author a detection/response "
                                               "for this technique."),
                priority="high" if g.get("verdict") == "MISSED" else "medium"))
        return out

    def tickets(self, report_data: dict, *, min_priority: str = "high") -> list[Ticket]:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        floor = order.get(min_priority, 3)
        tickets: list[Ticket] = []
        for f in report_data.get("findings", []) or []:
            if order.get(f.get("priority", "info"), 0) < floor:
                continue
            det = f.get("detection", "UNKNOWN")
            tickets.append(Ticket(
                title=f"[Safeguard] {f.get('title')} ({f.get('priority')})",
                severity=f.get("priority", "info"),
                body=(f"Asset: {f.get('asset')}\nRisk: {f.get('risk')}\n"
                      f"Detection: {det}\nCVEs: {', '.join(f.get('cve_ids', []))}\n"
                      f"ATT&CK: {', '.join(f.get('techniques', []))}"),
                labels=["safeguard", f.get("priority", "info"),
                        "undetected" if det in ("MISSED", "PARTIAL") else "detected"]))
        return tickets

    def push(self, report_data: dict, outbox: str | Path,
             *, min_priority: str = "high") -> dict[str, str]:
        out = Path(outbox)
        out.mkdir(parents=True, exist_ok=True)
        pb = out / "act_playbooks.json"
        tk = out / "act_tickets.json"
        pb.write_text(json.dumps([p.as_dict() for p in self.playbooks(report_data)],
                                 indent=2), encoding="utf-8")
        tk.write_text(json.dumps([t.as_dict()
                                  for t in self.tickets(report_data,
                                                        min_priority=min_priority)],
                                 indent=2), encoding="utf-8")
        return {"playbooks": str(pb), "tickets": str(tk)}
