"""Phase 3 — Vulnerability Detection.

Turns discovered assets into normalised, deduplicated ``Finding`` records using
non-destructive detection tools (Nuclei safe templates, Nikto), run through the
safety pipeline.
"""

from safeguard.scan.findings import FindingLedger
from safeguard.scan.flow import ScanFlow, ScanStep, ScanReport

__all__ = ["FindingLedger", "ScanFlow", "ScanStep", "ScanReport"]
