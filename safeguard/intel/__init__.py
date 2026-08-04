"""Phase 6 — Intelligence & Correlation (sovereign, offline).

Local NVD/CVE mirror, MITRE ATT&CK technique mapping, risk scoring
(CVSS + EPSS + asset criticality + detection status), and an attack-path
correlator. All data is local; there are no external NVD/MITRE calls at runtime.
The numeric-claim verifier grounds every figure against these sources.
"""

from safeguard.intel.nvd import CVERecord, LocalNVDMirror
from safeguard.intel.attack import AttackMap, Technique
from safeguard.intel.risk import RiskScorer, RiskScore
from safeguard.intel.enrich import Enricher
from safeguard.intel.correlate import AttackPathCorrelator

__all__ = [
    "CVERecord",
    "LocalNVDMirror",
    "AttackMap",
    "Technique",
    "RiskScorer",
    "RiskScore",
    "Enricher",
    "AttackPathCorrelator",
]
