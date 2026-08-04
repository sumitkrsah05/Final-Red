"""Concrete tool adapters. Register new adapters in ``ADAPTERS``."""

from safeguard.tools.adapters.checkov import CheckovAdapter
from safeguard.tools.adapters.dalfox import DalfoxAdapter
from safeguard.tools.adapters.gitleaks import GitleaksAdapter
from safeguard.tools.adapters.gobuster import GobusterAdapter
from safeguard.tools.adapters.httpx import HttpxAdapter
from safeguard.tools.adapters.nikto import NiktoAdapter
from safeguard.tools.adapters.nmap import NmapAdapter
from safeguard.tools.adapters.nuclei import NucleiAdapter
from safeguard.tools.adapters.prowler import ProwlerAdapter
from safeguard.tools.adapters.semgrep import SemgrepAdapter
from safeguard.tools.adapters.sqlmap import SqlmapAdapter
from safeguard.tools.adapters.trivy import TrivyAdapter
from safeguard.tools.adapters.whatweb import WhatWebAdapter

# name (as in tools.yaml) -> adapter class
ADAPTERS = {
    "nmap": NmapAdapter,
    "httpx": HttpxAdapter,
    "whatweb": WhatWebAdapter,
    "gobuster": GobusterAdapter,
    "nuclei": NucleiAdapter,
    "nikto": NiktoAdapter,
    "dalfox": DalfoxAdapter,
    "sqlmap": SqlmapAdapter,
    "semgrep": SemgrepAdapter,
    "gitleaks": GitleaksAdapter,
    "checkov": CheckovAdapter,
    "trivy": TrivyAdapter,
    "prowler": ProwlerAdapter,
}

__all__ = ["ADAPTERS", "NmapAdapter", "HttpxAdapter", "WhatWebAdapter",
           "GobusterAdapter", "NucleiAdapter", "NiktoAdapter",
           "DalfoxAdapter", "SqlmapAdapter", "SemgrepAdapter",
           "GitleaksAdapter", "CheckovAdapter", "TrivyAdapter",
           "ProwlerAdapter"]
