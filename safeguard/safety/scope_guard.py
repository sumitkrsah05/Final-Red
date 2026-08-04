"""Scope guard — the first and hardest gate.

Every target is checked against the ROE allowlist (CIDRs, domains) and the
exclusion list, and the current time against the permitted windows, *before any
packet leaves*. Fail-closed: an unresolvable target, an unlisted target, an
excluded target, missing authorisation, or an expired window all raise.

Domain/host targets are matched literally and by parent-domain suffix. IP
targets are matched against the in-scope CIDRs. Exclusions always win.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit

from safeguard.config.models import RulesOfEngagement, TimeWindow
from safeguard.config.models import _parse_hhmm
from safeguard.safety.exceptions import OutOfScope, OutOfWindow

_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@dataclass(frozen=True)
class Target:
    """A resolved target for a single action."""

    raw: str  # domain, host, or IP as proposed
    ip: Optional[str] = None  # resolved IP if known (host/CIDR checks)
    path: Optional[str] = None  # URL path, checked against path exclusions

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.raw)
            return True
        except ValueError:
            return False


class ScopeGuard:
    def __init__(self, roe: RulesOfEngagement) -> None:
        self.roe = roe
        self._networks = roe.scope.networks()
        self._domains = tuple(d.lower().lstrip(".") for d in roe.scope.domains)
        self._repos = set(roe.scope.repos)
        self._cloud_accounts = set(roe.scope.cloud_accounts)
        self._excluded_hosts = set(roe.exclusions.hosts)
        self._excluded_paths = tuple(roe.exclusions.paths)

    # -- scope ------------------------------------------------------------
    def check_target(self, target: Target) -> None:
        """Raise OutOfScope if the target is not permitted.

        A URL target (``https://host/path``) is decomposed: the host is matched
        against the allowlist and the path against the exclusions."""
        if not self.roe.authorisation_ref:
            raise OutOfScope("engagement has no authorisation_ref")

        host, path = _host_and_path(target.raw)
        path = target.path or path

        # Exclusions win, unconditionally.
        if self._is_excluded(host, target.ip, path):
            raise OutOfScope(f"target excluded by ROE: {target.raw}")

        if self._in_scope(host, target.ip):
            return
        raise OutOfScope(f"target not in ROE allowlist: {target.raw}")

    def _is_excluded(self, host: str, ip: Optional[str], path: Optional[str]) -> bool:
        for candidate in (host, ip):
            if candidate and candidate in self._excluded_hosts:
                return True
        if path:
            for pat in self._excluded_paths:
                if fnmatch.fnmatch(path, pat):
                    return True
        return False

    def _in_scope(self, host: str, ip: Optional[str]) -> bool:
        # Gray/white-box targets: repos and cloud accounts are matched literally
        # against their allowlists (they are not network hosts).
        if host in self._repos or host in self._cloud_accounts:
            return True
        # IP-based match (single address)
        for candidate in (host, ip):
            if not candidate:
                continue
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if any(addr in net for net in self._networks):
                return True
        # CIDR target: in scope only if it is a subset of an allowed network.
        if "/" in host:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                net = None
            if net is not None and any(
                net.subnet_of(allowed) for allowed in self._networks
                if net.version == allowed.version
            ):
                return True
        # Domain-based match (exact or subdomain of a listed domain)
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if not is_ip:
            h = host.lower().rstrip(".")
            for dom in self._domains:
                if h == dom or h.endswith("." + dom):
                    return True
        return False

    # -- time window ------------------------------------------------------
    def check_window(self, now: datetime) -> None:
        """Raise OutOfWindow if ``now`` is outside every allowed window.

        ``now`` must be timezone-aware in the ROE timezone (the caller resolves
        the zone; the guard compares wall-clock day/time)."""
        if not self.roe.windows:
            raise OutOfWindow("no execution window defined — fail closed")
        day = _WEEKDAYS[now.weekday()]
        minutes = now.hour * 60 + now.minute
        for w in self.roe.windows:
            if day not in w.days:
                continue
            sh, sm = _parse_hhmm(w.start, "start")
            eh, em = _parse_hhmm(w.end, "end")
            start, end = sh * 60 + sm, eh * 60 + em
            if start <= minutes < end:
                return
        raise OutOfWindow(f"{day} {now:%H:%M} outside permitted windows")

    def is_approver(self, name: str) -> bool:
        return name in self.roe.approvers


def _host_and_path(raw: str) -> tuple[str, Optional[str]]:
    """Split a target into (host, path). Accepts bare hosts, IPs, CIDRs, and
    URLs. For a URL the scheme/port are stripped and the path preserved."""
    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.hostname or parts.netloc
        return host, (parts.path or None)
    # bare host[:port] — keep CIDR slashes intact, drop a trailing :port
    host = raw
    if host.count(":") == 1 and "/" not in host.split(":")[1]:
        host = host.split(":")[0]
    return host, None
