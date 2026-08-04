import itertools
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from safeguard.config.models import (
    Budget,
    Exclusions,
    Mode,
    RulesOfEngagement,
    SafetyClass,
    ScopeSpec,
    TimeWindow,
    ToolSpec,
)
from safeguard.safety.approvals import ApprovalStore
from safeguard.safety.audit import AuditLog
from safeguard.safety.killswitch import KillSwitch
from safeguard.safety.pipeline import SafetyPipeline
from safeguard.safety.rate_limiter import RateLimiter
from safeguard.safety.scope_guard import ScopeGuard
from safeguard.tools.runner import LocalSubprocessRunner


@pytest.fixture
def roe():
    return RulesOfEngagement(
        engagement_id="eng-test-001",
        owner="void",
        authorised_by="mgr",
        authorisation_ref="JIRA-1",
        mode=Mode.BLACK_BOX,
        profile="non_destructive",
        scope=ScopeSpec(domains=("demo-app.esds-lab.internal",),
                        cidrs=("10.20.30.0/24",)),
        exclusions=Exclusions(hosts=("10.20.30.5",), paths=("/billing/*",)),
        timezone="Asia/Kolkata",
        windows=(TimeWindow(days=("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"),
                            start="00:00", end="23:59"),),
        approvers=("void",),
        budget=Budget(max_requests_per_second_per_target=5,
                      max_concurrency_per_target=2,
                      max_total_actions=10),
    )


@pytest.fixture
def nmap_spec():
    return ToolSpec(name="nmap", safety_class=SafetyClass.ACTIVE_RECON,
                    sandbox="recon-runner", default_flags=("-sV", "-T3"))


class FakeClock:
    """Deterministic monotonic clock."""

    def __init__(self, start=0.0, step=0.01):
        self._counter = itertools.count()
        self._start = start
        self._step = step

    def __call__(self):
        return self._start + next(self._counter) * self._step


@pytest.fixture
def make_pipeline(roe):
    def _make(runner=None, now=None, monotonic=None, approvals=None, evidence=None):
        tz = ZoneInfo(roe.timezone)
        fixed_now = now or (lambda: datetime(2026, 8, 4, 3, 0, tzinfo=tz))  # a Tue 03:00
        return SafetyPipeline(
            roe=roe,
            scope_guard=ScopeGuard(roe),
            rate_limiter=RateLimiter(roe.budget),
            kill_switch=KillSwitch(),
            audit=AuditLog(roe.engagement_id),
            runner=runner or LocalSubprocessRunner(dry_run=True),
            approvals=approvals or ApprovalStore(),
            evidence=evidence,
            now_fn=fixed_now,
            monotonic_fn=monotonic or FakeClock(),
        )
    return _make
