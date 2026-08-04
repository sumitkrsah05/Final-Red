"""Phase 0 safety-rail tests: scope guard, windows, audit chain, kill switch,
rate limiter, approvals, and the destructive-class load guard."""

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from safeguard.config.models import Budget
from safeguard.safety.audit import AuditLog
from safeguard.safety.exceptions import (
    BudgetExceeded,
    OutOfScope,
    OutOfWindow,
    RateLimited,
)
from safeguard.safety.killswitch import KillSwitch
from safeguard.safety.rate_limiter import RateLimiter
from safeguard.safety.scope_guard import ScopeGuard, Target


# -- scope guard ---------------------------------------------------------
def test_in_scope_domain_and_subdomain(roe):
    g = ScopeGuard(roe)
    g.check_target(Target(raw="demo-app.esds-lab.internal"))
    g.check_target(Target(raw="api.demo-app.esds-lab.internal"))


def test_in_scope_cidr(roe):
    ScopeGuard(roe).check_target(Target(raw="10.20.30.44"))


def test_out_of_scope_hard_block(roe):
    with pytest.raises(OutOfScope):
        ScopeGuard(roe).check_target(Target(raw="8.8.8.8"))
    with pytest.raises(OutOfScope):
        ScopeGuard(roe).check_target(Target(raw="evil.example.com"))


def test_exclusion_wins_over_cidr(roe):
    with pytest.raises(OutOfScope):
        ScopeGuard(roe).check_target(Target(raw="10.20.30.5"))  # excluded host


def test_excluded_path(roe):
    with pytest.raises(OutOfScope):
        ScopeGuard(roe).check_target(
            Target(raw="demo-app.esds-lab.internal", path="/billing/invoices")
        )


def test_missing_authorisation_fails_closed(roe):
    import dataclasses
    # __post_init__ re-validates on replace and rejects a missing ref — the ROE
    # can never even be constructed without an authorisation reference.
    with pytest.raises(ValueError):
        dataclasses.replace(roe, authorisation_ref="")


# -- time window ---------------------------------------------------------
def test_window_enforced():
    from safeguard.config.models import (
        Exclusions, Mode, RulesOfEngagement, ScopeSpec, TimeWindow,
    )
    tz = ZoneInfo("Asia/Kolkata")
    roe = RulesOfEngagement(
        engagement_id="e", owner="o", authorised_by="m", authorisation_ref="R",
        mode=Mode.BLACK_BOX, profile="non_destructive",
        scope=ScopeSpec(cidrs=("10.0.0.0/8",)), exclusions=Exclusions(),
        timezone="Asia/Kolkata",
        windows=(TimeWindow(days=("Tue",), start="02:00", end="04:00"),),
        approvers=("void",), budget=Budget(),
    )
    g = ScopeGuard(roe)
    g.check_window(datetime(2026, 8, 4, 3, 0, tzinfo=tz))  # Tue 03:00 -> ok
    with pytest.raises(OutOfWindow):
        g.check_window(datetime(2026, 8, 4, 5, 0, tzinfo=tz))  # Tue 05:00
    with pytest.raises(OutOfWindow):
        g.check_window(datetime(2026, 8, 5, 3, 0, tzinfo=tz))  # Wed 03:00


# -- audit chain ---------------------------------------------------------
def test_audit_hash_chain_intact_and_tamper_evident():
    log = AuditLog("eng-x")
    for i in range(5):
        log.append(actor="agent", action="t", ts=f"2026-01-01T00:00:0{i}", params={"i": i})
    assert log.verify()
    # tamper with a middle event's detail
    log._events[2].detail["i"] = 999
    assert not log.verify()


def test_audit_links_prev_hash():
    log = AuditLog("eng-x")
    e0 = log.append(actor="a", action="x", ts="t0")
    e1 = log.append(actor="a", action="y", ts="t1")
    assert e1.prev_hash == e0.hash
    assert log.head == e1.hash


# -- kill switch ---------------------------------------------------------
def test_kill_switch_revocation_hook_fires():
    ks = KillSwitch()
    fired = []
    ks.register_revocation_hook(lambda: fired.append(True))
    assert not ks.engaged
    ks.engage("test")
    assert ks.engaged
    assert fired == [True]
    ks.engage("again")  # idempotent; hook not re-fired
    assert fired == [True]


# -- rate limiter --------------------------------------------------------
def test_rate_limiter_concurrency_ceiling():
    rl = RateLimiter(Budget(max_requests_per_second_per_target=100,
                            max_concurrency_per_target=2,
                            max_total_actions=100))
    rl.acquire("t", now=0.0)
    rl.acquire("t", now=0.0)
    with pytest.raises(RateLimited):
        rl.acquire("t", now=0.0)
    rl.release("t")
    rl.acquire("t", now=0.0)  # slot freed


def test_rate_limiter_total_budget():
    rl = RateLimiter(Budget(max_requests_per_second_per_target=100,
                            max_concurrency_per_target=100,
                            max_total_actions=3))
    for _ in range(3):
        rl.acquire("t", now=0.0)
        rl.release("t")
    with pytest.raises(BudgetExceeded):
        rl.acquire("t", now=0.0)


# -- destructive class not loadable --------------------------------------
def test_destructive_tool_rejected_at_load(tmp_path):
    from safeguard.config.loader import load_tool_registry
    p = tmp_path / "tools.yaml"
    p.write_text("tools:\n  evil:\n    class: destructive\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_tool_registry(str(p))
