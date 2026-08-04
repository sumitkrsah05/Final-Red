"""Rate & blast-radius limiter.

Enforces two ceilings from the ROE budget:
  * per-target request rate (token-bucket, requests/sec), and
  * per-target concurrency (in-flight actions),
plus a global engagement action budget (``max_total_actions``).

Deterministic clock: the caller supplies ``now`` (monotonic seconds) so the
limiter is testable and free of the disallowed ``time`` side effects.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from safeguard.config.models import Budget
from safeguard.safety.exceptions import BudgetExceeded, RateLimited


@dataclass
class _Bucket:
    tokens: float
    last: float
    in_flight: int = 0


@dataclass
class RateLimiter:
    budget: Budget
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _total_actions: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _bucket(self, target: str, now: float) -> _Bucket:
        b = self._buckets.get(target)
        if b is None:
            b = _Bucket(tokens=self.budget.max_requests_per_second_per_target, last=now)
            self._buckets[target] = b
        return b

    def acquire(self, target: str, now: float) -> None:
        """Reserve one action slot for ``target`` at time ``now`` (seconds).

        Raises BudgetExceeded / RateLimited without mutating state on denial."""
        rate = self.budget.max_requests_per_second_per_target
        cap = self.budget.max_concurrency_per_target
        with self._lock:
            if self._total_actions >= self.budget.max_total_actions:
                raise BudgetExceeded(
                    f"engagement action budget exhausted "
                    f"({self.budget.max_total_actions})"
                )
            b = self._bucket(target, now)
            # Refill token bucket.
            elapsed = max(0.0, now - b.last)
            b.tokens = min(rate, b.tokens + elapsed * rate)
            b.last = now
            if b.in_flight >= cap:
                raise RateLimited(
                    f"concurrency ceiling reached for {target} ({cap})"
                )
            if b.tokens < 1.0:
                raise RateLimited(f"request rate ceiling reached for {target}")
            b.tokens -= 1.0
            b.in_flight += 1
            self._total_actions += 1

    def release(self, target: str) -> None:
        with self._lock:
            b = self._buckets.get(target)
            if b and b.in_flight > 0:
                b.in_flight -= 1

    @property
    def total_actions(self) -> int:
        with self._lock:
            return self._total_actions
