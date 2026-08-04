"""Continuous runner.

One cycle = diff the fresh report bundle against the stored baseline, then save
the fresh bundle as the new baseline. Scheduling itself (cron/per-asset-group)
is an orchestration concern left to the deployment; this class is the
deterministic core each scheduled tick calls.
"""

from __future__ import annotations

from dataclasses import dataclass

from safeguard.continuous.baseline import BaselineStore, RegressionReport, diff_reports


@dataclass
class CycleResult:
    regression: RegressionReport
    baseline_path: str
    cycle_index: int


class ContinuousRunner:
    def __init__(self, store: BaselineStore) -> None:
        self.store = store

    def record(self, engagement_id: str, report_data: dict) -> CycleResult:
        prior = self.store.latest(engagement_id)
        regression = diff_reports(prior, report_data)
        path = self.store.save(engagement_id, report_data)
        return CycleResult(regression=regression, baseline_path=path,
                           cycle_index=self.store.count(engagement_id) - 1)
