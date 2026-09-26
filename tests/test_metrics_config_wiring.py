"""The config's ``metrics`` block reaches the metrics (§13.7, §13.4).

``metrics.bci_weights`` was validated by ``doctor`` (the five weights must sum to 1) and then never
used: the BCI — the headline consistency gate — was composed from the default table whatever an
operator set. ``metrics.trajectory_cluster_threshold`` likewise: trajectories were always cut at
0.2. Found by a runtime probe of which config fields package code ever reads (spec-notes).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from bellwether.cli import orchestrator
from bellwether.cli.orchestrator import TargetInfo, drive_evaluation, plan_matrix
from tests.test_driver import _firstlight_profile, _ReplayExecutor, _scenario

_WEIGHTS = {"outcome": 0.5, "trigger": 0.1, "trajectory": 0.1, "capability": 0.2, "output": 0.1}


def test_the_driver_hands_the_configured_weights_and_threshold_to_the_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    real_bci, real_trajectory = orchestrator.compute_bci, orchestrator.summarise_trajectory

    def bci_spy(components, *, weights=None, pass_rate=None):  # type: ignore[no-untyped-def]
        seen["weights"] = weights
        return real_bci(components, weights=weights, pass_rate=pass_rate)

    def trajectory_spy(sequences, *, threshold=0.2, noise_floor_distance=None):  # type: ignore[no-untyped-def]
        seen["threshold"] = threshold
        return real_trajectory(
            sequences, threshold=threshold, noise_floor_distance=noise_floor_distance
        )

    monkeypatch.setattr(orchestrator, "compute_bci", bci_spy)
    monkeypatch.setattr(orchestrator, "summarise_trajectory", trajectory_spy)
    plans = plan_matrix(
        [_scenario("alpha")], [TargetInfo("api-loop", "p", "frontier")], repetitions=6
    )
    drive_evaluation(
        plans,
        _ReplayExecutor(tmp_path),
        profile=_firstlight_profile(),
        bci_weights=_WEIGHTS,
        trajectory_cluster_threshold=0.35,
    )
    assert seen == {"weights": _WEIGHTS, "threshold": 0.35}
