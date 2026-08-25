"""Noise-floor calibration, offline half (§24, §13.4 — WP-19).

A tool that measures behavioural variance must know its own measurement error. The
offline assertions here: identical scripted runs produce **exactly zero** trajectory
dispersion over Plane A alone (any nonzero value means §11.5 epoch anchoring is admitting
jitter — fix the anchoring, never record the number); the calibrated floor rides through
``aggregate`` so a set at or below it is flagged ``at_noise_floor``; and the summary
*withholds* the precise figure at the floor, so no surface can render a dispersion the
instrument produces on identical input. The real-container half — the measurement the
committed ``NOISE_FLOOR_TRAJECTORY`` constant must match, sequentially and under
concurrent load — is ``test_noise_floor_docker.py``.
"""

from __future__ import annotations

from pathlib import Path

from bellwether.constants import NOISE_FLOOR_CALIBRATED_AT, NOISE_FLOOR_TRAJECTORY
from bellwether.metrics import summarise_trajectory
from bellwether.trace import CanonBlock, NormalizationContext, canonicalize
from tests.test_orchestrator import _executed_run, _run_pipeline

_CONTEXT = NormalizationContext(workspace_root="/work/security-review")


def _plane_a_sequences(tmp_path: Path, repetitions: int = 6) -> list[tuple]:  # type: ignore[type-arg]
    """The §24 calibration input: each run's step sequence over Plane A tool calls alone."""
    sequences = []
    for repetition in range(1, repetitions + 1):
        executed = _executed_run(repetition, tmp_path)
        canon = canonicalize(executed.trace.actions, _CONTEXT, canon=CanonBlock(traj_planes=["A"]))
        sequences.append(canon.step_sequence)
    return sequences


def test_plane_a_dispersion_over_identical_runs_is_exactly_zero(tmp_path: Path) -> None:
    """The assertion that validates the variance metric itself: six identical runs,
    canonicalised over Plane A tool calls alone, must disperse by exactly 0.0 — not a small
    number, zero. Any nonzero value means epoch anchoring (§11.5) is admitting jitter, and
    per WP-19's done-when the fix is the anchoring, never accepting the number."""
    sequences = _plane_a_sequences(tmp_path)
    assert all(sequences), "a run produced an empty Plane A sequence; the input is broken"
    metrics = summarise_trajectory(sequences, noise_floor_distance=NOISE_FLOOR_TRAJECTORY)
    assert metrics.mean_pairwise_distance == 0.0
    assert metrics.distinct_clusters == 1
    assert metrics.at_noise_floor


def test_the_committed_floor_is_a_measurement_with_a_date() -> None:
    """The constant is a published measurement (§24): a float the docker calibration
    re-measures, and a date without which staleness cannot be judged."""
    assert isinstance(NOISE_FLOOR_TRAJECTORY, float)
    assert NOISE_FLOOR_TRAJECTORY >= 0.0
    # The date must parse as a date, not merely look like one.
    import datetime as dt

    dt.date.fromisoformat(NOISE_FLOOR_CALIBRATED_AT)


def test_a_set_at_the_floor_withholds_the_precise_figure(tmp_path: Path) -> None:
    """§13.4's MUST, encoded in the data: at or below the floor, `summary.json` carries
    `trajectory_at_noise_floor: true` and **no** dispersion number — reporting a precise
    small figure the instrument produces on identical input is a fabrication, and a summary
    that does not carry the number keeps every renderer honest at once."""
    result = _run_pipeline(tmp_path, tmp_path / "out")
    consistency = result.summary.consistency
    assert consistency.trajectory_at_noise_floor
    assert consistency.trajectory_dispersion is None
    assert result.summary.noise_floor is not None
    assert result.summary.noise_floor.trajectory == NOISE_FLOOR_TRAJECTORY
    assert result.summary.noise_floor.calibrated_at == NOISE_FLOOR_CALIBRATED_AT


def test_dispersion_above_the_floor_is_reported_precisely() -> None:
    """Above the floor the precise figure is the honest report — the qualitative label
    must never blur a real signal."""
    identical = [("tool_call", "read", None)] * 4
    different = [("tool_call", "write", None), ("model_turn", None, None)]
    metrics = summarise_trajectory(
        [tuple(identical), tuple(different)], noise_floor_distance=NOISE_FLOOR_TRAJECTORY
    )
    assert metrics.mean_pairwise_distance is not None
    assert metrics.mean_pairwise_distance > NOISE_FLOOR_TRAJECTORY
    assert not metrics.at_noise_floor
