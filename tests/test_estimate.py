"""The §19.1 pre-flight estimate: printed before anything is spent, priced only where configured.

Run counts come from the schedules the sets will actually run (a scenario may override the
profile's): best is every set at its first look, worst is every set at n_max, expected is the
midpoint look (this build keeps no stopping history, and says so). The cost ceiling prices the
per-repetition token cap; the expected cost draws tokens per run from the stored baseline where
one exists; with any unpriced target there is no dollar figure at all — never a guess.
"""

from __future__ import annotations

from pathlib import Path

from bellwether.cli.baselines import baseline_from_summary
from bellwether.cli.diff import load_summary
from bellwether.cli.estimate import estimate_run, render_estimate
from bellwether.cli.orchestrator import TargetInfo
from bellwether.config.models.provider import ModelPricing

_REPORTS = Path(__file__).resolve().parent.parent / "examples" / "reports"
_FRONTIER = TargetInfo("api-loop", "anthropic", "frontier")
_SMALL = TargetInfo("api-loop", "anthropic", "small")
_PRICE = ModelPricing(input_usd_per_mtok=1.0, output_usd_per_mtok=5.0)


def test_run_counts_follow_each_sets_own_schedule() -> None:
    estimate = estimate_run(
        schedules={"a": ((6, 12, 20), 20), "b": ((6, 12), 12)},
        targets=[_FRONTIER, _SMALL],
        max_tokens_per_run=1000,
        pricing_for=lambda _t: None,
    )
    assert estimate.scenarios == 2 and estimate.targets == 2
    assert estimate.best_runs == (6 + 6) * 2
    assert estimate.expected_runs == (12 + 12) * 2  # midpoint of 3 looks; last of 2
    assert estimate.worst_runs == (20 + 12) * 2
    assert estimate.cost_ceiling_usd is None
    assert estimate.unpriced_targets == ("anthropic/frontier", "anthropic/small")
    assert any("no cost figure" in c for c in estimate.caveats)
    assert any("no stopping history" in c for c in estimate.caveats)


def test_fixed_mode_expects_the_full_count() -> None:
    estimate = estimate_run(
        schedules={"a": ((3,), 3)},
        targets=[_FRONTIER],
        max_tokens_per_run=1000,
        pricing_for=lambda _t: None,
        fixed_mode=True,
    )
    assert (estimate.best_runs, estimate.expected_runs, estimate.worst_runs) == (3, 3, 3)
    assert estimate.fixed_mode


def test_a_priced_matrix_gets_a_ceiling_and_a_baseline_gives_an_expected_cost() -> None:
    priced = estimate_run(
        schedules={"a": ((6, 12, 20), 20)},
        targets=[_FRONTIER],
        max_tokens_per_run=1_000_000,
        pricing_for=lambda _t: _PRICE,
    )
    # 20 runs × 1M tokens × $1/M as input
    assert priced.cost_ceiling_usd == 20.0
    assert priced.cost_expected_usd is None
    assert "no baseline" in render_estimate(priced)[2]

    baseline = baseline_from_summary(
        load_summary(_REPORTS / "demo-benign-note-taker" / "summary.json")
    )
    cost = baseline.summary.cost
    assert cost is not None and baseline.summary.matrix.runs_completed == 6
    with_baseline = estimate_run(
        schedules={"a": ((6, 12, 20), 20)},
        targets=[_FRONTIER],
        max_tokens_per_run=1_000_000,
        pricing_for=lambda _t: _PRICE,
        baseline=baseline,
    )
    per_run = {k: int(v / 6) for k, v in cost.tokens.items()}
    assert with_baseline.cost_expected_usd is not None
    assert with_baseline.cost_expected_usd == _PRICE.cost_usd(per_run) * 12  # midpoint look
    lines = render_estimate(with_baseline)
    assert "ceiling ≤ $20.00" in lines[2] and "expected ≈ $" in lines[2]


def test_one_unpriced_target_leaves_the_whole_matrix_unpriced() -> None:
    estimate = estimate_run(
        schedules={"a": ((6, 12), 12)},
        targets=[_FRONTIER, _SMALL],
        max_tokens_per_run=1000,
        pricing_for=lambda t: _PRICE if t.model_alias == "frontier" else None,
    )
    assert estimate.cost_ceiling_usd is None
    assert estimate.unpriced_targets == ("anthropic/small",)
    assert "unpriced (anthropic/small)" in render_estimate(estimate)[2]
