"""The §19.1 pre-flight estimate: printed before anything is spent, priced only where configured.

Run counts come from the schedules the sets will actually run (a scenario may override the
profile's): best is every set at its first look, worst is every set at n_max, expected is the
midpoint look (this build keeps no stopping history, and says so). The cost ceiling prices the
per-repetition token cap; the expected cost draws tokens per run from the stored baseline where
one exists; with any unpriced target there is no dollar figure at all — never a guess.
"""

from __future__ import annotations

from pathlib import Path

import pytest

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
    # 20 runs × 1M tokens at the dearest rate ($5/M output): a bound, not a likely mix.
    assert priced.cost_ceiling_usd == 100.0
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
    assert "ceiling ≤ $100.00" in lines[2] and "expected ≈ $" in lines[2]


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


def test_an_enabled_cache_adds_the_upper_bound_caveat() -> None:
    """Hits are known only per plan as the matrix runs, so the figures are stated as upper
    bounds rather than the estimate guessing a hit rate."""
    without = estimate_run(
        schedules={"a": ((6, 12), 12)},
        targets=[_FRONTIER],
        max_tokens_per_run=1000,
        pricing_for=lambda _t: _PRICE,
    )
    with_cache = estimate_run(
        schedules={"a": ((6, 12), 12)},
        targets=[_FRONTIER],
        max_tokens_per_run=1000,
        pricing_for=lambda _t: _PRICE,
        cache_enabled=True,
    )
    assert not any("run-cache" in c for c in without.caveats)
    assert any("run-cache hits are not deducted" in c for c in with_cache.caveats)
    assert any("upper bounds" in line for line in render_estimate(with_cache))


def test_the_ceiling_bounds_an_output_heavy_run() -> None:
    """The token cap bounds the total, not its composition, so the ceiling prices the whole cap
    at the dearest rate. Pricing it as input would understate an output-heavy run fivefold while
    the line still read as an upper bound — and that line is what the operator approves."""
    estimate = estimate_run(
        schedules={"a": ((2,), 2)},
        targets=[_FRONTIER],
        max_tokens_per_run=1_000_000,
        pricing_for=lambda _t: _PRICE,
    )
    assert estimate.worst_runs == 2
    # _PRICE is input 1.00, output 5.00 per million: the cap costs at most the output rate.
    assert estimate.cost_ceiling_usd == pytest.approx(2 * 5.0)
    worst_real_cost = _PRICE.cost_usd({"output": 1_000_000}) * 2
    assert estimate.cost_ceiling_usd is not None
    assert estimate.cost_ceiling_usd >= worst_real_cost


def test_the_expected_cost_divides_by_executed_runs_only() -> None:
    """The baseline's cost counts executed runs only (§19.2), so the per-run divisor must too —
    dividing by every completed run understates tokens per run by the replayed share."""
    summary = load_summary(_REPORTS / "demo-benign-note-taker" / "summary.json")
    baseline = baseline_from_summary(summary)
    assert summary.cost is not None and summary.matrix.runs_cached == 0

    def estimate_for(record: object) -> float | None:
        return estimate_run(
            schedules={"a": ((6, 12), 12)},
            targets=[_FRONTIER],
            max_tokens_per_run=1000,
            pricing_for=lambda _t: _PRICE,
            baseline=record,  # type: ignore[arg-type]
        ).cost_expected_usd

    none_cached = estimate_for(baseline)
    assert none_cached is not None

    # The same evaluation with half its runs replayed: the same tokens over half the executed
    # runs is twice the tokens per run, so the expectation doubles rather than staying put.
    half = summary.matrix.runs_completed // 2
    cached_summary = summary.model_copy(
        update={"matrix": summary.matrix.model_copy(update={"runs_cached": half})}
    )
    half_cached = estimate_for(baseline.model_copy(update={"summary": cached_summary}))
    assert half_cached is not None
    assert half_cached == pytest.approx(none_cached * 2, rel=1e-6)
