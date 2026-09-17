"""The pre-flight estimate (§19.1): what a run will cost, printed before anything is spent.

§19.1 makes the estimate mandatory, not threshold-gated: before executing, print the matrix
size, the sequential design's best- and worst-case run counts, and an estimated cost range;
``--yes`` skips the confirmation prompt, never the estimate. This module computes it from the
plan — one figure per set, summed — and prices it only where the operator configured prices.

Three honesty rules shape the numbers. The run counts come from the schedules the sets will
actually run (a scenario may override the profile's, §7.2): best is every set stopping at its
first look, worst is every set running to ``n_max``, and expected uses the schedule's midpoint
look, which is what the spec prescribes for a skill with no stopping history (this build keeps
no history store, so it is always the midpoint). The cost *ceiling* is the per-repetition
token cap times the configured price — a bound, not a forecast; the expected cost uses the
skill's stored baseline's observed tokens per run where one exists, and is otherwise absent
rather than guessed. The judge and A/B multipliers §19.1 lists are zero because neither
subsystem exists in this build, and the estimate says so.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from bellwether.cli.baselines import BaselineRecord
from bellwether.cli.orchestrator import TargetInfo
from bellwether.config.models.provider import ModelPricing

__all__ = ["RunEstimate", "estimate_run", "render_estimate"]


@dataclass(frozen=True)
class RunEstimate:
    scenarios: int
    targets: int
    #: Per set: (first look, midpoint look, n_max).
    best_runs: int
    expected_runs: int
    worst_runs: int
    max_tokens_per_run: int
    #: Every target alias priced → a ceiling in USD (worst runs × token cap × price); else None.
    cost_ceiling_usd: float | None
    #: Expected cost from the stored baseline's observed tokens per run, where one exists.
    cost_expected_usd: float | None
    unpriced_targets: tuple[str, ...]
    fixed_mode: bool
    #: What the estimate could not include, stated rather than omitted.
    caveats: tuple[str, ...]


def _midpoint(looks: Sequence[int]) -> int:
    if not looks:
        return 0
    return looks[(len(looks) - 1) // 2] if len(looks) > 2 else looks[-1]


def estimate_run(
    *,
    schedules: Mapping[str, tuple[tuple[int, ...], int]],
    targets: Sequence[TargetInfo],
    max_tokens_per_run: int,
    pricing_for: Callable[[TargetInfo], ModelPricing | None],
    baseline: BaselineRecord | None = None,
    fixed_mode: bool = False,
) -> RunEstimate:
    """Sum the per-set counts and price them where possible (§19.1)."""
    n_targets = len(targets)
    best = sum((looks[0] if looks else n_max) for looks, n_max in schedules.values()) * n_targets
    worst = sum(n_max for _, n_max in schedules.values()) * n_targets
    expected = (
        worst
        if fixed_mode
        else sum(_midpoint(looks) or n_max for looks, n_max in schedules.values()) * n_targets
    )

    # Pricing: the ceiling treats every token as input (the cheapest kind is not assumed; the
    # cap is a bound on total tokens, so the dearest plausible kind — output — would overstate
    # by a wide margin and input is the volume kind). Stated in the caveats.
    unpriced: list[str] = []
    per_target_ceiling: dict[str, float] = {}
    for target in targets:
        pricing = pricing_for(target)
        if pricing is None:
            unpriced.append(f"{target.provider}/{target.model_alias}")
        else:
            per_target_ceiling[target.slug] = pricing.cost_usd({"input": max_tokens_per_run})
    caveats: list[str] = [
        "judge and A/B terms are 0: neither subsystem exists in this build",
        "E[N] is the schedule's midpoint look: this build keeps no stopping history",
    ]
    ceiling: float | None = None
    expected_cost: float | None = None
    if not unpriced:
        runs_per_target = worst // max(n_targets, 1)
        ceiling = sum(per_target_ceiling[t.slug] * runs_per_target for t in targets)
        caveats.append(
            "the cost ceiling prices the per-repetition token cap as input tokens; "
            "output tokens cost more per token but are a small share of a run"
        )
        if baseline is not None and baseline.summary.cost is not None:
            cost = baseline.summary.cost
            completed = baseline.summary.matrix.runs_completed
            if completed > 0 and cost.tokens:
                per_run = {kind: value / completed for kind, value in cost.tokens.items()}
                expected_runs_per_target = expected // max(n_targets, 1)
                expected_cost = 0.0
                for target in targets:
                    pricing = pricing_for(target)
                    assert pricing is not None
                    expected_cost += (
                        pricing.cost_usd({k: int(v) for k, v in per_run.items()})
                        * expected_runs_per_target
                    )
                caveats.append(
                    f"expected cost uses the baseline's observed tokens per run "
                    f"(evaluation {baseline.eval_id})"
                )
    else:
        caveats.append(
            "no cost figure: "
            + ", ".join(sorted(unpriced))
            + " have no providers.<name>.pricing; the per-repetition token cap "
            "(--max-tokens) is the enforced bound"
        )
    return RunEstimate(
        scenarios=len(schedules),
        targets=n_targets,
        best_runs=best,
        expected_runs=expected,
        worst_runs=worst,
        max_tokens_per_run=max_tokens_per_run,
        cost_ceiling_usd=ceiling,
        cost_expected_usd=expected_cost,
        unpriced_targets=tuple(sorted(unpriced)),
        fixed_mode=fixed_mode,
        caveats=tuple(caveats),
    )


def render_estimate(estimate: RunEstimate) -> list[str]:
    """Human lines for the terminal, before the confirmation."""
    design = "fixed-N (descriptive only)" if estimate.fixed_mode else "sequential"
    lines = [
        f"pre-flight estimate (§19.1): {estimate.scenarios} scenario(s) × {estimate.targets} "
        f"target(s), {design}",
        f"  runs: best {estimate.best_runs}, expected {estimate.expected_runs}, "
        f"worst {estimate.worst_runs}; token cap {estimate.max_tokens_per_run} per run",
    ]
    if estimate.cost_ceiling_usd is not None:
        expected = (
            f", expected ≈ ${estimate.cost_expected_usd:.2f}"
            if estimate.cost_expected_usd is not None
            else ", expected: no baseline to draw tokens per run from"
        )
        lines.append(f"  cost: ceiling ≤ ${estimate.cost_ceiling_usd:.2f}{expected}")
    else:
        lines.append(f"  cost: unpriced ({', '.join(estimate.unpriced_targets)})")
    lines += [f"  note: {caveat}" for caveat in estimate.caveats]
    return lines
