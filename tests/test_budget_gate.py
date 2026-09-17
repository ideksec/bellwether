"""The budget gate, decided from what the run footers recorded (§16.2, §19.1).

`gates.budget` was configured and read nowhere: a dollar/time ceiling that read as a control
and did nothing. It is now composed from observation — every run's footer carries its wall
clock and token totals — under the same reflex as the other gates: a footerless run's spend
is *unobserved*, so the total is a lower bound (enough to block, never enough to pass unless
the per-run cap bounds it), and an unpriced target leaves the cost gate uncomposed and
disclosed rather than charged at a guessed rate. These pin the decision tables directly; the
end-to-end path lives in `test_run.py`.
"""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from bellwether.cli.orchestrator import (
    BUDGET_SCOPE,
    BudgetReading,
    SetReading,
    TargetInfo,
    _budget_cost_result,
    _budget_wall_clock_result,
    budget_reading,
)
from bellwether.config import template_path
from bellwether.config.models.policy import ProfileSpec
from bellwether.config.models.provider import ModelPricing, ProviderConfig
from bellwether.config.policy_loader import parse_policy

_FRONTIER = TargetInfo(harness="api-loop", provider="anthropic", model_alias="frontier")
_SMALL = TargetInfo(harness="api-loop", provider="anthropic", model_alias="small")
_PRICE = ModelPricing(
    input_usd_per_mtok=3.0,
    output_usd_per_mtok=15.0,
    cache_read_usd_per_mtok=0.3,
    cache_write_usd_per_mtok=3.75,
)


def _profile(*, max_cost_usd: float = 25.0, max_wall_clock_minutes: int = 60) -> ProfileSpec:
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    base = policy.profile("low")
    budget = base.gates.budget.model_copy(
        update={"max_cost_usd": max_cost_usd, "max_wall_clock_minutes": max_wall_clock_minutes}
    )
    return base.model_copy(update={"gates": base.gates.model_copy(update={"budget": budget})})


def _reading(
    target: TargetInfo = _FRONTIER,
    *,
    wall_clock_ms: int = 0,
    unobserved: int = 0,
    tokens: dict[str, int] | None = None,
) -> SetReading:
    return SetReading(
        scenario_id="s",
        target=target,
        n_completed=6,
        n_evaluable=6,
        pass_rate=1.0,
        lower_bound=0.6,
        functional_threshold=0.5,
        look=6,
        look_outcome="pass",
        bci=100.0,
        consistently_failing=False,
        jaccard_weighted=1.0,
        jaccard_plain=1.0,
        modal_trajectory_share=1.0,
        mean_pairwise_distance=0.0,
        rare_capability_risk="none",
        rare_capability_blocking=False,
        tier1_agreement=True,
        scope_exceeded=(),
        egress_observed=True,
        egress_blocked=False,
        weights_digest="sha256:0",
        runs=(),
        wall_clock_ms_observed=wall_clock_ms,
        n_wall_clock_unobserved=unobserved,
        tokens=tokens or {},
    )


# ---------------------------------------------------------------------------
# pricing configuration
# ---------------------------------------------------------------------------


def test_pricing_prices_each_token_kind_separately() -> None:
    """§9.3: cache reads and writes are separate line items; a naive mean misprices a matrix
    whose first run is a cache miss and whose remainder are hits."""
    cost = _PRICE.cost_usd(
        {"input": 1_000_000, "output": 100_000, "cache_read": 2_000_000, "cache_write": 400_000}
    )
    assert cost == pytest.approx(3.0 + 1.5 + 0.6 + 1.5)


def test_pricing_treats_a_missing_kind_as_zero() -> None:
    assert _PRICE.cost_usd({"input": 500_000}) == pytest.approx(1.5)


def test_pricing_for_an_unknown_alias_is_refused() -> None:
    """A price for an alias no target can resolve is a misconfiguration, not a default."""
    with pytest.raises(ValidationError, match="pricing names alias"):
        ProviderConfig(
            type="anthropic",
            api_key_env="K",
            models={"frontier": "id"},
            pricing={"small": _PRICE},
        )


def test_pricing_for_resolves_per_alias() -> None:
    provider = ProviderConfig(
        type="anthropic",
        api_key_env="K",
        models={"frontier": "id", "small": "id2"},
        pricing={"frontier": _PRICE},
    )
    assert provider.pricing_for("frontier") is _PRICE
    assert provider.pricing_for("small") is None


# ---------------------------------------------------------------------------
# the matrix-wide reading
# ---------------------------------------------------------------------------


def test_budget_reading_sums_across_sets_and_prices_a_fully_priced_matrix() -> None:
    readings = [
        _reading(_FRONTIER, wall_clock_ms=60_000, tokens={"input": 1_000_000, "output": 0}),
        _reading(_SMALL, wall_clock_ms=30_000, tokens={"input": 0, "output": 100_000}),
    ]
    spend = budget_reading(readings, pricing_for=lambda _t: _PRICE)
    assert spend.wall_clock_ms == 90_000
    assert spend.n_unobserved == 0
    assert spend.tokens == {
        "input": 1_000_000,
        "output": 100_000,
        "cache_read": 0,
        "cache_write": 0,
    }
    assert spend.cost_usd == pytest.approx(4.5)
    assert spend.unpriced == ()


def test_an_unpriced_target_leaves_the_matrix_unpriced_and_names_it() -> None:
    """One unpriced alias makes the whole cost unknown — a partial sum would read as the
    matrix's cost while omitting a target."""
    readings = [_reading(_FRONTIER, tokens={"input": 10}), _reading(_SMALL, tokens={"input": 10})]
    spend = budget_reading(
        readings, pricing_for=lambda t: _PRICE if t.model_alias == "frontier" else None
    )
    assert spend.cost_usd is None
    assert spend.unpriced == ("anthropic/small",)


def test_no_pricing_resolver_means_unpriced() -> None:
    spend = budget_reading([_reading(_FRONTIER)])
    assert spend.cost_usd is None
    assert spend.unpriced == ("anthropic/frontier",)


def test_budget_reading_counts_footerless_runs() -> None:
    spend = budget_reading([_reading(wall_clock_ms=10_000, unobserved=2)])
    assert spend.wall_clock_ms == 10_000
    assert spend.n_unobserved == 2


# ---------------------------------------------------------------------------
# wall clock
# ---------------------------------------------------------------------------


def _spend(*, wall_ms: int = 0, unobserved: int = 0, cost: float | None = None) -> BudgetReading:
    return BudgetReading(
        wall_clock_ms=wall_ms,
        n_unobserved=unobserved,
        tokens={},
        cost_usd=cost,
        unpriced=() if cost is not None else ("anthropic/frontier",),
    )


def test_wall_clock_within_the_ceiling_with_every_run_footered_passes() -> None:
    result = _budget_wall_clock_result(
        _spend(wall_ms=10 * 60_000), _profile(max_wall_clock_minutes=60), per_run_cap_ms=None
    )
    assert result.status == "pass"
    assert result.target == BUDGET_SCOPE
    assert result.observed == "10.00 min"
    assert "within the 60 min ceiling" in result.reason


def test_wall_clock_over_the_ceiling_blocks() -> None:
    result = _budget_wall_clock_result(
        _spend(wall_ms=61 * 60_000), _profile(max_wall_clock_minutes=60), per_run_cap_ms=None
    )
    assert result.status == "block"
    assert "max_wall_clock_minutes" in result.reason


def test_a_lower_bound_over_the_ceiling_blocks_even_with_unobserved_runs() -> None:
    """Enough is enough: what was observed already exceeds the line."""
    result = _budget_wall_clock_result(
        _spend(wall_ms=61 * 60_000, unobserved=3),
        _profile(max_wall_clock_minutes=60),
        per_run_cap_ms=None,
    )
    assert result.status == "block"


def test_a_footerless_run_bounded_by_the_per_run_cap_still_passes() -> None:
    """Observed 10 min + 2 unobserved runs × 5 min cap = at most 20 min, within 60."""
    result = _budget_wall_clock_result(
        _spend(wall_ms=10 * 60_000, unobserved=2),
        _profile(max_wall_clock_minutes=60),
        per_run_cap_ms=5 * 60_000,
    )
    assert result.status == "pass"
    assert result.observed == "≥ 10.00 min, ≤ 20.00 min"
    assert "2 run(s) have no footer" in result.reason


def test_a_footerless_run_the_cap_cannot_bound_defers() -> None:
    """Observed 50 min + 3 unobserved × 5 min cap = up to 65 min: not bounded within 60."""
    result = _budget_wall_clock_result(
        _spend(wall_ms=50 * 60_000, unobserved=3),
        _profile(max_wall_clock_minutes=60),
        per_run_cap_ms=5 * 60_000,
    )
    assert result.status == "not_evaluable"
    assert result.observed == "≥ 50.00 min"
    assert "cannot be bounded" in result.reason


def test_a_footerless_run_with_no_cap_defers() -> None:
    result = _budget_wall_clock_result(
        _spend(wall_ms=1_000, unobserved=1), _profile(), per_run_cap_ms=None
    )
    assert result.status == "not_evaluable"


# ---------------------------------------------------------------------------
# cost
# ---------------------------------------------------------------------------


def test_cost_within_the_ceiling_passes() -> None:
    result = _budget_cost_result(_spend(cost=1.2345678), _profile(max_cost_usd=25.0))
    assert result.status == "pass"
    assert result.observed == "$1.2346"
    assert result.threshold == "≤ $25.00"


def test_cost_over_the_ceiling_blocks() -> None:
    result = _budget_cost_result(_spend(cost=25.01), _profile(max_cost_usd=25.0))
    assert result.status == "block"
    assert "max_cost_usd" in result.reason


def test_a_zero_ceiling_blocks_any_priced_spend() -> None:
    result = _budget_cost_result(_spend(cost=0.0001), _profile(max_cost_usd=0.0))
    assert result.status == "block"


def test_cost_with_a_footerless_run_defers_unless_already_over() -> None:
    under = _budget_cost_result(_spend(cost=1.0, unobserved=1), _profile(max_cost_usd=25.0))
    assert under.status == "not_evaluable"
    assert under.observed == "≥ $1.0000"
    over = _budget_cost_result(_spend(cost=30.0, unobserved=1), _profile(max_cost_usd=25.0))
    assert over.status == "block"
