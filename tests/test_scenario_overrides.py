"""The per-scenario §7.2 fields the model accepts are honoured: `timeout_seconds` becomes the
run's wall clock, and `looks`/`n_max` become the set's sequential schedule — with the manifest
override's consistency rule, so an inconsistent schedule refuses while planning rather than
producing a figure the design does not license (§13.1)."""

from __future__ import annotations

import pytest

from bellwether.cli.execution import run_limits_for
from bellwether.cli.orchestrator import TargetInfo, effective_schedule, plan_matrix
from bellwether.config.models.scenarios import Scenario, ScenarioDefaults
from bellwether.errors import BellwetherError
from bellwether.harness import RunLimits

PROFILE_LOOKS = (6, 12, 20)
PROFILE_N_MAX = 20


def _scenario(scenario_id: str = "s", **fields: object) -> Scenario:
    return Scenario.model_validate(
        {
            "id": scenario_id,
            "expectation": "should_trigger",
            "prompt": "go",
            "assert": [{"skill_activated": True}],
            **fields,
        }
    )


# ---------------------------------------------------------------------------
# timeout_seconds → wall clock
# ---------------------------------------------------------------------------


def test_the_scenario_timeout_becomes_the_runs_wall_clock() -> None:
    base = RunLimits(max_total_tokens=5_000)
    limits = run_limits_for(base, _scenario(timeout_seconds=120), ScenarioDefaults())
    assert limits.wall_seconds == 120.0
    assert limits.max_total_tokens == 5_000  # everything else untouched


def test_the_suite_default_timeout_applies_when_the_scenario_sets_none() -> None:
    limits = run_limits_for(RunLimits(), _scenario(), ScenarioDefaults(timeout_seconds=300))
    assert limits.wall_seconds == 300.0


def test_without_a_suite_the_base_limits_stand() -> None:
    base = RunLimits(wall_seconds=42.0)
    assert run_limits_for(base, _scenario(), None) == base


# ---------------------------------------------------------------------------
# looks / n_max → the set's schedule
# ---------------------------------------------------------------------------


def test_no_override_reproduces_the_resolved_matrix_exactly() -> None:
    looks, n_max = effective_schedule(
        _scenario(), ScenarioDefaults(), looks=PROFILE_LOOKS, n_max=PROFILE_N_MAX
    )
    assert (looks, n_max) == (PROFILE_LOOKS, PROFILE_N_MAX)


def test_an_n_max_at_a_profile_look_truncates_the_schedule_to_it() -> None:
    """`n_max: 12` under looks [6, 12, 20] is the unambiguous two-look schedule ending at 12."""
    looks, n_max = effective_schedule(
        _scenario(n_max=12), ScenarioDefaults(), looks=PROFILE_LOOKS, n_max=PROFILE_N_MAX
    )
    assert (looks, n_max) == ((6, 12), 12)


def test_a_scenarios_own_looks_and_n_max_win_over_the_suite_and_the_profile() -> None:
    defaults = ScenarioDefaults(looks=[4, 8], n_max=8)
    own = effective_schedule(
        _scenario(looks=[2, 4], n_max=4), defaults, looks=PROFILE_LOOKS, n_max=PROFILE_N_MAX
    )
    assert own == ((2, 4), 4)
    inherited = effective_schedule(_scenario(), defaults, looks=PROFILE_LOOKS, n_max=PROFILE_N_MAX)
    assert inherited == ((4, 8), 8)


def test_an_n_max_that_is_not_a_look_boundary_is_refused_not_invented() -> None:
    """The manifest override's rule (the last look must equal n_max), applied per scenario:
    a schedule with no decision point at n_max would need a look the author never
    pre-registered, and inventing one changes the Pocock correction."""
    with pytest.raises(BellwetherError, match="n_max"):
        effective_schedule(
            _scenario(n_max=10), ScenarioDefaults(), looks=PROFILE_LOOKS, n_max=PROFILE_N_MAX
        )


def test_unsorted_looks_are_refused() -> None:
    with pytest.raises(BellwetherError, match="increasing"):
        effective_schedule(
            _scenario(looks=[8, 4], n_max=8), ScenarioDefaults(), looks=PROFILE_LOOKS, n_max=20
        )


def test_plan_matrix_runs_each_scenario_its_own_number_of_times() -> None:
    target = TargetInfo("api-loop", "anthropic", "frontier")
    a, b = _scenario("a", n_max=4), _scenario("b")
    plans = plan_matrix(
        [a, b], [target], repetitions=6, n_max_for=lambda s: 4 if s.id == "a" else 6
    )
    counts: dict[str, int] = {}
    for plan in plans:
        counts[plan.scenario.id] = counts.get(plan.scenario.id, 0) + 1
    assert counts == {"a": 4, "b": 6}


def test_plan_matrix_holds_a_scenario_override_to_the_two_run_floor() -> None:
    with pytest.raises(BellwetherError, match="at least two"):
        plan_matrix(
            [_scenario("a")],
            [TargetInfo("api-loop", "anthropic", "frontier")],
            repetitions=6,
            n_max_for=lambda _s: 1,
        )
