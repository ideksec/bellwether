"""WP-10: the nondeterminism metrics (§13).

Property-based tests are mandatory here, not optional — the build plan is explicit that
"the property tests are the specification". They assert bounds, identity, monotonicity,
the §11.4 edge cases, renormalisation, rounding-independence, and the two frequency
properties. Two exact tables from the spec (§13.1 lower bounds, §13.5.1.1 sensitivity)
are reproduced to the published digits, and the frequency-independent gate is shown to
fire identically at every look point.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bellwether.metrics import (
    capability_weight,
    compute_bci,
    decide_at_look,
    jaccard_pair,
    min_runs_for_confidence,
    next_look,
    normalised_edit_distance,
    outcome_consistency,
    summarise_capability,
    summarise_outcomes,
    summarise_trajectory,
    trigger_consistency,
    trigger_entropy,
    weighted_jaccard_pair,
    wilson_interval,
)

# ---------------------------------------------------------------------------
# The two done-when tables (§13.1, §13.5.1.1) — exact to the published digits
# ---------------------------------------------------------------------------

POCOCK_Z = 2.289


@pytest.mark.parametrize(
    ("n", "successes", "expected_lb"),
    [
        (6, 6, 0.534),
        (6, 5, 0.380),
        (12, 12, 0.696),
        (12, 11, 0.592),
        (20, 20, 0.792),
        (20, 19, 0.720),
    ],
)
def test_the_achievable_lower_bound_table_reproduces_exactly(
    n: int, successes: int, expected_lb: float
) -> None:
    """§13.1: these calibrate the §16.1 thresholds and MUST reproduce, or they read as bugs."""
    assert wilson_interval(successes, n, z=POCOCK_Z).lower == pytest.approx(expected_lb, abs=0.001)


def _sensitivity_sets(n: int) -> list[frozenset[str]]:
    """§13.5.1.1: a core of five weight-1 classes; one deviant run also reads a canary."""
    core = {"workspace_read", "tool:a", "tool:b", "tool:c", "tool:d"}
    sets = [frozenset(core) for _ in range(n - 1)]
    sets.append(frozenset(core | {"canary_read"}))
    return sets


@pytest.mark.parametrize(
    ("n", "plain", "weighted"),
    [(6, 0.944, 0.778), (12, 0.972, 0.889), (20, 0.983, 0.933)],
)
def test_the_jaccard_sensitivity_table_reproduces_exactly(
    n: int, plain: float, weighted: float
) -> None:
    """§13.5.1.1: the most important caveat in §13. One canary read in twenty passes a 0.9
    weighted threshold — which is why Jaccard is not the mechanism that catches it."""
    metrics = summarise_capability(_sensitivity_sets(n))
    assert metrics.jaccard_plain == pytest.approx(plain, abs=0.001)
    assert metrics.jaccard_weighted == pytest.approx(weighted, abs=0.001)


@pytest.mark.parametrize("n", [6, 12, 20])
def test_a_rare_high_risk_capability_blocks_at_every_look(n: int) -> None:
    """§13.5.1.1 / §24: a capability in exactly one run MUST block at N=6, 12, 20 alike —
    the frequency-independent gate, not Jaccard, is what catches it."""
    metrics = summarise_capability(_sensitivity_sets(n))
    findings = [f.tier1 for f in metrics.rare_findings]
    assert findings == ["canary_read"], f"N={n}"
    # And weighted Jaccard would NOT catch it — at N=20 it clears 0.9.
    if n == 20:
        assert metrics.jaccard_weighted is not None and metrics.jaccard_weighted > 0.9


# ---------------------------------------------------------------------------
# Wilson interval — bounds and ordering
# ---------------------------------------------------------------------------


@given(
    n=st.integers(min_value=1, max_value=500),
    frac=st.floats(min_value=0.0, max_value=1.0),
    z=st.sampled_from([1.96, 2.289]),
)
def test_wilson_interval_is_ordered_and_bounded(n: int, frac: float, z: float) -> None:
    successes = round(frac * n)
    interval = wilson_interval(successes, n, z=z)
    assert 0.0 <= interval.lower <= interval.point <= interval.upper <= 1.0


def test_wilson_at_zero_n_is_the_whole_interval() -> None:
    interval = wilson_interval(0, 0, z=POCOCK_Z)
    assert (interval.lower, interval.upper) == (0.0, 1.0)


def test_more_evidence_never_widens_a_perfect_interval() -> None:
    """§13.1's incentive: more runs tighten the interval, making the gate easier to clear."""
    prev = 0.0
    for n in (6, 12, 20, 50):
        lb = wilson_interval(n, n, z=POCOCK_Z).lower
        assert lb >= prev
        prev = lb


def test_min_runs_for_confidence_is_sobering_and_bounded() -> None:
    """§13.3: roughly 34 at p̂=0.9, roughly 93 at p̂=0.5 — surfacing them is §2's honesty."""
    assert 25 <= min_runs_for_confidence(0.9) <= 45
    assert 80 <= min_runs_for_confidence(0.5) <= 100


# ---------------------------------------------------------------------------
# outcome_consistency — symmetric, rounding-independent, the p̂=0 hazard
# ---------------------------------------------------------------------------


@given(p=st.floats(min_value=0.0, max_value=1.0))
def test_outcome_consistency_is_symmetric_and_bounded(p: float) -> None:
    value = outcome_consistency(p)
    assert 0.0 <= value <= 1.0
    assert outcome_consistency(p) == outcome_consistency(1 - p)


def test_outcome_consistency_edges() -> None:
    assert outcome_consistency(0.0) == 1.0  # the consistently-wrong hazard: fails every run
    assert outcome_consistency(1.0) == 1.0
    assert outcome_consistency(0.5) == 0.0


def test_outcome_consistency_is_rounding_mode_independent() -> None:
    """§13.3: revision 1's ``1 − 2·|p̂ − round(p̂)|`` was asymmetric about 0.5 under
    banker's rounding (round(0.5)=0 but round(1.5)=2). The new form is exact."""
    assert outcome_consistency(0.5) == outcome_consistency(0.5)
    # symmetry about 0.5 to the grid, the property the old form violated
    for p in (0.1, 0.25, 0.4, 0.49, 0.5, 0.51, 0.6, 0.75, 0.9):
        assert outcome_consistency(p) == outcome_consistency(round(1 - p, 6))


def test_consistently_failing_flag_and_flake() -> None:
    stability = summarise_outcomes(["fail", "fail", "pass"])  # p̂ = 1/3
    assert stability.consistently_failing
    assert stability.flake
    perfect = summarise_outcomes(["pass", "pass"])
    assert not perfect.consistently_failing and not perfect.flake


def test_a_set_with_no_evaluable_runs_reports_no_rate() -> None:
    """§13.2: a rate over no evidence is not a number; forcing one launders a broken run."""
    stability = summarise_outcomes(["not_evaluable", "not_evaluable"])
    assert stability.pass_rate is None
    assert stability.denominators.n_evaluable == 0
    assert stability.denominators.evaluable_fraction == 0.0


def test_denominators_never_collapse_the_exclusion_categories() -> None:
    stability = summarise_outcomes(
        ["pass", "fail", "not_evaluable", "excluded_quality"], n_planned=5
    )
    d = stability.denominators
    assert (d.passes, d.fails, d.n_evaluable) == (1, 1, 2)
    assert d.n_not_evaluable == 1 and d.n_excluded_quality == 1
    assert d.n_errored == 3  # 5 planned − 2 evaluable


# ---------------------------------------------------------------------------
# Jaccard — identity, symmetry, bounds, weighted==plain at equal weights
# ---------------------------------------------------------------------------

_classes = st.sampled_from(
    ["workspace_read", "workspace_write", "canary_read", "egress:x", "tool:a"]
)
_capset = st.frozensets(_classes, max_size=5)


@given(a=_capset, b=_capset)
def test_jaccard_is_symmetric_and_bounded(a: frozenset[str], b: frozenset[str]) -> None:
    weights = {
        "workspace_read": 1,
        "workspace_write": 2,
        "canary_read": 10,
        "egress": 10,
        "tool": 1,
    }
    for fn in (jaccard_pair, lambda x, y: weighted_jaccard_pair(x, y, weights)):
        assert 0.0 <= fn(a, b) <= 1.0
        assert fn(a, b) == fn(b, a)
    assert jaccard_pair(a, a) == 1.0


def test_empty_sets_are_perfectly_similar() -> None:
    assert jaccard_pair(frozenset(), frozenset()) == 1.0
    assert weighted_jaccard_pair(frozenset(), frozenset(), {}) == 1.0


@given(a=_capset, b=_capset)
def test_weighted_equals_plain_when_all_weights_equal(a: frozenset[str], b: frozenset[str]) -> None:
    """The identity the build plan names explicitly: J_weighted == J_plain at equal weights."""
    equal = dict.fromkeys(("workspace_read", "workspace_write", "canary_read", "egress", "tool"), 3)
    assert weighted_jaccard_pair(a, b, equal) == pytest.approx(jaccard_pair(a, b))


def test_a_higher_weight_class_dominates_the_disagreement() -> None:
    """The property that makes weighting worth doing: a canary deviation costs more than a
    workspace_read deviation."""
    base = frozenset({"workspace_read"})
    with_canary = frozenset({"workspace_read", "canary_read"})
    with_read = frozenset({"workspace_read", "workspace_write"})
    w = {"workspace_read": 1, "workspace_write": 2, "canary_read": 10}
    assert weighted_jaccard_pair(base, with_canary, w) < weighted_jaccard_pair(base, with_read, w)


def test_capability_weight_strips_the_parameter() -> None:
    w = {"egress": 10, "process": 5, "tool": 1}
    assert capability_weight("egress:evil.com", w) == 10
    assert capability_weight("process:curl", w) == 5
    assert capability_weight("unheard_of_class", w) == 1  # floor, never zero


def test_core_and_peripheral_partition_the_union() -> None:
    sets = [{"a", "b"}, {"a", "c"}, {"a", "b", "c"}]
    metrics = summarise_capability(sets)
    assert metrics.core == ("a",)
    assert {p.tier1 for p in metrics.peripheral} == {"b", "c"}


# ---------------------------------------------------------------------------
# Trajectory — distance metric, clustering determinism, edge cases
# ---------------------------------------------------------------------------


def _seq(*kinds: str) -> list[tuple[str, str | None, str | None]]:
    return [(k, None, None) for k in kinds]


@given(
    a=st.lists(st.sampled_from(["r", "w", "b"]), max_size=8),
    b=st.lists(st.sampled_from(["r", "w", "b"]), max_size=8),
)
def test_edit_distance_is_a_bounded_symmetric_metric(a: list[str], b: list[str]) -> None:
    sa, sb = _seq(*a), _seq(*b)
    d = normalised_edit_distance(sa, sb)
    assert 0.0 <= d <= 1.0
    assert normalised_edit_distance(sa, sb) == normalised_edit_distance(sb, sa)
    assert normalised_edit_distance(sa, sa) == 0.0


def test_trajectory_clustering_is_shuffle_invariant() -> None:
    import random

    sequences = [_seq("r", "w"), _seq("r", "w"), _seq("r", "w", "b"), _seq("b", "b", "b")]
    reference = summarise_trajectory(sequences)
    rng = random.Random(4)
    for _ in range(20):
        shuffled = list(sequences)
        rng.shuffle(shuffled)
        got = summarise_trajectory(shuffled)
        assert got.distinct_clusters == reference.distinct_clusters
        assert got.modal_cluster_share == reference.modal_cluster_share
        assert [c.representative for c in got.clusters] == [
            c.representative for c in reference.clusters
        ]


def test_identical_sequences_form_one_cluster() -> None:
    metrics = summarise_trajectory([_seq("r", "w")] * 5)
    assert metrics.distinct_clusters == 1
    assert metrics.modal_cluster_share == 1.0
    assert metrics.mean_pairwise_distance == 0.0
    assert metrics.h_traj == 0.0


def test_h_traj_is_not_evaluable_at_n_1() -> None:
    """§11.4: any entropy at N=1 is not_evaluable, not 0."""
    metrics = summarise_trajectory([_seq("r")])
    assert metrics.h_traj is None
    assert metrics.modal_cluster_share == 1.0  # share is defined at N=1; entropy is not


def test_noise_floor_labelling() -> None:
    metrics = summarise_trajectory([_seq("r", "w"), _seq("r", "b")], noise_floor_distance=1.0)
    assert metrics.at_noise_floor  # any dispersion at/below the floor is not a real number


# ---------------------------------------------------------------------------
# Trigger entropy
# ---------------------------------------------------------------------------


def test_trigger_entropy_edges() -> None:
    assert trigger_entropy([True, True, True]) == 0.0
    assert trigger_entropy([True, False]) == 1.0
    assert trigger_entropy([True]) is None  # N=1 not_evaluable
    assert trigger_consistency([True, True]) == 1.0


@given(acts=st.lists(st.booleans(), min_size=2, max_size=20))
def test_trigger_entropy_is_bounded(acts: list[bool]) -> None:
    h = trigger_entropy(acts)
    assert h is not None and 0.0 <= h <= 1.0


# ---------------------------------------------------------------------------
# BCI — bounds, renormalisation, monotonicity
# ---------------------------------------------------------------------------


@given(
    outcome=st.floats(0, 1),
    capability=st.floats(0, 1),
    trajectory=st.floats(0, 1),
)
def test_bci_is_bounded(outcome: float, capability: float, trajectory: float) -> None:
    bci = compute_bci(
        {
            "outcome": outcome,
            "capability": capability,
            "trajectory": trajectory,
            "trigger": None,
            "output": None,
        }
    )
    assert 0.0 <= bci.score <= 100.0


def test_renormalisation_recovers_the_full_scale() -> None:
    """§13.7: without renormalising, the max achievable BCI silently becomes 95 and
    min_bci:85 becomes 89.5. All-perfect available components must reach 100."""
    bci = compute_bci(
        {"outcome": 1.0, "capability": 1.0, "trajectory": 1.0, "trigger": None, "output": None}
    )
    assert bci.score == 100.0
    assert {c.name for c in bci.components_used} == {"outcome", "capability", "trajectory"}
    assert {name for name, _ in bci.components_excluded} == {"trigger", "output"}


def test_excluding_a_component_does_not_change_a_uniform_score() -> None:
    full = compute_bci(
        {"outcome": 0.5, "capability": 0.5, "trajectory": 0.5, "trigger": 0.5, "output": 0.5}
    )
    partial = compute_bci(
        {"outcome": 0.5, "capability": 0.5, "trajectory": 0.5, "trigger": None, "output": None}
    )
    assert full.score == partial.score == 50.0


@given(bump=st.floats(0, 1))
def test_bci_is_monotone_in_each_component(bump: float) -> None:
    base = {"outcome": 0.3, "capability": 0.3, "trajectory": 0.3, "trigger": None, "output": None}
    low = compute_bci(base).score
    raised = compute_bci({**base, "capability": max(0.3, bump)}).score
    assert raised >= low - 1e-9


def test_bci_carries_the_consistently_failing_annotation() -> None:
    bci = compute_bci(
        {"outcome": 1.0, "capability": 1.0, "trajectory": 1.0, "trigger": None, "output": None},
        pass_rate=0.2,
    )
    assert bci.consistently_failing
    assert bci.render_guard() == "consistently failing"


def test_a_component_out_of_range_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="must be in"):
        compute_bci({"outcome": 1.5})


# ---------------------------------------------------------------------------
# Sequential design (§13.1)
# ---------------------------------------------------------------------------


def test_the_decision_table() -> None:
    # 6/6 at threshold 0.5: LB 0.534 ≥ 0.5 → pass
    d = decide_at_look(6, 6, threshold=0.5, look_index=1, is_final_look=False, tier1_agreement=True)
    assert d.outcome == "pass"
    # 0/6 at 0.7: UB well below 0.7 → fail
    d = decide_at_look(0, 6, threshold=0.7, look_index=1, is_final_look=False, tier1_agreement=True)
    assert d.outcome == "fail"
    # 5/6 at 0.7: unresolved, not final → continue
    d = decide_at_look(5, 6, threshold=0.7, look_index=1, is_final_look=False, tier1_agreement=True)
    assert d.outcome == "continue"
    # unresolved at the final look → insufficient_evidence
    d = decide_at_look(
        17, 20, threshold=0.7, look_index=3, is_final_look=True, tier1_agreement=True
    )
    assert d.outcome == "insufficient_evidence"


def test_a_pass_is_held_open_while_capabilities_disagree() -> None:
    """§13.1: capability stability is the security-relevant question; a resolved pass
    interval does not stop the set while tier-1 sets still differ."""
    held = decide_at_look(
        6, 6, threshold=0.5, look_index=1, is_final_look=False, tier1_agreement=False
    )
    assert held.outcome == "continue"
    assert held.held_open_for_capability
    # But on the final look it cannot hold open further — it passes.
    final = decide_at_look(
        20, 20, threshold=0.5, look_index=3, is_final_look=True, tier1_agreement=False
    )
    assert final.outcome == "pass"


def test_a_resolved_fail_is_never_held_open() -> None:
    d = decide_at_look(
        0, 6, threshold=0.7, look_index=1, is_final_look=False, tier1_agreement=False
    )
    assert d.outcome == "fail"


def test_an_all_not_evaluable_set_is_never_escalated() -> None:
    d = decide_at_look(
        0,
        0,
        threshold=0.7,
        look_index=1,
        is_final_look=False,
        tier1_agreement=True,
        all_not_evaluable=True,
    )
    assert d.outcome == "insufficient_evidence"


def test_next_look_progression() -> None:
    assert next_look(0) == 6
    assert next_look(6) == 12
    assert next_look(12) == 20
    assert next_look(20) is None


def test_the_high_criticality_consequences_from_the_spec() -> None:
    """§13.1's stated consequences, as a guard on the calibration."""
    # 18/20 gives 0.657, does not clear 0.7
    assert wilson_interval(18, 20, z=POCOCK_Z).lower == pytest.approx(0.657, abs=0.002)
    # 12/12 clears 0.6; 11/12 does not
    assert wilson_interval(12, 12, z=POCOCK_Z).lower >= 0.6
    assert wilson_interval(11, 12, z=POCOCK_Z).lower < 0.6
