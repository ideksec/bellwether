"""Regression tests for the metrics/verdict/gate fixes from the security & quality review.

Each test fails against the pre-fix code and passes after. They cover: the inverted rare-
capability gate (BW-03), the two unenforced consistency gates (BW-10), the hard-coded Pocock
boundary (BW-11), the policy→base-class weight resolver (BW-12), the drifted EXIT_REASONS
constant (BW-38), and the silently-dropped BCI component (BW-41).
"""

from __future__ import annotations

import yaml

from bellwether.cli.orchestrator import (
    SetReading,
    TargetInfo,
    _consistency_result,
    _rare_threshold_for,
    resolve_capability_weights,
)
from bellwether.config import template_path
from bellwether.config.models.policy import ProfileSpec
from bellwether.config.policy_loader import parse_policy
from bellwether.constants import DEFAULT_CAPABILITY_WEIGHTS, EXIT_REASONS
from bellwether.metrics import summarise_capability, summarise_outcomes
from bellwether.metrics.bci import compute_bci
from bellwether.metrics.sequential import decide_at_look
from bellwether.metrics.stats import wilson_interval

_TARGET = TargetInfo(harness="api-loop", provider="anthropic", model_alias="haiku")


def _profile(**consistency: object) -> ProfileSpec:
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    base = policy.profile("low")
    gates = base.gates.model_copy(
        update={"consistency": base.gates.consistency.model_copy(update=consistency)}
    )
    return base.model_copy(update={"gates": gates})


def _reading(**overrides: object) -> SetReading:
    defaults: dict[str, object] = {
        "scenario_id": "s",
        "target": _TARGET,
        "n_completed": 6,
        "n_evaluable": 6,
        "pass_rate": 1.0,
        "lower_bound": 0.6,
        "functional_threshold": 0.5,
        "look": 6,
        "look_outcome": "pass",
        "bci": 100.0,
        "consistently_failing": False,
        "jaccard_weighted": 1.0,
        "jaccard_plain": 1.0,
        "modal_trajectory_share": 1.0,
        "mean_pairwise_distance": 0.0,
        "rare_capability_risk": "none",
        "rare_capability_blocking": False,
        "tier1_agreement": True,
        "scope_exceeded": (),
        "egress_observed": True,
        "egress_blocked": False,
        "weights_digest": "sha256:0",
        "runs": (),
    }
    defaults.update(overrides)
    return SetReading(**defaults)  # type: ignore[arg-type]


# --- BW-03: the rare-capability gate is no longer inverted -----------------------------


def test_rare_threshold_tightens_as_severity_rises() -> None:
    # Spec §13.5.2: low→10, medium→5, high→3; raising the knob LOWERS the weight cutoff.
    assert _rare_threshold_for("low") == 10
    assert _rare_threshold_for("medium") == 5
    assert _rare_threshold_for("high") == 3
    assert _rare_threshold_for("critical") <= 3


def test_a_weight5_rare_capability_is_caught_at_medium_not_low() -> None:
    # `process:*` has weight 5; it appears in 1 of 3 runs (rare). At the shipped 'medium'
    # default (threshold 5) it MUST be a rare finding; at 'low' (threshold 10) it must not.
    sets = [{"workspace_read"}, {"workspace_read"}, {"workspace_read", "process:cat"}]
    at_medium = summarise_capability(
        sets, rare_capability_weight_threshold=_rare_threshold_for("medium")
    )
    at_low = summarise_capability(sets, rare_capability_weight_threshold=_rare_threshold_for("low"))
    assert any(f.tier1 == "process:cat" for f in at_medium.rare_findings)
    assert not at_low.rare_findings


def test_consistency_gate_blocks_on_a_rare_capability() -> None:
    assert (
        _consistency_result(_reading(rare_capability_blocking=True), _profile()).status == "block"
    )
    assert (
        _consistency_result(_reading(rare_capability_blocking=False), _profile()).status == "pass"
    )


# --- BW-10: the two trajectory gates are now enforced ----------------------------------


def test_modal_trajectory_share_gate_is_enforced() -> None:
    profile = _profile(min_modal_trajectory_share=0.4)
    result = _consistency_result(_reading(modal_trajectory_share=0.2), profile)
    assert result.status == "warn"
    assert "modal trajectory share" in result.reason


def test_mean_edit_distance_gate_is_enforced() -> None:
    profile = _profile(max_mean_edit_distance=0.6)
    result = _consistency_result(_reading(mean_pairwise_distance=0.785), profile)
    assert result.status == "warn"
    assert "mean edit distance" in result.reason


# --- BW-11: the Pocock boundary is threaded, not hard-coded -----------------------------


def test_decide_at_look_respects_the_configured_boundary_z() -> None:
    common: dict[str, object] = {
        "threshold": 0.5,
        "look_index": 1,
        "is_final_look": True,
        "tier1_agreement": True,
    }
    single_look = decide_at_look(6, 6, boundary_z=1.960, **common)  # type: ignore[arg-type]
    default = decide_at_look(6, 6, **common)  # type: ignore[arg-type]
    assert single_look.lower_bound == wilson_interval(6, 6, z=1.960).lower  # 0.609657
    assert default.lower_bound == wilson_interval(6, 6, z=2.289).lower  # 0.533831
    assert single_look.lower_bound != default.lower_bound


def test_summarise_outcomes_respects_the_configured_pocock_z() -> None:
    stability = summarise_outcomes(["pass"] * 6, pocock_z=1.960)
    assert stability.pocock_interval is not None
    assert stability.pocock_interval.lower == wilson_interval(6, 6, z=1.960).lower


# --- BW-12: policy weight keys resolve onto the metric's base classes -------------------


def test_default_policy_weights_resolve_to_the_metric_table() -> None:
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    resolved = resolve_capability_weights(policy.profile("low").metrics.capability_risk_weights)
    # The shipped default reproduces the metric's base-class table exactly (a no-op).
    assert resolved == {cls: int(w) for cls, w in DEFAULT_CAPABILITY_WEIGHTS.items()}


def test_a_policy_override_reaches_the_base_class() -> None:
    resolved = resolve_capability_weights({"egress_non_model": 20.0, "process_exec": 7.0})
    assert resolved["egress"] == 20  # not the ignored 'egress_non_model' key
    assert resolved["process"] == 7
    # Classes the policy did not mention keep their §13.5.1 defaults, not the floor.
    assert resolved["egress_blocked"] == DEFAULT_CAPABILITY_WEIGHTS["egress_blocked"]
    assert resolved["workspace_delete"] == DEFAULT_CAPABILITY_WEIGHTS["workspace_delete"]


# --- BW-38: EXIT_REASONS agrees with the run-outcome logic ------------------------------


def test_exit_reasons_agree_with_run_outcome_sets() -> None:
    from bellwether.assertions import results

    failing = {reason for reason, kind in EXIT_REASONS.items() if kind == "fail"}
    not_evaluable = {reason for reason, kind in EXIT_REASONS.items() if kind == "not_evaluable"}
    assert failing == set(results._FAILING_EXITS)
    assert not_evaluable == set(results._NOT_EVALUABLE_EXITS)
    # The two that had drifted:
    assert EXIT_REASONS["sandbox_error"] == "fail"
    assert EXIT_REASONS["harness_error"] == "fail"


# --- BW-41: a supplied-but-unweighted BCI component is recorded, not dropped ------------


def test_compute_bci_records_an_unweighted_component() -> None:
    bci = compute_bci({"outcome": 0.0, "capability": 1.0}, weights={"outcome": 0.3})
    excluded = {name for name, _reason in bci.components_excluded}
    assert "capability" in excluded  # supplied a value but had no weight — must not vanish
    assert bci.score == 0.0
