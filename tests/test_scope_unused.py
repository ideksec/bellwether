"""The §12.5 ``unused`` disposition on the scope gate.

Over-declaration is reported by default and blocks only where a profile opts in with
``scope.block_on: [unused]``. Both directions are pinned here — the opt-in must bite, and
the default must not turn a clean run ``conditional`` for a spare declaration.
"""

from __future__ import annotations

import yaml

from bellwether.cli.orchestrator import SetReading, TargetInfo, _scope_result
from bellwether.config.models.policy import ProfileSpec
from bellwether.config.policy_loader import parse_policy
from bellwether.config.templates import template_path

_TARGET = TargetInfo(harness="api-loop", provider="anthropic", model_alias="frontier")


def _profile(block_on: list[str]) -> ProfileSpec:
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    base = policy.profile("low")
    gates = base.gates.model_copy(
        update={"scope": base.gates.scope.model_copy(update={"block_on": block_on})}
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


def test_unused_is_named_but_passes_under_the_shipped_default() -> None:
    result = _scope_result(_reading(scope_unused=("bash",)), _profile(["exceeded"]))
    assert result.status == "pass"
    assert "never used: bash" in result.reason


def test_unused_blocks_where_the_profile_opts_in() -> None:
    result = _scope_result(_reading(scope_unused=("bash",)), _profile(["exceeded", "unused"]))
    assert result.status == "block"
    assert result.observed == "bash"


def test_exceeded_still_wins_over_unused() -> None:
    """A run that both exceeded and under-used its declaration blocks on the exceedance —
    the more serious finding names the gate's reason."""
    reading = _reading(scope_exceeded=("${HOME}/.aws/credentials",), scope_unused=("bash",))
    result = _scope_result(reading, _profile(["exceeded", "unused"]))
    assert result.status == "block"
    assert "outside declared scope" in result.reason


def test_nothing_declared_unused_leaves_the_reason_untouched() -> None:
    result = _scope_result(_reading(), _profile(["exceeded"]))
    assert result.status == "pass"
    assert result.reason == "declared vs observed"
