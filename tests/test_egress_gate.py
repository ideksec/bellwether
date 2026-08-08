"""The egress gate, decided from observed proxy evidence (§10.5, §16.2).

Once the recording proxy is wired into a run, egress stops being `not_evaluable` and becomes a
real gate: an observed-clean run passes, an observed run with a default-deny block takes the
policy disposition, and a run where the proxy never ran still defers. These pin that decision
table on `_security_runtime_result` directly, so it does not depend on standing up a container.
"""

from __future__ import annotations

import yaml

from bellwether.cli.orchestrator import SetReading, TargetInfo, _security_runtime_result
from bellwether.config import template_path
from bellwether.config.models.policy import ProfileSpec
from bellwether.config.policy_loader import parse_policy

_TARGET = TargetInfo(harness="api-loop", provider="anthropic", model_alias="haiku")


def _profile(egress: str) -> ProfileSpec:
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    base = policy.profile("low")
    security = base.gates.security_runtime.model_copy(update={"egress_outside_allowlist": egress})
    return base.model_copy(
        update={"gates": base.gates.model_copy(update={"security_runtime": security})}
    )


def _reading(*, egress_observed: bool, egress_blocked: bool) -> SetReading:
    return SetReading(
        scenario_id="s",
        target=_TARGET,
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
        egress_observed=egress_observed,
        egress_blocked=egress_blocked,
        weights_digest="sha256:0",
        runs=(),
    )


def test_observed_and_clean_passes() -> None:
    result = _security_runtime_result(
        _reading(egress_observed=True, egress_blocked=False), _profile("block")
    )
    assert result.status == "pass"
    assert "no egress outside the allowlist" in result.reason


def test_observed_block_under_a_blocking_profile_blocks() -> None:
    result = _security_runtime_result(
        _reading(egress_observed=True, egress_blocked=True), _profile("block")
    )
    assert result.status == "block"
    assert "outside the allowlist" in result.reason


def test_observed_block_under_a_warn_profile_only_warns() -> None:
    """A softer profile downgrades the same evidence to a warning rather than a hard block."""
    result = _security_runtime_result(
        _reading(egress_observed=True, egress_blocked=True), _profile("warn")
    )
    assert result.status == "warn"


def test_unobserved_defers() -> None:
    """The proxy did not run, so the channel is unobserved — never called clean."""
    result = _security_runtime_result(
        _reading(egress_observed=False, egress_blocked=False), _profile("block")
    )
    assert result.status == "not_evaluable"
    assert "not observed" in result.reason
