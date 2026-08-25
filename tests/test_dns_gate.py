"""The DNS gate, decided from Plane E resolver evidence (§10.6, §16.2).

An HTTP proxy never sees UDP/53, so without the controlled resolver DNS is the covert
channel that routes entirely around the egress plane. Once the resolver observes a run,
the lookup class stops being report-only and becomes a scored gate: an observed-clean set
passes, an observed refusal takes the policy disposition, and a set the resolver did not
watch defers. These pin the decision table on `_dns_result` directly, mirroring
`test_canary_gate.py`; the end-to-end path (a blocked-lookup trace driving the composed
verdict) lives in `test_orchestrator.py`.
"""

from __future__ import annotations

import yaml

from bellwether.cli.orchestrator import SetReading, TargetInfo, _dns_result
from bellwether.config import template_path
from bellwether.config.models.policy import ProfileSpec
from bellwether.config.policy_loader import parse_policy

_TARGET = TargetInfo(harness="api-loop", provider="anthropic", model_alias="haiku")


def _profile(dns_outside_allowlist: str) -> ProfileSpec:
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    base = policy.profile("low")
    security = base.gates.security_runtime.model_copy(
        update={"dns_outside_allowlist": dns_outside_allowlist}
    )
    return base.model_copy(
        update={"gates": base.gates.model_copy(update={"security_runtime": security})}
    )


def _reading(*, dns_observed: bool, dns_blocked: bool) -> SetReading:
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
        egress_observed=True,
        egress_blocked=False,
        weights_digest="sha256:0",
        runs=(),
        dns_observed=dns_observed,
        dns_blocked=dns_blocked,
    )


def test_resolved_and_clean_passes() -> None:
    result = _dns_result(_reading(dns_observed=True, dns_blocked=False), _profile("block"))
    assert result.status == "pass"
    assert "refused none" in result.reason


def test_a_blocked_lookup_under_a_blocking_profile_blocks() -> None:
    result = _dns_result(_reading(dns_observed=True, dns_blocked=True), _profile("block"))
    assert result.status == "block"
    assert "outside the allowlist" in result.reason


def test_a_blocked_lookup_under_a_warn_profile_only_warns() -> None:
    """A softer profile downgrades the same evidence to a warning rather than a hard block."""
    result = _dns_result(_reading(dns_observed=True, dns_blocked=True), _profile("warn"))
    assert result.status == "warn"


def test_unresolvered_defers_rather_than_passing() -> None:
    """No resolver means the lookups were not observed — the gate defers with the reason,
    never reads an unwatched channel as clean (§10.7). This is what keeps the scripted,
    first-light, and demo paths honest: DNS stays an advisory not_evaluable there."""
    result = _dns_result(_reading(dns_observed=False, dns_blocked=False), _profile("block"))
    assert result.status == "not_evaluable"
    assert "not observed" in result.reason


def test_a_blocked_lookup_in_an_otherwise_unobserved_set_still_surfaces() -> None:
    """One run recorded a refusal but another ran without the resolver: the set defers on
    completeness, and the disposition still governs how the composed verdict treats the
    required gate — a refusal plus an incomplete plane must never total to a pass."""
    result = _dns_result(_reading(dns_observed=False, dns_blocked=True), _profile("block"))
    assert result.status == "not_evaluable"
