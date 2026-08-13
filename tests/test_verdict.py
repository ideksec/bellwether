"""WP-11: the verdict engine and the precondition check (§16.2, §16.4).

The done-when: the three unsatisfiable combinations of §16.4 are each caught before a
single run executes, with a message naming the gate, the target, and the remedy. The
§16.2 composition rules — per-target worst, not_evaluable-blocks-with-reason,
descriptive_only-never-ready — are asserted directly.
"""

from __future__ import annotations

import pytest

from bellwether.config.policy_loader import parse_policy
from bellwether.errors import ConfigurationError
from bellwether.verdict import (
    TargetDeclaration,
    TargetGateResult,
    build_gate,
    check_preconditions,
    compose_verdict,
    validate_bci_weights,
    validate_capability_weights,
    worst_status,
)

# ---------------------------------------------------------------------------
# §16.2 composition
# ---------------------------------------------------------------------------


def tgr(target: str, status: str, reason: str = "r") -> TargetGateResult:
    return TargetGateResult(
        target=target, status=status, observed="o", threshold="t", reason=reason
    )  # type: ignore[arg-type]


def test_a_gate_takes_the_worst_target_never_the_average() -> None:
    """§16.2 step 2: passes on frontier, fails on small → the gate blocks. Losing this by
    averaging first defeats the whole multi-model matrix."""
    gate = build_gate("functional", [tgr("frontier", "pass"), tgr("small", "block")])
    assert gate.status == "block"
    assert "small" in gate.worst_reason


def test_worst_status_ordering() -> None:
    assert worst_status(["pass", "warn"]) == "warn"
    assert worst_status(["pass", "not_evaluable"]) == "not_evaluable"
    assert worst_status(["warn", "block"]) == "block"
    assert worst_status(["not_evaluable", "block"]) == "block"
    assert worst_status([]) == "not_evaluable"  # no evidence blocks a required gate


def test_a_block_makes_the_verdict_not_ready() -> None:
    gates = [
        build_gate("a", [tgr("frontier", "pass")]),
        build_gate("b", [tgr("frontier", "block")]),
    ]
    assert compose_verdict(gates).verdict == "not_ready"


def test_a_warn_with_no_block_is_conditional() -> None:
    gates = [build_gate("a", [tgr("frontier", "pass")]), build_gate("b", [tgr("frontier", "warn")])]
    assert compose_verdict(gates).verdict == "conditional"


def test_all_pass_is_ready() -> None:
    gates = [build_gate("a", [tgr("frontier", "pass")]), build_gate("b", [tgr("small", "pass")])]
    assert compose_verdict(gates).verdict == "ready"


def test_not_evaluable_on_a_required_gate_blocks_with_its_reason() -> None:
    """§16.2 step 3: required evidence unavailable blocks, carrying the coverage reason."""
    coverage_reason = "process capture plane inactive (eBPF load denied)"
    gate = build_gate(
        "security_runtime",
        [tgr("frontier", "not_evaluable", coverage_reason)],
        required=True,
    )
    result = compose_verdict([gate])
    assert result.verdict == "not_ready"
    assert gate in result.blocking()
    assert coverage_reason in gate.worst_reason


def test_not_evaluable_on_an_advisory_gate_only_warns() -> None:
    gate = build_gate("regression", [tgr("frontier", "not_evaluable")], required=False)
    assert compose_verdict([gate]).verdict == "conditional"


def test_descriptive_only_can_never_be_ready() -> None:
    """§16.2 step 6: fixed-N mode's ceiling is conditional, however clean the gates."""
    gates = [build_gate("a", [tgr("frontier", "pass")])]
    result = compose_verdict(gates, descriptive_only=True)
    assert result.verdict == "conditional"
    assert any("descriptive_only" in note for note in result.notes)


def test_descriptive_only_still_fails_on_a_block() -> None:
    gates = [build_gate("a", [tgr("frontier", "block")])]
    assert compose_verdict(gates, descriptive_only=True).verdict == "not_ready"


# ---------------------------------------------------------------------------
# §16.4 precondition check — the three (four) unsatisfiable combinations
# ---------------------------------------------------------------------------

ALL_PLANES = frozenset(
    [
        "harness_events",
        "filesystem_writes",
        "filesystem_reads",
        "credentials",
        "egress",
        "dns",
        "process",
    ]
)


def api_loop_target(
    provider: str = "anthropic", *, egress: bool = True, dns: bool = True, structured: bool = True
) -> TargetDeclaration:
    return TargetDeclaration(
        label=f"api-loop/{provider}/frontier",
        provider=provider,
        capabilities={
            "structured_tool_events": structured,
            "egress_observable": egress,
            "dns_observable": dns,
            "controls_skill_presentation": True,
        },
    )


def default_policy(profile: str = "medium") -> object:
    import yaml

    from bellwether.config import template_path

    data = yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8"))
    return parse_policy(data).profile(profile)


def test_an_activation_blind_harness_is_refused_before_running() -> None:
    """§16.4 combo 1: generic-subprocess cannot observe activation, so
    require_all_should_trigger can never pass — caught before the matrix runs."""
    profile = default_policy("medium")
    blind = api_loop_target(structured=False)
    failures = check_preconditions(profile, [blind], available_planes=ALL_PLANES)  # type: ignore[arg-type]

    assert any(f.gate == "functional.require_all_should_trigger" for f in failures)
    message = failures[0].message("medium")
    assert "Cannot start" in message
    assert blind.label in message
    assert "→" in message  # names a remedy


def test_a_required_capture_plane_the_runner_lacks_is_refused() -> None:
    """§16.4 combo 2: the high profile requires the process plane; a runner without it
    cannot satisfy it, so refuse rather than block after a 40-minute run."""
    profile = default_policy("high")
    without_process = ALL_PLANES - {"process"}
    failures = check_preconditions(
        profile, [api_loop_target(), api_loop_target("openai")], available_planes=without_process
    )  # type: ignore[arg-type]

    plane_failures = [f for f in failures if "capture_planes[process]" in f.gate]
    assert plane_failures
    assert "not available on this runner" in plane_failures[0].remedy


def test_min_distinct_providers_two_is_refused_for_a_single_provider_matrix() -> None:
    """§16.4 combo 3: the high profile needs two providers; a single-provider matrix
    cannot satisfy it."""
    profile = default_policy("high")
    single = [api_loop_target("anthropic"), api_loop_target("anthropic")]
    failures = check_preconditions(profile, single, available_planes=ALL_PLANES)  # type: ignore[arg-type]

    assert any(f.gate == "matrix.min_distinct_providers" for f in failures)


def test_an_egress_blind_composition_under_a_blocking_egress_gate_is_refused() -> None:
    """§16.4 combo 4, egress half: a composition with no recording proxy cannot satisfy a
    blocking egress gate — refused with the remedy naming the config switch."""
    profile = default_policy("medium")
    blind = api_loop_target(egress=False)
    failures = check_preconditions(profile, [blind], available_planes=ALL_PLANES)  # type: ignore[arg-type]

    egress_failures = [f for f in failures if f.gate == "security_runtime.egress_outside_allowlist"]
    assert egress_failures
    assert "egress.image" in egress_failures[0].remedy


def test_a_dns_blind_composition_under_a_blocking_dns_gate_is_refused() -> None:
    """§16.4 combo 4, DNS half — checked independently of egress: the proxy and the
    resolver are wired by different config switches, so a wired proxy must not vouch for
    an unwired resolver. Pre-split, one `egress_observable` bit covered both gates and a
    proxy-only composition under `dns_outside_allowlist: block` sailed through."""
    profile = default_policy("medium")
    proxy_only = api_loop_target(egress=True, dns=False)
    failures = check_preconditions(profile, [proxy_only], available_planes=ALL_PLANES)  # type: ignore[arg-type]

    dns_failures = [f for f in failures if f.gate == "security_runtime.dns_outside_allowlist"]
    assert dns_failures
    assert "dns.image" in dns_failures[0].remedy
    # And the egress half stays satisfied — the two channels are judged separately.
    assert not any(f.gate == "security_runtime.egress_outside_allowlist" for f in failures)


def test_a_satisfiable_matrix_produces_no_failures() -> None:
    """The happy path: medium profile, an observant harness, two providers → clear to run."""
    profile = default_policy("medium")
    targets = [api_loop_target("anthropic"), api_loop_target("openai")]
    assert check_preconditions(profile, targets, available_planes=ALL_PLANES) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §16.1 weight validation
# ---------------------------------------------------------------------------


def test_a_denied_class_cannot_be_weighted_zero() -> None:
    """§16.1: weight 0 on a denied class erases it from the risk-weighted Jaccard,
    defeating the gate the deny list is meant to inform."""
    with pytest.raises(ConfigurationError, match="denies"):
        validate_capability_weights({"egress": 0, "workspace_read": 1}, deny_classes={"egress"})


def test_a_denied_tool_cannot_be_weighted_zero() -> None:
    with pytest.raises(ConfigurationError):
        validate_capability_weights({"curl": 0}, deny_classes={"tool:curl"})


def test_non_denied_zero_weights_are_allowed() -> None:
    # A weight of 0 on a class nobody denies is odd but not this validator's concern.
    validate_capability_weights({"workspace_read": 0}, deny_classes={"egress"})


def test_bci_weight_warnings_name_the_problem() -> None:
    zero = validate_bci_weights({"outcome": 0.0, "capability": 1.0})
    assert any("is 0" in w for w in zero)
    far = validate_bci_weights({"outcome": 5.0, "capability": 5.0})
    assert any("far from" in w for w in far)
    ok = validate_bci_weights(
        {"outcome": 0.3, "trigger": 0.2, "trajectory": 0.15, "capability": 0.3, "output": 0.05}
    )
    assert ok == []
