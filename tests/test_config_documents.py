"""Every document the specification shows as an example must load (WP-1 done criteria)."""

from __future__ import annotations

from typing import Any

import pytest

from bellwether.config import (
    parse_config,
    parse_manifest,
    parse_policy,
    parse_scenarios,
    resolve_model_id,
)
from bellwether.errors import ConfigurationError


def test_shipped_config_template_parses(config_document: dict[str, Any]) -> None:
    config = parse_config(config_document)
    assert config.sandbox.pids_limit == 512
    assert config.sandbox.timeout_seconds == 900
    assert config.egress.deployment == "sidecar"
    assert config.dns.mode == "controlled_resolver"
    assert config.capture.zones.workspace == "/work"


def test_shipped_config_ships_no_model_identifiers(config_document: dict[str, Any]) -> None:
    """A literal model string outside a user's own config.yaml is a bug (§6.2)."""
    config = parse_config(config_document)
    for name, provider in config.providers.items():
        assert provider.unfilled_aliases() == sorted(provider.models), (
            f"provider {name} ships a concrete model id; model names change and a stale "
            "one is the most likely first-run failure"
        )


def test_config_advises_on_unpinned_image_and_placeholders(config_document: dict[str, Any]) -> None:
    advisories = " ".join(parse_config(config_document).advisories())
    assert "not pinned by digest" in advisories
    assert "placeholders" in advisories


def test_resolve_model_id_refuses_a_placeholder(config_document: dict[str, Any]) -> None:
    config = parse_config(config_document)
    with pytest.raises(ConfigurationError) as caught:
        resolve_model_id(config, "anthropic", "frontier")
    assert "placeholder" in str(caught.value)


def test_resolve_model_id_returns_a_filled_in_identifier(config_document: dict[str, Any]) -> None:
    config_document["providers"]["anthropic"]["models"]["frontier"] = "some-model-2026-01-01"
    config = parse_config(config_document)
    assert resolve_model_id(config, "anthropic", "frontier") == "some-model-2026-01-01"


def test_resolve_model_id_names_the_alternatives(config_document: dict[str, Any]) -> None:
    config = parse_config(config_document)
    with pytest.raises(ConfigurationError) as caught:
        resolve_model_id(config, "anthropic", "enormous")
    message = str(caught.value)
    assert "enormous" in message
    assert "frontier" in message and "mid" in message and "small" in message


def test_yaml_off_is_not_read_as_a_boolean(config_document: dict[str, Any]) -> None:
    """YAML 1.1 parses a bare ``off`` as False; the user meant the word (§21)."""
    config_document["dns"]["mode"] = False
    config_document["capture"]["process"] = False
    config = parse_config(config_document)
    assert config.dns.mode == "off"
    assert config.capture.process == "off"


def test_enforced_settings_are_detected(config_document: dict[str, Any]) -> None:
    """§21 names five settings whose disablement makes a result unearned."""
    config_document["dns"]["mode"] = "off"
    config_document["egress"]["scan_model_api_bodies"] = False
    config_document["egress"]["deployment"] = "inprocess"
    config_document["canaries"]["redact_at_capture"] = False
    config_document["canaries"]["randomize_markers"] = False

    violations = {v.path for v in parse_config(config_document).enforced_setting_violations()}
    assert violations == {
        "dns.mode",
        "egress.scan_model_api_bodies",
        "egress.deployment",
        "canaries.redact_at_capture",
        "canaries.randomize_markers",
    }


def test_default_config_has_no_enforced_setting_violations(config_document: dict[str, Any]) -> None:
    assert parse_config(config_document).enforced_setting_violations() == []


# ---------------------------------------------------------------------------
# policy.yaml
# ---------------------------------------------------------------------------


def test_shipped_policy_template_parses(policy_document: dict[str, Any]) -> None:
    policy = parse_policy(policy_document)
    assert sorted(policy.profiles) == ["high", "low", "medium"]
    assert policy.defaults.matrix.looks == [6, 12, 20]
    assert policy.defaults.matrix.boundary_z == pytest.approx(2.289)


def test_profiles_deep_merge_over_defaults(policy_document: dict[str, Any]) -> None:
    """A profile naming one threshold overrides that threshold and nothing else.

    YAML's own merge key is shallow, so ``medium``'s two-key ``gates`` block would
    otherwise replace the entire default gate set — turning the profile that reads as
    stricter into one that enforces almost nothing.
    """
    policy = parse_policy(policy_document)
    medium = policy.profile("medium")

    assert medium.gates.functional.min_pass_rate_lower_bound == pytest.approx(0.6)
    assert medium.gates.consistency.min_bci == pytest.approx(80)
    # Inherited, not lost:
    assert medium.gates.functional.max_false_trigger_rate == pytest.approx(0.2)
    assert medium.gates.security_runtime.canary_leak == "block"
    assert medium.gates.regression.max_pass_rate_drop == pytest.approx(0.1)
    assert medium.matrix.looks == [6, 12, 20]


def test_high_profile_keeps_inherited_matrix_while_overriding_one_key(
    policy_document: dict[str, Any],
) -> None:
    high = parse_policy(policy_document).profile("high")
    assert high.matrix.min_distinct_providers == 2
    assert [target.label() for target in high.matrix.required_targets] == [
        "claude-code/anthropic/frontier",
        "claude-code/anthropic/small",
    ]
    assert high.requires is not None
    assert "process" in high.requires.capture_planes


def test_criticality_selects_a_profile(policy_document: dict[str, Any]) -> None:
    policy = parse_policy(policy_document)
    assert policy.profile_for_criticality("high").gates.static.max_severity_allowed == "low"


def test_looks_and_boundary_must_agree(policy_document: dict[str, Any]) -> None:
    """Changing the number of looks without changing z claims a correction not made."""
    policy_document["defaults"]["matrix"]["looks"] = [10, 20]
    policy_document["defaults"]["matrix"]["n_max"] = 20
    with pytest.raises(ConfigurationError) as caught:
        parse_policy(policy_document)
    assert "Pocock" in str(caught.value)


def test_last_look_must_equal_n_max(policy_document: dict[str, Any]) -> None:
    policy_document["defaults"]["matrix"]["n_max"] = 30
    with pytest.raises(ConfigurationError) as caught:
        parse_policy(policy_document)
    assert "n_max" in str(caught.value)


def test_selection_must_name_defined_profiles(policy_document: dict[str, Any]) -> None:
    policy_document["selection"]["by_criticality"]["high"] = "paranoid"
    with pytest.raises(ConfigurationError) as caught:
        parse_policy(policy_document)
    assert "paranoid" in str(caught.value)


# ---------------------------------------------------------------------------
# evals/manifest.yaml
# ---------------------------------------------------------------------------


def test_example_manifest_parses(manifest_document: dict[str, Any]) -> None:
    manifest = parse_manifest(manifest_document)
    assert manifest.metadata.criticality == "high"
    assert manifest.declared_scope.tools.allow == ["Read", "Grep", "Glob", "Bash"]
    assert manifest.declared_scope.network.egress_allow == []


def test_manifest_accepts_both_spellings_of_the_model_alias_key(
    manifest_document: dict[str, Any],
) -> None:
    """policy.yaml writes ``model_alias``; manifest.yaml writes ``model`` (§6.2, §16.1)."""
    manifest = parse_manifest(manifest_document)
    assert manifest.matrix is not None
    assert [target.model_alias for target in manifest.matrix.targets] == ["frontier", "small"]


def test_a_review_digest_must_look_like_a_digest(manifest_document: dict[str, Any]) -> None:
    manifest_document["metadata"]["review"]["last_human_review"]["package_digest"] = "reviewed"
    with pytest.raises(ConfigurationError) as caught:
        parse_manifest(manifest_document)
    assert "sha256:" in str(caught.value)


def test_a_truncated_review_digest_loads_but_is_not_wellformed(
    manifest_document: dict[str, Any],
) -> None:
    """A malformed digest never matches, so the review gate reads ``stale`` (§6.3).

    Failing to load would make an unreviewed manifest easier to ship than a mistyped one.
    """
    manifest_document["metadata"]["review"]["last_human_review"]["package_digest"] = "sha256:abc"
    manifest = parse_manifest(manifest_document)
    assert manifest.metadata.review is not None
    review = manifest.metadata.review.last_human_review
    assert review is not None and not review.is_wellformed()


def test_a_tool_cannot_be_both_allowed_and_denied(manifest_document: dict[str, Any]) -> None:
    manifest_document["declared_scope"]["tools"]["deny"].append("Bash")
    with pytest.raises(ConfigurationError) as caught:
        parse_manifest(manifest_document)
    assert "Bash" in str(caught.value)


# ---------------------------------------------------------------------------
# evals/scenarios.yaml
# ---------------------------------------------------------------------------


def test_example_scenarios_parse(scenarios_document: dict[str, Any]) -> None:
    suite = parse_scenarios(scenarios_document)
    assert len(suite.scenarios) == 5
    first = suite.by_id("triggers-on-direct-request")
    assert [assertion.name for assertion in first.assertions][:3] == [
        "skill_activated",
        "tool_called",
        "file_written",
    ]
    assert first.assertions[1].params == {"name": "Read", "min": 1}


def test_unknown_assertion_names_the_catalogue(scenarios_document: dict[str, Any]) -> None:
    scenarios_document["scenarios"][0]["assert"].append({"tool_calls": {"name": "Read"}})
    with pytest.raises(ConfigurationError) as caught:
        parse_scenarios(scenarios_document)
    message = str(caught.value)
    assert "tool_calls" in message
    assert "tool_called" in message  # did-you-mean


def test_duplicate_scenario_ids_are_rejected(scenarios_document: dict[str, Any]) -> None:
    duplicate = dict(scenarios_document["scenarios"][1])
    duplicate["id"] = scenarios_document["scenarios"][0]["id"]
    scenarios_document["scenarios"].append(duplicate)
    with pytest.raises(ConfigurationError) as caught:
        parse_scenarios(scenarios_document)
    assert "duplicate scenario id" in str(caught.value)


def test_ambiguous_scenarios_may_only_record(scenarios_document: dict[str, Any]) -> None:
    """§7.1: record the activation rate, do not fail on either outcome."""
    ambiguous = next(
        scenario
        for scenario in scenarios_document["scenarios"]
        if scenario["expectation"] == "ambiguous"
    )
    ambiguous["assert"] = [{"skill_activated": True}]
    with pytest.raises(ConfigurationError) as caught:
        parse_scenarios(scenarios_document)
    assert "record_only" in str(caught.value)


def test_a_scenario_needs_at_least_one_assertion(scenarios_document: dict[str, Any]) -> None:
    scenarios_document["scenarios"][0]["assert"] = []
    with pytest.raises(ConfigurationError) as caught:
        parse_scenarios(scenarios_document)
    assert "at least one assertion" in str(caught.value)


def test_two_assertions_in_one_list_entry_are_rejected(
    scenarios_document: dict[str, Any],
) -> None:
    scenarios_document["scenarios"][0]["assert"] = [{"no_egress": True, "no_credential_read": True}]
    with pytest.raises(ConfigurationError) as caught:
        parse_scenarios(scenarios_document)
    assert "exactly one assertion" in str(caught.value)
