"""Every deliberately-malformed document must produce a readable error (§21).

"All config MUST be validated with clear error messages that name the file, the path
within it, and the allowed values. Use pydantic and render validation errors as human
sentences, not stack traces."

A user meets Bellwether for the first time through one of these messages.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from bellwether.config import load_config, parse_config, parse_policy, parse_scenarios
from bellwether.errors import ConfigurationError

SOURCE = ".bellwether/config.yaml"


def _mutate(document: dict[str, Any], mutate: Callable[[dict[str, Any]], None]) -> str:
    mutate(document)
    with pytest.raises(ConfigurationError) as caught:
        parse_config(document, SOURCE)
    return str(caught.value)


def test_unknown_enum_value_lists_the_allowed_values(config_document: dict[str, Any]) -> None:
    message = _mutate(config_document, lambda d: d["sandbox"].__setitem__("backend", "podman"))
    assert SOURCE in message
    assert "sandbox.backend" in message
    assert "docker" in message and "gvisor" in message and "firecracker" in message
    assert "podman" in message


def test_a_typo_suggests_the_field_it_meant(config_document: dict[str, Any]) -> None:
    message = _mutate(config_document, lambda d: d["sandbox"].__setitem__("cpu", 2))
    assert "unknown field 'cpu'" in message
    assert "did you mean 'cpus'" in message


def test_a_typo_with_no_near_match_lists_the_known_fields(
    config_document: dict[str, Any],
) -> None:
    message = _mutate(config_document, lambda d: d["sandbox"].__setitem__("zzz", 1))
    assert "known fields:" in message
    assert "pids_limit" in message


def test_wrong_type_names_the_path_and_the_value(config_document: dict[str, Any]) -> None:
    message = _mutate(config_document, lambda d: d["sandbox"].__setitem__("pids_limit", "many"))
    assert "sandbox.pids_limit" in message
    assert "integer" in message
    assert "'many'" in message


def test_out_of_range_value_is_explained(config_document: dict[str, Any]) -> None:
    message = _mutate(config_document, lambda d: d["execution"].__setitem__("concurrency", 0))
    assert "execution.concurrency" in message
    assert "greater than or equal to 1" in message


def test_missing_required_field(config_document: dict[str, Any]) -> None:
    message = _mutate(config_document, lambda d: d["sandbox"].pop("image"))
    assert "sandbox.image" in message
    assert "required field is missing" in message


def test_wrong_api_version(config_document: dict[str, Any]) -> None:
    message = _mutate(config_document, lambda d: d.__setitem__("apiVersion", "bellwether/v2"))
    assert "apiVersion" in message
    assert "bellwether/v1" in message


def test_wrong_kind(config_document: dict[str, Any]) -> None:
    message = _mutate(config_document, lambda d: d.__setitem__("kind", "Policy"))
    assert "kind" in message
    assert "Config" in message


def test_bci_weights_that_do_not_sum_to_one(config_document: dict[str, Any]) -> None:
    message = _mutate(
        config_document, lambda d: d["metrics"]["bci_weights"].__setitem__("output", 0.5)
    )
    assert "sum to 1.0" in message
    assert "renormalisation" in message


def test_judge_pointing_at_an_unconfigured_provider(config_document: dict[str, Any]) -> None:
    message = _mutate(
        config_document, lambda d: d["judges"]["default"].__setitem__("provider", "x")
    )
    assert "not a configured provider" in message
    assert "anthropic" in message


def test_several_problems_are_all_reported(config_document: dict[str, Any]) -> None:
    config_document["sandbox"]["backend"] = "podman"
    config_document["execution"]["concurrency"] = 0
    with pytest.raises(ConfigurationError) as caught:
        parse_config(config_document, SOURCE)
    error = caught.value
    assert len(error.problems) == 2
    assert "2 problems" in str(error)


def test_no_stack_trace_vocabulary_leaks_into_the_message(
    config_document: dict[str, Any],
) -> None:
    message = _mutate(config_document, lambda d: d["sandbox"].__setitem__("pids_limit", []))
    for leak in ("Traceback", "ValidationError", "pydantic", "self.", "__init__"):
        assert leak not in message


# ---------------------------------------------------------------------------
# Document-level problems
# ---------------------------------------------------------------------------


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError) as caught:
        load_config(tmp_path / "nope.yaml")
    assert "file not found" in str(caught.value)


def test_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("\n", encoding="utf-8")
    with pytest.raises(ConfigurationError) as caught:
        load_config(path)
    assert "is empty" in str(caught.value)


def test_yaml_syntax_error_reports_line_and_column(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("apiVersion: bellwether/v1\nkind: Config\n  bad: [1, 2\n", encoding="utf-8")
    with pytest.raises(ConfigurationError) as caught:
        load_config(path)
    message = str(caught.value)
    assert "not valid YAML" in message
    assert "line" in message and "column" in message


def test_a_top_level_list_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ConfigurationError) as caught:
        load_config(path)
    assert "must be a mapping" in str(caught.value)


def test_policy_profiles_must_be_mappings(policy_document: dict[str, Any]) -> None:
    policy_document["profiles"]["low"] = ["not", "a", "mapping"]
    with pytest.raises(ConfigurationError) as caught:
        parse_policy(policy_document)
    assert "profiles.low" in str(caught.value)


def test_scenario_assertions_must_be_mappings(scenarios_document: dict[str, Any]) -> None:
    scenarios_document["scenarios"][0]["assert"] = ["no_egress"]
    with pytest.raises(ConfigurationError) as caught:
        parse_scenarios(scenarios_document)
    assert "mapping" in str(caught.value)


def test_scenario_id_shape_is_constrained(scenarios_document: dict[str, Any]) -> None:
    scenarios_document["scenarios"][0]["id"] = "Triggers On Direct Request"
    with pytest.raises(ConfigurationError) as caught:
        parse_scenarios(scenarios_document)
    assert "scenario id" in str(caught.value)
