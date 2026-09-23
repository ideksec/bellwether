"""The two §7.1 trigger controls decide the verdict (§16.2).

``functional.require_all_should_trigger`` and ``functional.max_false_trigger_rate`` were registered
as enforcing in the control registry and read by nothing — the registry checks that every control
is *classified*, not that the classification is true. So a skill that never loaded, on a scenario
that did not assert activation, reached ``ready`` whenever the base model did the task anyway; and
a skill that fired on every prompt it should have ignored was never counted at all.

Driven through the real path: the scripted api-loop harness, ``drive_evaluation`` (which is where
the policy switch reaches ``analyse_run``), and ``orchestrate`` (which composes the gates).
"""

from __future__ import annotations

from pathlib import Path

from bellwether.cli.orchestrator import TargetInfo, drive_evaluation, orchestrate, plan_matrix
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.harness import ModelTurn, TurnUsage
from tests.test_driver import _TRANSCRIPT, _firstlight_profile, _ReplayExecutor

_TARGET = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")

#: The model answers without ever loading the skill.
_NEVER_ACTIVATES = [ModelTurn(text="done", usage=TurnUsage(input=90, output=10))]


def _profile(**functional: object):  # type: ignore[no-untyped-def]
    profile = _firstlight_profile()
    gates = profile.gates.model_copy(
        update={"functional": profile.gates.functional.model_copy(update=functional)}
    )
    return profile.model_copy(update={"gates": gates})


def _verdict(tmp_path: Path, scenario: Scenario, transcript, profile):  # type: ignore[no-untyped-def]
    plans = plan_matrix([scenario], [_TARGET], repetitions=6)
    readings = drive_evaluation(
        plans, _ReplayExecutor(tmp_path, transcript=transcript), profile=profile
    )
    result = orchestrate(
        skill_name="security-review",
        package_digest="sha256:" + "a" * 64,
        payload_digest="sha256:" + "b" * 64,
        criticality="low",
        profile_name="low",
        profile=profile,
        policy_digest="sha256:" + "c" * 64,
        readings=readings,
        eval_id="triggers",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
        out_dir=tmp_path / "out",
    )
    return result.verdict


def _gate(verdict, name: str):  # type: ignore[no-untyped-def]
    return next((gate for gate in verdict.gates if gate.name == name), None)


# --- require_all_should_trigger --------------------------------------------------------------

_SHOULD_TRIGGER_NO_ACTIVATION_ASSERTION = Scenario(
    id="triggers-on-direct-request",
    expectation="should_trigger",
    prompt="Review.",
    assertions=[AssertionSpec(name="output_matches", params="done")],
)


def test_a_skill_that_never_loads_fails_a_should_trigger_scenario(tmp_path: Path) -> None:
    """The output assertion passes — the base model did the task — but the skill never loaded."""
    verdict = _verdict(
        tmp_path,
        _SHOULD_TRIGGER_NO_ACTIVATION_ASSERTION,
        _NEVER_ACTIVATES,
        _profile(require_all_should_trigger=True),
    )
    assert _gate(verdict, "functional").status == "block"
    assert verdict.verdict == "not_ready"


def test_switching_the_control_off_is_what_lets_it_pass(tmp_path: Path) -> None:
    verdict = _verdict(
        tmp_path,
        _SHOULD_TRIGGER_NO_ACTIVATION_ASSERTION,
        _NEVER_ACTIVATES,
        _profile(require_all_should_trigger=False),
    )
    assert _gate(verdict, "functional").status == "pass"


def test_a_skill_that_loads_is_unaffected(tmp_path: Path) -> None:
    verdict = _verdict(
        tmp_path,
        _SHOULD_TRIGGER_NO_ACTIVATION_ASSERTION,
        _TRANSCRIPT,
        _profile(require_all_should_trigger=True),
    )
    assert _gate(verdict, "functional").status == "pass"


# --- max_false_trigger_rate ------------------------------------------------------------------

_SHOULD_NOT_TRIGGER = Scenario(
    id="triggers-on-direct-request",
    expectation="should_not_trigger",
    prompt="What is the weather?",
    assertions=[AssertionSpec(name="output_matches", params="done")],
)


def test_a_skill_that_fires_on_every_negative_prompt_is_blocked(tmp_path: Path) -> None:
    verdict = _verdict(tmp_path, _SHOULD_NOT_TRIGGER, _TRANSCRIPT, _profile())
    gate = _gate(verdict, "functional.false_trigger")
    assert gate is not None and gate.status == "block"
    assert "6 of 6" in gate.worst_reason
    assert verdict.verdict == "not_ready"


def test_a_skill_that_stays_quiet_passes_the_false_trigger_gate(tmp_path: Path) -> None:
    verdict = _verdict(tmp_path, _SHOULD_NOT_TRIGGER, _NEVER_ACTIVATES, _profile())
    assert _gate(verdict, "functional.false_trigger").status == "pass"


def test_the_threshold_is_the_one_configured(tmp_path: Path) -> None:
    """A rate of 1.0 passes only when the operator allows 1.0 — the value is read, not assumed."""
    verdict = _verdict(
        tmp_path, _SHOULD_NOT_TRIGGER, _TRANSCRIPT, _profile(max_false_trigger_rate=1.0)
    )
    assert _gate(verdict, "functional.false_trigger").status == "pass"


def test_no_negative_scenario_leaves_the_gate_uncomposed_and_says_so(tmp_path: Path) -> None:
    verdict = _verdict(tmp_path, _SHOULD_TRIGGER_NO_ACTIVATION_ASSERTION, _TRANSCRIPT, _profile())
    assert _gate(verdict, "functional.false_trigger") is None
    assert any("functional.false_trigger not composed" in note for note in verdict.notes)
