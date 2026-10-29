"""The generic probe suite (§5 external mode, §7.6) and the path that runs it.

A third-party skill has no ``evals/scenarios.yaml``. Before this, ``run`` refused it and
``bellwether probe`` was a stub. Now the suite is generated from the skill's description and
runs through the ordinary pipeline, with the verdict saying what §7.6 requires it to say: task
quality was not evaluated. These pin the generator, the selection rule (an authored suite always
wins; a skill with no scenarios still refuses unless asked), the note, and the command's front
door.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from bellwether.cli.app import app
from bellwether.cli.run import probe_coverage_note, scenario_suite_for
from bellwether.config.models.scenarios import ScenarioSuite
from bellwether.errors import BellwetherError, SkillError
from bellwether.skill import (
    ACTIVATION_PROBE_ID,
    REPRESENTATIVE_PROBE_ID,
    UNRELATED_PROMPTS,
    generic_probe_suite,
    load_skill,
    unrelated_probe_id,
)
from tests.test_run import _evaluate

runner = CliRunner()


def _external_skill(tmp_path: Path, *, description: str = "Reviews code.") -> Path:
    """A third-party skill as it arrives: SKILL.md and nothing under evals/."""
    root = tmp_path / "security-review"
    root.mkdir()
    front = f"description: {description}\n" if description else ""
    (root / "SKILL.md").write_text(
        f"---\nname: security-review\n{front}---\nbody\n", encoding="utf-8"
    )
    return root


# ---------------------------------------------------------------------------
# The generator
# ---------------------------------------------------------------------------


def test_the_suite_has_the_three_probe_kinds_of_section_7_6() -> None:
    suite = generic_probe_suite("security-review", "Reviews code for security issues.")
    by_id = {scenario.id: scenario for scenario in suite.scenarios}
    activation = by_id[ACTIVATION_PROBE_ID]
    assert activation.expectation == "should_trigger" and activation.probe == "activation"
    # The description, echoed back as the prompt — the §7.4 coexistence matrix reads this one.
    assert activation.prompt == "Reviews code for security issues."
    representative = by_id[REPRESENTATIVE_PROBE_ID]
    assert representative.expectation == "should_trigger"
    assert representative.probe == "representative"
    assert "Reviews code for security issues." in representative.prompt
    unrelated = [s for s in suite.scenarios if s.expectation == "should_not_trigger"]
    assert [s.id for s in unrelated] == [
        unrelated_probe_id(i) for i in range(1, len(UNRELATED_PROMPTS) + 1)
    ]
    assert [s.prompt for s in unrelated] == list(UNRELATED_PROMPTS)
    assert all("probe" in s.tags for s in suite.scenarios)


def test_the_suite_is_a_valid_authored_suite() -> None:
    """Round-trips through the same loader an evals/scenarios.yaml takes: ids unique, every
    assertion known, the representative probe's record_only well formed."""
    suite = generic_probe_suite("x", "Does a thing.")
    text = yaml.safe_dump(suite.model_dump(by_alias=True, exclude_none=True))
    reloaded = ScenarioSuite.model_validate(yaml.safe_load(text))
    assert reloaded == suite


def test_whitespace_in_the_description_is_collapsed_and_the_suite_is_deterministic() -> None:
    a = generic_probe_suite("x", "Reviews   code\n  for issues.")
    b = generic_probe_suite("x", "Reviews code for issues.")
    assert a == b


def test_a_skill_with_no_description_is_refused_not_guessed() -> None:
    with pytest.raises(SkillError, match="no description"):
        generic_probe_suite("x", "   ")


# ---------------------------------------------------------------------------
# Selection: an authored suite wins; no scenarios refuses unless asked
# ---------------------------------------------------------------------------


def test_an_authored_suite_is_never_replaced_by_the_generated_one(tmp_path: Path) -> None:
    root = _external_skill(tmp_path)
    (root / "evals").mkdir()
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n  - id: mine\n    expectation: should_trigger\n"
        '    prompt: "Review this project."\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    package = load_skill(root)
    chosen = scenario_suite_for(package, generic_probes=True)
    assert chosen is package.scenarios
    assert [s.id for s in chosen.scenarios] == ["mine"]


def test_a_skill_without_scenarios_still_refuses_unless_probes_are_asked_for(
    tmp_path: Path,
) -> None:
    package = load_skill(_external_skill(tmp_path))
    with pytest.raises(BellwetherError, match="bellwether probe"):
        scenario_suite_for(package, generic_probes=False)
    generated = scenario_suite_for(package, generic_probes=True)
    assert generated is not package.scenarios
    assert ACTIVATION_PROBE_ID in {s.id for s in generated.scenarios}


def test_the_coverage_note_says_what_section_7_6_requires(tmp_path: Path) -> None:
    package = load_skill(_external_skill(tmp_path))
    note = probe_coverage_note(package, scenario_suite_for(package, generic_probes=True))
    assert note.startswith("Behaviour observed; task quality not evaluated (no scenarios supplied)")
    assert f"{len(UNRELATED_PROMPTS)} unrelated prompts" in note


# ---------------------------------------------------------------------------
# The run path, end to end on the scripted executor
# ---------------------------------------------------------------------------


def test_run_evaluation_runs_the_generated_suite_and_notes_the_missing_coverage(
    tmp_path: Path,
) -> None:
    """The external-mode run: every probe becomes a repetition set, the verdict carries the
    coverage note, and the artifacts are the ordinary ones."""
    package = load_skill(_external_skill(tmp_path))
    result, executor = _evaluate(package, tmp_path, generic_probes=True, profile_override="low")
    # The scripted executor names each trace by its scenario: every probe ran.
    executed = {path.name for path in tmp_path.glob("run-*.jsonl")}
    for scenario_id in (ACTIVATION_PROBE_ID, REPRESENTATIVE_PROBE_ID, unrelated_probe_id(1)):
        assert any(name.startswith(f"run-{scenario_id}-") for name in executed), scenario_id
    assert result.summary.matrix.scenarios == 2 + len(UNRELATED_PROMPTS)
    assert executor.calls > 0
    assert any(
        note.startswith("Behaviour observed; task quality not evaluated")
        for note in result.verdict.notes
    )
    # The scripted model activates the skill on every prompt, so the unrelated probes count as
    # false triggers and the gate that §7.6's over-trigger probes feed is composed and decides.
    false_trigger = next(g for g in result.verdict.gates if g.name == "functional.false_trigger")
    assert false_trigger.status == "block"
    assert result.verdict.verdict == "not_ready"


def test_run_evaluation_with_an_authored_suite_carries_no_coverage_note(tmp_path: Path) -> None:
    root = _external_skill(tmp_path)
    (root / "evals").mkdir()
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n  - id: benign-stable\n    expectation: should_trigger\n"
        '    prompt: "Review this project."\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    result, _executor = _evaluate(
        load_skill(root), tmp_path, generic_probes=True, profile_override="low"
    )
    assert not any("task quality not evaluated" in note for note in result.verdict.notes)
    assert result.summary.matrix.scenarios == 1
    assert all(path.name.startswith("run-benign-stable-") for path in tmp_path.glob("run-*.jsonl"))


# ---------------------------------------------------------------------------
# The command's front door
# ---------------------------------------------------------------------------


def test_probe_refuses_a_url_before_touching_anything(tmp_path: Path) -> None:
    result = runner.invoke(app, ["probe", "https://example.invalid/skill.git"])
    assert result.exit_code == 3
    assert "local skill directory" in result.output


def test_probe_has_no_held_out_prompts_in_its_help() -> None:
    """§7.6: the held-out set must not appear in --help. There is no held-out set in this build,
    and the published prompts do not appear in the help either — the help describes the suite,
    it does not print it."""
    result = runner.invoke(app, ["probe", "--help"])
    assert result.exit_code == 0
    for prompt in UNRELATED_PROMPTS:
        assert prompt not in result.output


# ---------------------------------------------------------------------------
# The wiring from the commands to run_evaluation
# ---------------------------------------------------------------------------


def _captured_run_evaluation(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Stand in for run_evaluation and the daemon probe so a CLI invocation reaches the call
    without a container; what matters here is which `generic_probes` the command passes."""
    import importlib

    app_module = importlib.import_module("bellwether.cli.app")
    run_module = importlib.import_module("bellwether.cli.run")

    captured: dict[str, object] = {}

    def fake_run_evaluation(**kwargs: object) -> object:
        captured.update(kwargs)
        raise BellwetherError("captured")

    monkeypatch.setattr(run_module, "run_evaluation", fake_run_evaluation)
    monkeypatch.setattr(app_module.DockerBackend, "available", lambda _self: (True, ""))
    return captured


def _scaffold(tmp_path: Path) -> Path:
    assert runner.invoke(app, ["init", str(tmp_path)]).exit_code == 0
    return tmp_path / ".bellwether" / "config.yaml"


def test_run_passes_the_flag_through_and_defaults_it_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _captured_run_evaluation(monkeypatch)
    config = _scaffold(tmp_path)
    skill = _external_skill(tmp_path)
    runner.invoke(app, ["run", str(skill), "--config", str(config), "--generic-probes"])
    assert captured["generic_probes"] is True
    captured.clear()
    runner.invoke(app, ["run", str(skill), "--config", str(config)])
    assert captured["generic_probes"] is False


def test_probe_is_run_with_the_generic_suite_forced_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _captured_run_evaluation(monkeypatch)
    config = _scaffold(tmp_path)
    skill = _external_skill(tmp_path)
    result = runner.invoke(app, ["probe", str(skill), "--config", str(config), "--profile", "low"])
    assert captured["generic_probes"] is True
    assert captured["profile_override"] == "low"
    # The stand-in raised, so the command reports it as an environment problem — exit 3,
    # never a verdict.
    assert result.exit_code == 3
