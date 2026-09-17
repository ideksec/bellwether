"""Per-scenario fixtures (§7.2, §9.1 step 1): a scenario's ``fixture:`` name resolves to its own
starting tree, and the matrix stamps it on every plan for that scenario.

Two properties with teeth. The legacy flat layout every shipped skill uses — a flat
``evals/fixtures/`` plus a ``fixture:`` label with no matching subdirectory — must keep resolving
to that flat tree, because the proven live runs were made against exactly it. And a name that
resolves nowhere must refuse, never be quietly replaced by an empty workspace: a run on the wrong
starting tree produces a clean-looking verdict about a scenario that never ran as designed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bellwether.cli.fixtures import EMPTY_FIXTURE, fixture_resolver, resolve_fixture
from bellwether.cli.orchestrator import TargetInfo, plan_matrix
from bellwether.config.models.scenarios import Scenario, ScenarioSuite
from bellwether.errors import BellwetherError


def _scenario(scenario_id: str, fixture: str | None = None) -> Scenario:
    return Scenario.model_validate(
        {
            "id": scenario_id,
            "expectation": "should_trigger",
            "prompt": "go",
            "fixture": fixture,
            "assert": [{"skill_activated": True}],
        }
    )


def _suite(*scenarios: Scenario, default: str | None = None) -> ScenarioSuite:
    return ScenarioSuite.model_validate(
        {
            "apiVersion": "bellwether/v1",
            "kind": "ScenarioSuite",
            "defaults": {"fixture": default} if default is not None else {},
            "scenarios": [s.model_dump(by_alias=True, exclude_none=True) for s in scenarios],
        }
    )


# ---------------------------------------------------------------------------
# resolve_fixture — the resolution rules
# ---------------------------------------------------------------------------


def test_a_named_skill_local_fixture_resolves_to_its_directory(tmp_path: Path) -> None:
    (tmp_path / "evals" / "fixtures" / "python-repo").mkdir(parents=True)
    resolved = resolve_fixture(tmp_path, "python-repo")
    assert resolved.name == "python-repo"
    assert resolved.path == tmp_path / "evals" / "fixtures" / "python-repo"


def test_a_named_shared_fixture_resolves_when_the_skill_has_none(tmp_path: Path) -> None:
    """§5: `.bellwether/fixtures/<name>/` is the reusable pool; a skill-local name wins over it."""
    shared = tmp_path / ".bellwether" / "fixtures"
    (shared / "docs-project").mkdir(parents=True)
    skill = tmp_path / "skills" / "s"
    skill.mkdir(parents=True)
    resolved = resolve_fixture(skill, "docs-project", shared_root=shared)
    assert resolved.path == shared / "docs-project"
    # Skill-local takes precedence over shared when both exist.
    (skill / "evals" / "fixtures" / "docs-project").mkdir(parents=True)
    assert resolve_fixture(skill, "docs-project", shared_root=shared).path == (
        skill / "evals" / "fixtures" / "docs-project"
    )


def test_empty_is_a_bare_workspace_and_needs_no_directory(tmp_path: Path) -> None:
    resolved = resolve_fixture(tmp_path, EMPTY_FIXTURE)
    assert resolved.name == EMPTY_FIXTURE
    assert resolved.path.is_dir()
    assert not any(resolved.path.iterdir())


def test_the_legacy_flat_layout_keeps_resolving_to_the_flat_tree(tmp_path: Path) -> None:
    """The shape every shipped skill uses: a flat evals/fixtures/ and a fixture: label with no
    matching subdirectory. It must resolve to the flat tree — what the proven live runs used —
    with the label recorded as the name."""
    flat = tmp_path / "evals" / "fixtures"
    (flat / "standup").mkdir(parents=True)
    (flat / "standup" / "2026-01-05.md").write_text("notes", encoding="utf-8")
    resolved = resolve_fixture(tmp_path, "standup-repo")
    assert resolved.path == flat
    assert resolved.name == "standup-repo"


def test_no_name_uses_the_flat_tree_if_present_else_a_bare_workspace(tmp_path: Path) -> None:
    assert not any(resolve_fixture(tmp_path, None).path.iterdir())  # nothing shipped → bare
    flat = tmp_path / "evals" / "fixtures"
    flat.mkdir(parents=True)
    (flat / "README.md").write_text("x", encoding="utf-8")
    resolved = resolve_fixture(tmp_path, None)
    assert resolved.path == flat
    assert resolved.name is None


def test_a_name_that_resolves_nowhere_is_refused_not_silently_emptied(tmp_path: Path) -> None:
    """A named fixture with no directory and no flat tree to fall back on refuses, naming the
    scenario, the name, and where it looked — running on an empty workspace instead would
    produce a verdict about a scenario that never ran as designed."""
    with pytest.raises(BellwetherError, match="python-repo") as excinfo:
        resolve_fixture(
            tmp_path, "python-repo", scenario_id="review", shared_root=tmp_path / "shared"
        )
    message = str(excinfo.value)
    assert "review" in message
    assert str(tmp_path / "evals" / "fixtures" / "python-repo") in message
    assert EMPTY_FIXTURE in message  # names the remedy


# ---------------------------------------------------------------------------
# fixture_resolver and plan_matrix — suite defaults and per-plan stamping
# ---------------------------------------------------------------------------


def test_the_resolver_falls_back_to_the_suite_default(tmp_path: Path) -> None:
    (tmp_path / "evals" / "fixtures" / "base").mkdir(parents=True)
    (tmp_path / "evals" / "fixtures" / "special").mkdir(parents=True)
    suite = _suite(_scenario("a"), _scenario("b", fixture="special"), default="base")
    resolve = fixture_resolver(tmp_path, suite)
    assert resolve(suite.by_id("a")).path.name == "base"  # from defaults.fixture
    assert resolve(suite.by_id("b")).path.name == "special"  # its own wins


def test_plan_matrix_stamps_each_scenarios_fixture_on_every_repetition(tmp_path: Path) -> None:
    """Different scenarios, different starting trees — the property the single-fixture executor
    could not express. Every repetition of a scenario shares its tree; another scenario's plans
    carry a different one."""
    (tmp_path / "evals" / "fixtures" / "one").mkdir(parents=True)
    (tmp_path / "evals" / "fixtures" / "two").mkdir(parents=True)
    suite = _suite(_scenario("first", fixture="one"), _scenario("second", fixture="two"))
    target = TargetInfo("api-loop", "anthropic", "frontier")
    plans = plan_matrix(
        suite.scenarios, [target], repetitions=3, fixture_for=fixture_resolver(tmp_path, suite)
    )

    by_scenario = {}
    for plan in plans:
        by_scenario.setdefault(plan.scenario.id, set()).add((plan.fixture_name, plan.fixture))
    assert by_scenario["first"] == {("one", tmp_path / "evals" / "fixtures" / "one")}
    assert by_scenario["second"] == {("two", tmp_path / "evals" / "fixtures" / "two")}


def test_plan_matrix_without_a_resolver_leaves_the_fixture_to_the_executor() -> None:
    plans = plan_matrix(
        [_scenario("s")], [TargetInfo("api-loop", "anthropic", "frontier")], repetitions=2
    )
    assert all(plan.fixture is None and plan.fixture_name is None for plan in plans)


def test_a_missing_fixture_refuses_before_any_plan_is_built(tmp_path: Path) -> None:
    suite = _suite(_scenario("ok", fixture=EMPTY_FIXTURE), _scenario("bad", fixture="ghost"))
    with pytest.raises(BellwetherError, match="ghost"):
        plan_matrix(
            suite.scenarios,
            [TargetInfo("api-loop", "anthropic", "frontier")],
            repetitions=2,
            fixture_for=fixture_resolver(tmp_path, suite),
        )
