"""§7.4 coexistence loading: a scenario's ``also_load_skills`` resolve to sibling skills offered
alongside the one under test, so an assertion on *which* skill activated has competitors to
observe. A competitor that resolves nowhere refuses before any run — a coexistence scenario whose
rival is silently absent would report the primary winning for the wrong reason."""

from __future__ import annotations

from pathlib import Path

import pytest

from bellwether.cli.companions import companion_resolver, resolve_companions
from bellwether.cli.execution import offered_skills_for
from bellwether.cli.orchestrator import RunPlan, TargetInfo, plan_matrix
from bellwether.config.models.scenarios import Scenario
from bellwether.errors import BellwetherError
from bellwether.skill import load_skill


def _skill(root: Path, name: str, description: str) -> Path:
    skill = root / name
    (skill / "evals").mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n# {name}\nbody of {name}\n",
        encoding="utf-8",
    )
    return skill


def _scenario(scenario_id: str = "s", **fields: object) -> Scenario:
    return Scenario.model_validate(
        {
            "id": scenario_id,
            "expectation": "should_trigger",
            "prompt": "go",
            "assert": [{"skill_activated": True}],
            **fields,
        }
    )


def test_companions_resolve_to_sibling_skill_directories(tmp_path: Path) -> None:
    primary = _skill(tmp_path, "deploy-helper", "Deploys things.")
    _skill(tmp_path, "k8s-debug", "Debugs Kubernetes.")
    (packages,) = (resolve_companions(primary, ["k8s-debug"]),)
    assert [p.name for p in packages] == ["k8s-debug"]


def test_a_missing_companion_refuses_naming_the_scenario_and_where_it_looked(
    tmp_path: Path,
) -> None:
    primary = _skill(tmp_path, "deploy-helper", "Deploys things.")
    with pytest.raises(BellwetherError, match="ghost") as excinfo:
        resolve_companions(primary, ["ghost"], scenario_id="collide")
    assert "collide" in str(excinfo.value)
    assert str(tmp_path / "ghost") in str(excinfo.value)


def test_a_skill_cannot_be_its_own_companion(tmp_path: Path) -> None:
    primary = _skill(tmp_path, "deploy-helper", "Deploys things.")
    with pytest.raises(BellwetherError, match="own companion"):
        resolve_companions(primary, ["deploy-helper"])


def test_the_run_offers_the_primary_plus_its_companions(tmp_path: Path) -> None:
    """What the harness sees: the skill under test and every companion, each offered as
    name/description/body exactly as the primary is, so the model has real competitors."""
    primary_dir = _skill(tmp_path, "deploy-helper", "Deploys things.")
    _skill(tmp_path, "k8s-debug", "Debugs Kubernetes.")
    _skill(tmp_path, "schema-docs", "Documents schemas.")
    primary = load_skill(primary_dir)
    scenario = _scenario(also_load_skills=["k8s-debug", "schema-docs"])
    (plan,) = plan_matrix(
        [scenario],
        [TargetInfo("api-loop", "anthropic", "frontier")],
        repetitions=2,
        companions_for=companion_resolver(primary_dir),
    )[:1]
    assert [c.name for c in plan.companions] == ["k8s-debug", "schema-docs"]

    offered = offered_skills_for(primary, plan)
    assert [s.name for s in offered] == ["deploy-helper", "k8s-debug", "schema-docs"]
    assert offered[1].description == "Debugs Kubernetes."
    assert "body of k8s-debug" in offered[1].body


def test_a_scenario_without_companions_offers_the_primary_alone(tmp_path: Path) -> None:
    primary_dir = _skill(tmp_path, "deploy-helper", "Deploys things.")
    primary = load_skill(primary_dir)
    plan = RunPlan(
        scenario=_scenario(), target=TargetInfo("api-loop", "anthropic", "frontier"), repetition=1
    )
    assert [s.name for s in offered_skills_for(primary, plan)] == ["deploy-helper"]


# ---------------------------------------------------------------------------
# A companion is named by its name, not by a path (§5, §7.4)
# ---------------------------------------------------------------------------


def test_a_companion_entry_cannot_reach_outside_the_skills_tree(tmp_path: Path) -> None:
    """The entry was joined onto the skills directory as a path, so `../…` resolved out of it.

    A scenario file then chooses what the container is offered, from anywhere the process can
    read — and the §5 rule the refusal below cites, that a companion is a *sibling*, was never
    actually enforced.
    """
    skills = tmp_path / "skills"
    primary = _skill(skills, "deploy-helper", "deploys things")
    _skill(tmp_path / "elsewhere", "smuggled", "not a sibling")

    with pytest.raises(BellwetherError, match="a path rather than a skill name"):
        resolve_companions(primary, ["../elsewhere/smuggled"], scenario_id="escape")


def test_the_self_companion_refusal_cannot_be_walked_past(tmp_path: Path) -> None:
    """`./<name>` compared unequal to the directory name and resolved to the same directory.

    That put the skill under test in front of the harness twice, under two names — which is the
    one outcome the self-companion refusal exists to prevent, because "which activated" then
    has no answer.
    """
    skills = tmp_path / "skills"
    primary = _skill(skills, "deploy-helper", "deploys things")

    with pytest.raises(BellwetherError, match="a path rather than a skill name"):
        resolve_companions(primary, ["./deploy-helper"], scenario_id="twice")


@pytest.mark.parametrize("entry", ["", ".", "..", "a/b", "/etc", "sub\\dir"])
def test_every_shape_that_is_not_a_bare_name_is_refused(tmp_path: Path, entry: str) -> None:
    """Refused before the join, because the join is what makes a path dangerous. Backslash is
    refused on POSIX too: the entry comes from a YAML file that may have been written on
    Windows, and a name kept whole here would be a path on the machine it came from."""
    primary = _skill(tmp_path / "skills", "deploy-helper", "deploys things")

    with pytest.raises(BellwetherError, match="a path rather than a skill name"):
        resolve_companions(primary, [entry], scenario_id="shapes")


def test_an_ordinary_sibling_name_still_resolves(tmp_path: Path) -> None:
    """The guard must not cost the feature: a plain name is what §7.4 scenarios actually use,
    and a check that refused those would be worse than the hole it closed."""
    skills = tmp_path / "skills"
    primary = _skill(skills, "deploy-helper", "deploys things")
    _skill(skills, "k8s-debug", "debugs clusters")

    resolved = resolve_companions(primary, ["k8s-debug"], scenario_id="ok")
    assert [package.name for package in resolved] == ["k8s-debug"]
