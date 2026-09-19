"""§7.4 plural staging: a scenario's companion skills are staged beside the skill under test so
a harness that discovers skills from the install root (the claude-code CLI) can be offered a
competitor that is actually there.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from bellwether.cli.orchestrator import RunPlan, TargetInfo, plan_matrix
from bellwether.config.models.scenarios import Scenario
from bellwether.errors import SkillError
from bellwether.sandbox import stage_companions, stage_payload
from bellwether.skill import load_skill

INSTALL_ROOT = PurePosixPath("/home/agent/.claude/skills")


def _skill(root: Path, name: str, *, body: str = "body") -> Path:
    skill = root / name
    (skill / "evals").mkdir(parents=True)
    (skill / "evals" / "manifest.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: SkillManifest\nmetadata: {owner: x}\n", encoding="utf-8"
    )
    (skill / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: the {name} skill\n---\n# {name}\n{body}\n",
        encoding="utf-8",
    )
    return skill


def test_each_companion_is_staged_under_its_own_slug_at_the_install_root(tmp_path: Path) -> None:
    primary = load_skill(_skill(tmp_path / "lib", "deploy-helper"))
    companions = [
        load_skill(_skill(tmp_path / "lib", "k8s-debug")),
        load_skill(_skill(tmp_path / "lib", "schema-docs")),
    ]

    staged = stage_companions(
        companions, tmp_path / "run" / "companions", primary=primary, install_root=INSTALL_ROOT
    )

    assert [s.install_path for s in staged] == [
        INSTALL_ROOT / "k8s-debug",
        INSTALL_ROOT / "schema-docs",
    ]
    assert [s.root for s in staged] == [
        tmp_path / "run" / "companions" / "k8s-debug",
        tmp_path / "run" / "companions" / "schema-docs",
    ]
    for payload in staged:
        assert (payload.root / "SKILL.md").is_file()
        assert not (payload.root / "evals").exists(), "§3.5 holds for companions too"
        assert not payload.contains_machinery()


def test_a_companion_never_changes_the_primary_digest(tmp_path: Path) -> None:
    """The run cache and the baselines key on the skill under test; a companion is context,
    not payload."""
    primary = load_skill(_skill(tmp_path / "lib", "deploy-helper"))
    companion = load_skill(_skill(tmp_path / "lib", "k8s-debug"))

    alone = stage_payload(primary, tmp_path / "alone")
    staged = stage_companions(
        [companion], tmp_path / "companions", primary=primary, install_root=INSTALL_ROOT
    )

    assert alone.payload_digest == primary.payload_digest
    assert staged[0].payload_digest == companion.payload_digest
    assert staged[0].payload_digest != primary.payload_digest


def test_a_companion_colliding_with_the_primary_install_directory_is_refused(
    tmp_path: Path,
) -> None:
    """Two skills that slug to one directory would shadow each other at the install root and
    "which activated" would be undecidable — refused, naming both."""
    primary = load_skill(_skill(tmp_path / "a", "deploy helper"))
    companion = load_skill(_skill(tmp_path / "b", "deploy-helper"))
    assert primary.slug == companion.slug

    with pytest.raises(SkillError, match="same directory as 'deploy helper'"):
        stage_companions(
            [companion], tmp_path / "companions", primary=primary, install_root=INSTALL_ROOT
        )


def test_two_companions_colliding_with_each_other_are_refused(tmp_path: Path) -> None:
    primary = load_skill(_skill(tmp_path / "lib", "deploy-helper"))
    first = load_skill(_skill(tmp_path / "a", "k8s debug"))
    second = load_skill(_skill(tmp_path / "b", "k8s-debug"))

    with pytest.raises(SkillError, match="same directory as 'k8s debug'"):
        stage_companions(
            [first, second], tmp_path / "companions", primary=primary, install_root=INSTALL_ROOT
        )
    # The refusal happens before the second copy, so nothing is staged under its slug.
    assert not (tmp_path / "companions" / "k8s-debug").exists()


def test_no_companions_stages_nothing(tmp_path: Path) -> None:
    primary = load_skill(_skill(tmp_path / "lib", "deploy-helper"))
    assert (
        stage_companions([], tmp_path / "companions", primary=primary, install_root=INSTALL_ROOT)
        == ()
    )
    assert not (tmp_path / "companions").exists()


def test_a_claude_code_plan_carries_the_companions_the_executor_stages(tmp_path: Path) -> None:
    """The plan is the contract: `plan_matrix` stamps the resolved companions onto every
    repetition of a claude-code target exactly as it does for api-loop, and the executor reads
    them from there (the api-loop offers them host-side; claude-code stages them)."""
    from bellwether.cli.companions import companion_resolver

    primary_dir = _skill(tmp_path / "lib", "deploy-helper")
    _skill(tmp_path / "lib", "k8s-debug")
    scenario = Scenario.model_validate(
        {
            "id": "collide",
            "expectation": "should_trigger",
            "prompt": "go",
            "assert": [{"skill_activated": True}],
            "also_load_skills": ["k8s-debug"],
        }
    )
    plans: list[RunPlan] = plan_matrix(
        [scenario],
        [TargetInfo("claude-code", "anthropic", "frontier")],
        repetitions=2,
        companions_for=companion_resolver(primary_dir),
    )
    assert plans
    assert all([c.name for c in plan.companions] == ["k8s-debug"] for plan in plans)


# ---------------------------------------------------------------------------
# One copy of every skill, including the companions (§5/§6/§18 meets §7.4)
# ---------------------------------------------------------------------------


def _plugin_with_skills(root: Path, names: tuple[str, ...]) -> Path:
    import json

    bundle = root / "demo-bundle"
    bundle.mkdir(parents=True)
    (bundle / "plugin.json").write_text(
        json.dumps({"name": "demo-bundle", "version": "1.0.0"}), encoding="utf-8"
    )
    (bundle / "skills").mkdir()
    for name in names:
        _skill(bundle / "skills", name)
    return bundle


def test_a_companion_already_inside_the_installed_bundle_is_not_staged_again(
    tmp_path: Path,
) -> None:
    """The defect: whole-bundle staging stopped installing the skill under test twice, but a
    §7.4 companion that is a *sibling in the same bundle* was still staged bare on top of it.
    The harness would then see `k8s-debug` and `demo-bundle:k8s-debug` — two copies of the
    competitor — in exactly the scenarios companions exist to decide, where which skill
    activated is the whole question.
    """
    from bellwether.cli.execution import companions_to_stage

    bundle = _plugin_with_skills(tmp_path, ("deploy-helper", "k8s-debug"))
    companion = load_skill(bundle / "skills" / "k8s-debug")

    assert companions_to_stage([companion], bundle) == ()


def test_a_companion_from_outside_the_bundle_is_still_staged(tmp_path: Path) -> None:
    """The converse, because a filter that drops everything offers no competitor at all and
    every `other_skill_activated` assertion would pass vacuously."""
    from bellwether.cli.execution import companions_to_stage

    bundle = _plugin_with_skills(tmp_path, ("deploy-helper",))
    outsider = load_skill(_skill(tmp_path / "lib", "k8s-debug"))

    assert companions_to_stage([outsider], bundle) == (outsider,)


def test_a_bare_skill_directory_stages_every_companion_as_before(tmp_path: Path) -> None:
    """No bundle, no change: the filter is about what the bundle already installed."""
    from bellwether.cli.execution import companions_to_stage

    outsider = load_skill(_skill(tmp_path / "lib", "k8s-debug"))
    assert companions_to_stage([outsider], None) == (outsider,)


def test_a_companion_reached_through_a_symlink_is_recognised_as_the_bundles_own(
    tmp_path: Path,
) -> None:
    """The comparison is about the same *files*, not the same spelling. A checkout reached
    through a symlinked path is the same skill the bundle installs, and a lexical comparison
    would stage a second copy of it."""
    bundle = _plugin_with_skills(tmp_path, ("deploy-helper", "k8s-debug"))
    link = tmp_path / "linked-bundle"
    link.symlink_to(bundle, target_is_directory=True)
    companion = load_skill(link / "skills" / "k8s-debug")

    from bellwether.cli.execution import companions_to_stage

    assert companions_to_stage([companion], bundle) == ()
