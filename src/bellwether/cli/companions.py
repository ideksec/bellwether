"""Resolving a scenario's ``also_load_skills`` to the skills loaded alongside it (§7.4).

§7.4 asks for loading a set of other skills beside the one under test and asserting on *which*
activated — the coexistence failure mode where a skill's description is broad enough to capture
activations meant for another. ``Scenario.also_load_skills`` has carried those names since WP-1
and the run path ignored them; every scenario ran with the primary skill offered alone.

A companion is named by its skill name and resolves to a **sibling** skill directory — the §5
layout keeps every skill one directory under ``skills/``, so ``skills/<name>/`` beside the skill
under test is the one place a name means something. A name that resolves nowhere refuses before
any run: a coexistence scenario whose competitor is silently absent would report the primary
winning every activation for the wrong reason.

Companions are loaded as skill packages and *offered* — name, description, body — through the
harness exactly as the primary is. They are not staged into the sandbox: on ``api-loop`` the
offer is host-side and a companion's own scripts would not exist in the container (a tool call
into them fails as an ordinary error result, recorded). The ``claude-code`` harness discovers
skills from what is staged, so companions there need plural staging, which this build has not
built; the §16.4 preflight refuses that combination rather than offering a companion the CLI
cannot see.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from bellwether.config.models.scenarios import Scenario
from bellwether.errors import BellwetherError, SkillError
from bellwether.skill import SkillPackage, load_skill

__all__ = ["companion_resolver", "resolve_companions"]


def resolve_companions(
    skill_dir: Path, names: list[str], *, scenario_id: str = ""
) -> tuple[SkillPackage, ...]:
    """Load the sibling skills ``names`` beside ``skill_dir``, or raise :class:`BellwetherError`.

    Returned in the order named; the harness sorts what it offers, so order here is not
    load-bearing. A companion naming the skill under test itself is refused — it would be
    offered twice, and "which activated" would be undecidable.
    """
    packages: list[SkillPackage] = []
    where = f"scenario {scenario_id!r}" if scenario_id else "the scenario"
    for name in names:
        if name == skill_dir.name:
            raise BellwetherError(
                f"{where} lists the skill under test ({name!r}) in also_load_skills; a skill "
                "cannot be its own companion"
            )
        candidate = skill_dir.parent / name
        if not candidate.is_dir():
            raise BellwetherError(
                f"{where} names companion skill {name!r} in also_load_skills, but no sibling "
                f"directory {candidate} exists (§5: companions live beside the skill under test "
                "as skills/<name>/); a coexistence scenario whose competitor is absent would "
                "report the primary winning for the wrong reason"
            )
        try:
            packages.append(load_skill(candidate))
        except SkillError as error:
            raise BellwetherError(
                f"{where}: companion skill {name!r} at {candidate} did not load: {error}"
            ) from error
    return tuple(packages)


def companion_resolver(skill_dir: Path) -> Callable[[Scenario], tuple[SkillPackage, ...]]:
    """A per-scenario resolver over ``scenario.also_load_skills``."""

    def resolve(scenario: Scenario) -> tuple[SkillPackage, ...]:
        if not scenario.also_load_skills:
            return ()
        return resolve_companions(skill_dir, scenario.also_load_skills, scenario_id=scenario.id)

    return resolve
