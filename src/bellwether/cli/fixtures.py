"""Resolving a scenario's workspace fixture by name (§7.2, §9.1 step 1).

A scenario names its starting workspace with ``fixture: <name>``, defaulting from the suite's
``defaults.fixture``. Fixtures are plain directories (§9.1); the name resolves against two
places the §5 layout defines — the skill's own ``evals/fixtures/<name>/`` (scenario-specific)
and the repository's shared ``.bellwether/fixtures/<name>/`` (reusable across skills) — with
``empty`` reserved for a bare workspace.

One legacy shape is honoured deliberately. The first cut of ``bellwether run`` materialised the
*whole* ``evals/fixtures/`` directory as the workspace and ignored the name, and every shipped
skill was written against that: their ``evals/fixtures/`` is a flat tree (``standup/…``,
``README.md``) while their ``fixture:`` is a label with no matching subdirectory. So when a
named subdirectory does not exist but a flat ``evals/fixtures/`` does, that flat tree is the
fixture — exactly what the proven live runs used — and the name is recorded as the label it is.
A name that resolves nowhere is refused, not silently replaced by an empty workspace: a run on
the wrong starting tree would produce a clean-looking verdict about a scenario that never ran
as designed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from bellwether.config.models.scenarios import Scenario, ScenarioSuite
from bellwether.errors import BellwetherError

__all__ = ["EMPTY_FIXTURE", "ResolvedFixture", "fixture_resolver", "resolve_fixture"]

#: The reserved fixture name for a bare workspace (§5 ships it as ``.bellwether/fixtures/empty/``
#: too; naming it needs no directory to exist).
EMPTY_FIXTURE = "empty"


@dataclass(frozen=True)
class ResolvedFixture:
    """A fixture name and the directory it resolved to."""

    #: The name the scenario (or suite default) gave, recorded in the trace header
    #: (``sandbox.fixture``, §11.1) — or ``None`` when nothing named one.
    name: str | None
    path: Path


def resolve_fixture(
    skill_dir: Path,
    name: str | None,
    *,
    shared_root: Path | None = None,
    scenario_id: str = "",
) -> ResolvedFixture:
    """Resolve one fixture name for one scenario, or raise :class:`BellwetherError`.

    Resolution order: ``empty`` → a bare workspace; ``evals/fixtures/<name>/`` → that directory;
    ``<shared_root>/<name>/`` → that directory; a flat ``evals/fixtures/`` with no such
    subdirectory → the flat tree (the legacy shape every shipped skill uses); no name at all →
    the flat tree if present, else a bare workspace. A name that matches none of these refuses.
    """
    local_root = skill_dir / "evals" / "fixtures"
    if name == EMPTY_FIXTURE:
        return ResolvedFixture(name=name, path=_empty_workspace(skill_dir))
    if name is not None:
        candidates = [local_root / name]
        if shared_root is not None:
            candidates.append(shared_root / name)
        for candidate in candidates:
            if candidate.is_dir():
                return ResolvedFixture(name=name, path=candidate)
        if local_root.is_dir():
            # Legacy flat layout: the name is a label; the whole directory is the fixture.
            return ResolvedFixture(name=name, path=local_root)
        searched = ", ".join(str(candidate) for candidate in candidates)
        where = f"scenario {scenario_id!r}" if scenario_id else "the suite"
        raise BellwetherError(
            f"{where} names fixture {name!r}, but no such fixture directory exists (searched: "
            f"{searched}) and the skill has no evals/fixtures/ tree to fall back on. Create the "
            f"directory, or set fixture: {EMPTY_FIXTURE} for a bare workspace — running on the "
            "wrong starting tree would produce a verdict about a scenario that never ran as "
            "designed."
        )
    if local_root.is_dir():
        return ResolvedFixture(name=None, path=local_root)
    return ResolvedFixture(name=None, path=_empty_workspace(skill_dir))


def fixture_resolver(
    skill_dir: Path, suite: ScenarioSuite, *, shared_root: Path | None = None
) -> Callable[[Scenario], ResolvedFixture]:
    """A per-scenario resolver: the scenario's own ``fixture``, else the suite default."""

    def resolve(scenario: Scenario) -> ResolvedFixture:
        name = scenario.fixture if scenario.fixture is not None else suite.defaults.fixture
        return resolve_fixture(skill_dir, name, shared_root=shared_root, scenario_id=scenario.id)

    return resolve


def _empty_workspace(skill_dir: Path) -> Path:
    """A bare workspace directory, created on demand under the skill's evals tree."""
    empty = skill_dir / "evals" / ".empty-workspace"
    empty.mkdir(parents=True, exist_ok=True)
    return empty
