"""Which skills a set of changed files touches (§18, §19.3).

On a pull request, Bellwether should evaluate only the skills the diff actually changed —
not re-run every skill already in the repository on every push. That would burn the budget
(a live run is N model calls per scenario), and it would attach a fresh verdict to skills
nobody touched. This maps a list of changed file paths to the set of skill directories
affected, so the CI job can run just those.

A *skill directory* is one that contains a ``SKILL.md``. A changed file is attributed to the
nearest such ancestor: a change to ``foo/evals/manifest.yaml`` or ``foo/reference.md`` is a
change to the skill at ``foo/``, because a skill's behaviour and its declared scope both live
beside its ``SKILL.md``. A path under no skill directory (a change to the harness, a doc, this
file) touches no skill and is ignored. A skill whose ``SKILL.md`` no longer exists — the whole
skill was deleted — is not returned, because there is nothing left to evaluate.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path, PurePosixPath

__all__ = ["changed_skills", "skill_dir_for"]


def skill_dir_for(rel_path: str, *, root: Path) -> PurePosixPath | None:
    """The skill directory a single changed path belongs to, or None.

    Walks from the file's parent up to the repository root and returns the first ancestor
    that currently holds a ``SKILL.md`` (checked on disk under ``root``). Returns None when
    no ancestor is a skill — including when the skill's ``SKILL.md`` was deleted, so a removed
    skill is never handed back as something to evaluate.
    """
    normalized = rel_path.strip().replace("\\", "/")
    if not normalized:
        return None
    path = PurePosixPath(normalized)
    for parent in (path.parent, *path.parent.parents):
        if (root / parent / "SKILL.md").is_file():
            return parent
    return None


def changed_skills(paths: Iterable[str], *, root: Path | None = None) -> list[PurePosixPath]:
    """The skill directories touched by ``paths``, sorted and de-duplicated (§18).

    ``paths`` are repository-relative changed files (what ``git diff --name-only`` prints);
    ``root`` is the repository checkout the ``SKILL.md`` presence is checked against, the
    current directory by default. Two changes inside one skill collapse to one entry, so the
    caller runs each affected skill exactly once.
    """
    base = root if root is not None else Path.cwd()
    found: set[PurePosixPath] = set()
    for raw in paths:
        skill = skill_dir_for(raw, root=base)
        if skill is not None:
            found.add(skill)
    return sorted(found, key=str)
