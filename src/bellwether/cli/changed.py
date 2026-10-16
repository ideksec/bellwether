"""Which skills a set of changed files touches (§18, §19.3).

On a pull request, Bellwether should evaluate only the skills the diff actually changed —
not re-run every skill already in the repository on every push. That would burn the budget
(a live run is N model calls per scenario), and it would attach a fresh verdict to skills
nobody touched. This maps a list of changed file paths to the set of skill directories
affected, so the CI job can run just those.

A *skill directory* is one that contains a ``SKILL.md``. A changed file is attributed to the
nearest such ancestor: a change to ``foo/evals/manifest.yaml`` or ``foo/reference.md`` is a
change to the skill at ``foo/``, because a skill's behaviour and its declared scope both live
beside its ``SKILL.md``.

A path under no skill directory may still sit inside an *Agent Plugin* bundle
(agent-plugins.org) — a directory with a ``plugin.json``, carrying skills under ``skills/``.
A plugin-level change (the manifest, an ``mcp.json``, a client extension directory, a file
deleted from one of its skills) can change what every bundled skill does when the plugin is
installed, and there is no per-skill attribution for it — so it is attributed to **all** of
the plugin's skills. The alternative — attributing it to nothing — would print "no skills
changed" for a PR that rewrote the bundle's manifest, the silent false-green this detection
exists to avoid.

A path under no skill and no plugin (a change to the harness, a doc, this file) touches no
skill and is ignored. A skill whose ``SKILL.md`` no longer exists — the whole skill was
deleted — is not returned, because there is nothing left to evaluate.
"""

from __future__ import annotations

import posixpath
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath

from bellwether.skill import PLUGIN_MANIFEST, PLUGIN_SKILLS_DIR, plugin_skill_dirs

__all__ = ["changed_skills", "plugin_root_for", "scope_roots", "skill_dir_for"]


def _contained_path(rel_path: str) -> PurePosixPath | None:
    """Normalise a changed path, refusing one that names a file outside the checkout.

    A changed path must name a file *inside* the repository. An absolute path, or one that
    climbs out with ``..``, would make ``root / parent`` resolve outside the checkout —
    where it could be attributed to a ``SKILL.md`` or ``plugin.json`` that is not part of
    the evaluated repo at all (BW-34). (An internal ``..`` that stays within the root is
    collapsed and kept; git diff paths never carry one anyway.)
    """
    normalized = rel_path.strip().replace("\\", "/")
    if not normalized:
        return None
    collapsed = posixpath.normpath(normalized)
    if posixpath.isabs(collapsed) or collapsed == ".." or collapsed.startswith("../"):
        return None
    return PurePosixPath(collapsed)


def skill_dir_for(rel_path: str, *, root: Path) -> PurePosixPath | None:
    """The skill directory a single changed path belongs to, or None.

    Walks from the file's parent up to the repository root and returns the first ancestor
    that currently holds a ``SKILL.md`` (checked on disk under ``root``). Returns None when
    no ancestor is a skill — including when the skill's ``SKILL.md`` was deleted, so a removed
    skill is never handed back as something to evaluate.
    """
    path = _contained_path(rel_path)
    if path is None:
        return None
    for parent in (path.parent, *path.parent.parents):
        if (root / parent / "SKILL.md").is_file():
            return parent
    return None


def plugin_root_for(rel_path: str, *, root: Path) -> PurePosixPath | None:
    """The Agent Plugin directory a single changed path belongs to, or None.

    Same walk as :func:`skill_dir_for`, probing for a ``plugin.json`` instead. A deleted
    plugin (no ``plugin.json`` left on disk) is None, matching the deleted-skill rule.
    """
    path = _contained_path(rel_path)
    if path is None:
        return None
    for parent in (path.parent, *path.parent.parents):
        if (root / parent / PLUGIN_MANIFEST).is_file():
            return parent
    return None


def _under(skill: PurePosixPath, roots: Sequence[PurePosixPath]) -> bool:
    return any(
        root == PurePosixPath(".") or skill == root or root in skill.parents for root in roots
    )


def scope_roots(under: Sequence[str]) -> list[PurePosixPath]:
    """``--under`` values, normalised; ``ValueError`` for one that names nothing inside the
    checkout (absolute, or climbing out with ``..``) — a scope that matches no path would
    print "no skills changed" for every pull request, the false green this command exists to
    prevent."""
    roots: list[PurePosixPath] = []
    for raw in under:
        root = _contained_path(raw)
        if root is None:
            raise ValueError(
                f"--under {raw!r} does not name a directory inside the repository (an absolute "
                "path or one that climbs out with '..' matches nothing a diff can contain)"
            )
        roots.append(root)
    return roots


def changed_skills(
    paths: Iterable[str], *, root: Path | None = None, under: Sequence[str] = ()
) -> list[PurePosixPath]:
    """The skill directories touched by ``paths``, sorted and de-duplicated (§18).

    ``paths`` are repository-relative changed files (what ``git diff --name-only`` prints);
    ``root`` is the repository checkout the ``SKILL.md`` presence is checked against, the
    current directory by default. Two changes inside one skill collapse to one entry, so the
    caller runs each affected skill exactly once.

    Attribution is skill-first: a change *inside* a skill counts only as that skill, even
    when the skill sits in a plugin. Only a change with no skill ancestor falls through to
    the plugin rule, which fans out to every skill the plugin currently carries.

    ``under`` limits the answer to skills inside the named directories — the repository's real
    skill roots. A repository that also keeps test fixtures shaped like skills (this one keeps
    deliberately hostile ones under ``tests/``) would otherwise hand them to every CI job that
    evaluates "the changed skills". The filter applies to the *skill* found, after attribution,
    so a plugin-level change still fans out — to the plugin's skills that are in scope.
    """
    base = root if root is not None else Path.cwd()
    roots = scope_roots(under)
    found: set[PurePosixPath] = set()
    for raw in paths:
        skill = skill_dir_for(raw, root=base)
        if skill is not None:
            found.add(skill)
            continue
        plugin = plugin_root_for(raw, root=base)
        if plugin is not None:
            for skill_dir in plugin_skill_dirs(base / plugin):
                found.add(plugin / PLUGIN_SKILLS_DIR / skill_dir.name)
    if roots:
        found = {skill for skill in found if _under(skill, roots)}
    return sorted(found, key=str)
