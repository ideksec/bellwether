"""Staging the skill payload for installation into the container (§9.1 step 3, §3.5).

Only the portable skill payload is copied: the files a normal harness would load.
``evals/`` and everything under it MUST NOT be copied, because a skill that can see the
test machinery can behave only while it is being watched.

The payload is defined by an **allowlist** (:mod:`bellwether.skill.payload`), so a new
Bellwether file added later cannot leak into the container by omission. This module is
the second half of that promise: it copies what the allowlist selected, and it asserts
the outcome rather than trusting the filter — the cost of being wrong here is that every
run of every skill is silently observing a different thing than it reports.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from bellwether.determinism import sorted_walk
from bellwether.errors import SkillError
from bellwether.sandbox.fixtures import fixture_digest, normalize_metadata
from bellwether.skill import EVALS_DIR, SkillPackage, names_machinery_dir

#: Version-control metadata never staged into a container (§3.5). A plugin that is its own
#: checkout carries the whole evaluation machinery inside ``.git`` — leaving the working-tree
#: ``evals/`` behind is not enough when ``git show HEAD:evals/scenarios.yaml`` recovers it.
#: Compared case- and form-folded for the same reason ``evals/`` is: a checkout on a
#: case-insensitive filesystem can spell it ``.Git``.
_VCS_DIRS = frozenset({".git", ".hg", ".svn", ".bzr"})

__all__ = [
    "StagedBundle",
    "StagedPayload",
    "bundle_exclusion",
    "plugin_bundle_digest",
    "stage_companions",
    "stage_payload",
    "stage_plugin_bundle",
]


def bundle_exclusion(parts: Sequence[str]) -> str | None:
    """Why a path inside a plugin bundle is not staged, or ``None`` where it is.

    One function, because the copy and the digest that keys the run cache have to agree. They
    did not: the digest hashed the whole checkout, so a bundle that is its own git repository
    changed digest on every commit and never hit the cache, while the thing actually placed
    in the container had not changed at all.

    Returns ``"machinery"`` for anything under an ``evals/`` directory at any depth (§3.5)
    and ``"vcs"`` for anything under version-control metadata.
    """
    if names_machinery_dir(parts):
        return "machinery"
    if any(unicodedata.normalize("NFC", part).casefold() in _VCS_DIRS for part in parts):
        return "vcs"
    return None


def plugin_bundle_digest(bundle_root: Path) -> str:
    """Digest exactly what :func:`stage_plugin_bundle` would place in the container.

    The run cache replays a recorded trace when its key matches (§19.2), so the key has to
    describe the bundle *as installed*. Hashing the bundle's working directory instead counts
    content the container never sees — a plugin developed in place would thrash the cache on
    every commit, and the cost of that is paid in tokens.
    """
    excluded = frozenset(
        relative.as_posix()
        for relative in sorted_walk(bundle_root)
        if bundle_exclusion(relative.parts) is not None
    )
    return fixture_digest(bundle_root, excluded)


@dataclass(frozen=True)
class StagedPayload:
    """What was placed where, ready to be mounted or copied into the container."""

    root: Path
    #: Path *inside* the container where the harness expects to find the skill.
    install_path: PurePosixPath
    #: The digest that keys the run cache and the per-skill baseline (§6.1).
    payload_digest: str
    files: tuple[str, ...]
    #: Symlinks that were **not** staged because their target escapes the payload.
    #: Refused rather than copied: a link out of the payload is a way to place host
    #: content inside the container's view of the skill.
    refused_symlinks: tuple[str, ...] = ()

    def contains_machinery(self) -> bool:
        """Belt and braces for the §3.5 invariant. Always false, and checked anyway."""
        return any(
            path == EVALS_DIR.rstrip("/") or path.startswith(EVALS_DIR) for path in self.files
        )


def stage_payload(
    package: SkillPackage,
    destination: Path,
    *,
    install_path: str | PurePosixPath = "/home/agent/.claude/skills",
    owner: tuple[int, int] | None = None,
) -> StagedPayload:
    """Copy a skill's payload into ``destination``, normalising metadata as it goes.

    Metadata is normalised for the same reason fixtures are (§9.3): the payload is part
    of the container's starting state, and a starting state that differs per repetition
    is not a controlled variable.
    """
    if destination.exists() and any(destination.iterdir()):
        raise SkillError(
            f"{destination} is not empty; the payload is staged into a fresh directory"
        )
    destination.mkdir(parents=True, exist_ok=True)

    staged: list[str] = []
    refused: list[str] = []

    for relative in package.payload.included:
        origin = package.root / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)

        if origin.is_symlink():
            if not _target_stays_inside(package.root, origin):
                refused.append(relative)
                continue
            target.symlink_to(origin.readlink())
            staged.append(relative)
            continue

        target.write_bytes(origin.read_bytes())
        normalize_metadata(
            target,
            is_dir=False,
            executable=bool(origin.stat().st_mode & 0o100),
            owner=owner,
        )
        staged.append(relative)

    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir() and not path.is_symlink()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        normalize_metadata(directory, is_dir=True, executable=False, owner=owner)
    normalize_metadata(destination, is_dir=True, executable=False, owner=owner)

    install_root = PurePosixPath(install_path)
    resolved_install = install_root / package.slug

    # Asserted, not assumed. `PurePosixPath.__truediv__` discards the left operand when the
    # right is absolute, so a declared name of `/etc` would silently relocate the mount.
    # The slug cannot do that; this catches a future change that stops using it.
    if not resolved_install.is_relative_to(install_root):
        raise SkillError(
            f"refusing to install: derived install path {resolved_install} escapes {install_root}"
        )

    payload = StagedPayload(
        root=destination,
        install_path=resolved_install,
        payload_digest=package.payload_digest,
        files=tuple(staged),
        refused_symlinks=tuple(refused),
    )

    # The §3.5 invariant, asserted rather than assumed. An allowlist that silently let a
    # machinery file through would mean every run observes a skill that knows it is being
    # observed, and nothing else in the system would notice.
    if payload.contains_machinery():
        raise SkillError(
            "refusing to install: the staged payload contains Bellwether machinery, "
            "which would let the skill under test detect that it is being evaluated (§3.5)"
        )
    leaked = sorted(
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file() and path.relative_to(destination).as_posix().startswith(EVALS_DIR)
    )
    if leaked:
        raise SkillError(
            f"refusing to install: {', '.join(leaked)} reached the staging directory (§3.5)"
        )
    return payload


def _target_stays_inside(root: Path, link: Path) -> bool:
    """True where a symlink resolves within the payload it belongs to."""
    target = link.readlink()
    resolved = target if target.is_absolute() else (link.parent / target)
    try:
        return resolved.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):
        # A broken or cyclic link resolves nowhere; treat it as escaping.
        return False


def stage_companions(
    companions: Sequence[SkillPackage],
    destination: Path,
    *,
    primary: SkillPackage,
    install_root: PurePosixPath,
    owner: tuple[int, int] | None = None,
) -> tuple[StagedPayload, ...]:
    """Stage a scenario's §7.4 companion skills beside the skill under test.

    A harness that discovers skills from what is installed (the ``claude-code`` CLI reads
    ``<config dir>/skills/``) can only be offered a competitor that is actually there, so each
    companion is staged exactly as the primary is — the same allowlisted payload, the same
    metadata normalisation, the same §3.5 machinery check — into its own directory under
    ``destination``, to be bound read-only at ``install_root / <slug>``. The primary's own
    staging is untouched: nothing under a companion is hashed into the primary's digests, which
    keeps the run cache and baselines keyed on the skill under test alone.

    Two skills that slug to the same directory would shadow one another at the install root,
    and "which activated" would then be undecidable — refused, naming both.
    """
    # Checked for the whole set before anything is copied, so a refusal leaves no
    # half-staged run directory behind.
    seen: dict[str, str] = {primary.slug: primary.name}
    for companion in companions:
        if companion.slug in seen:
            raise SkillError(
                f"companion skill {companion.name!r} would install at "
                f"{install_root / companion.slug}, the same directory as "
                f"{seen[companion.slug]!r}; two skills cannot share an install directory"
            )
        seen[companion.slug] = companion.name
    return tuple(
        stage_payload(
            companion,
            destination / companion.slug,
            install_path=install_root,
            owner=owner,
        )
        for companion in companions
    )


@dataclass(frozen=True)
class StagedBundle:
    """An Agent Plugin staged whole, ready to be mounted and loaded with ``--plugin-dir``."""

    root: Path
    #: Path *inside* the container the bundle is mounted at, and what ``--plugin-dir`` names.
    install_path: PurePosixPath
    #: Every file staged, relative to the bundle root, sorted (§24).
    files: tuple[str, ...]
    #: Skill directory names under ``skills/``, sorted — what the harness will discover.
    skill_names: tuple[str, ...]
    #: Machinery directories refused: every ``evals/`` under the bundle (§3.5).
    refused_machinery: tuple[str, ...] = ()
    #: Symlinks **not** staged because their target escapes the bundle — a different refusal
    #: from machinery, kept apart for the same reason :class:`StagedPayload` keeps them apart.
    refused_symlinks: tuple[str, ...] = ()
    #: Version-control metadata directories skipped (§3.5): a bundle that is its own checkout
    #: carries the evaluation machinery inside ``.git`` even after the working tree's ``evals/``
    #: is left behind, and ``git show HEAD:evals/scenarios.yaml`` would recover it.
    refused_vcs: tuple[str, ...] = ()
    #: Non-regular files skipped: a FIFO blocks the copy until a writer appears, and the
    #: observed process must never decide whether the observer finishes (§10.0).
    refused_special: tuple[str, ...] = ()


def stage_plugin_bundle(
    bundle_root: Path,
    destination: Path,
    *,
    name: str | None = None,
    install_path: str | PurePosixPath = "/home/agent/.claude/plugins",
    owner: tuple[int, int] | None = None,
) -> StagedBundle:
    """Copy an Agent Plugin bundle whole, in the layout a real client installs (§5, §6, §18).

    Bare-directory staging installs each skill on its own, which loses everything the bundle
    holds *outside* a skill directory — shared references a skill's body points at, the
    manifest itself — so a skill that reads a sibling path works in a real client and fails
    under evaluation for a reason that is about Bellwether, not the skill. Staging the bundle
    whole is what makes the evaluated arrangement the deployed one.

    The §3.5 invariant is unchanged and applies bundle-wide: **no ``evals/`` directory is
    copied**, anywhere under the bundle, because a skill that can see the test machinery can
    behave only while it is being watched. Each one skipped is named in ``refused_machinery``
    rather than silently dropped, and the outcome is asserted rather than trusted.
    """
    install_root = PurePosixPath(install_path)
    # The bundle's own name (``PluginBundle.name``: the manifest's declared name, or the
    # directory name where it declares none) decides the container path. The host checkout's
    # directory name must not: the same bundle checked out as ``plugin`` on CI and
    # ``plugin-dev`` on a laptop would install at two different paths, which makes the run
    # cache machine-local (§24) and leaks the operator's directory layout into the sandbox.
    # Falls back to the *resolved* directory name so ``bellwether run ..`` still names the
    # directory it actually points at rather than putting ``..`` in the container path.
    chosen = name if name is not None else bundle_root.resolve().name
    if chosen in ("", ".", "..") or "/" in chosen or "\\" in chosen:
        raise SkillError(
            f"refusing to install: {chosen!r} is not a usable directory name, so the plugin "
            f"at {bundle_root} has nowhere to install inside the container"
        )
    resolved_install = install_root / chosen

    # Asserted, not assumed, exactly as ``stage_payload`` does for a skill.
    if not resolved_install.is_relative_to(install_root) or resolved_install == install_root:
        raise SkillError(
            f"refusing to install: derived plugin path {resolved_install} escapes {install_root}"
        )

    if destination.exists() and any(destination.iterdir()):
        raise SkillError(f"{destination} is not empty; the bundle is staged into a fresh directory")
    destination.mkdir(parents=True, exist_ok=True)

    staged: list[str] = []
    refused_machinery: list[str] = []
    refused_symlinks: list[str] = []
    refused_vcs: list[str] = []
    refused_special: list[str] = []
    # Sorted walk (§24): the same bundle must stage to the same bytes on every machine.
    # ``rglob`` matches dotfiles, which is the point — a bundle's own ``.env`` or ``.claude``
    # is content a real client would install — so the exclusions below are explicit.
    for origin in sorted(bundle_root.rglob("*"), key=lambda path: path.as_posix()):
        relative = origin.relative_to(bundle_root)
        parts = relative.parts
        excluded = bundle_exclusion(parts)
        if excluded is not None:
            # Named once, at the directory that caused it, rather than once per file beneath.
            if bundle_exclusion(parts[:-1]) is None:
                (refused_machinery if excluded == "machinery" else refused_vcs).append(
                    relative.as_posix()
                )
            continue
        target = destination / relative
        if origin.is_symlink():
            # A link out of the bundle places host content inside the container's view of it.
            if not _target_stays_inside(bundle_root, origin):
                refused_symlinks.append(relative.as_posix())
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(origin.readlink())
            staged.append(relative.as_posix())
            continue
        if origin.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not origin.is_file():
            # A FIFO would block ``read_bytes`` until a writer appears, and nothing is going to
            # write: the observed tree must never decide whether the observer finishes (§10.0).
            refused_special.append(relative.as_posix())
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(origin.read_bytes())
        normalize_metadata(
            target,
            is_dir=False,
            executable=bool(origin.stat().st_mode & 0o100),
            owner=owner,
        )
        staged.append(relative.as_posix())

    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir() and not path.is_symlink()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        normalize_metadata(directory, is_dir=True, executable=False, owner=owner)
    normalize_metadata(destination, is_dir=True, executable=False, owner=owner)

    skills_dir = destination / "skills"
    skill_names = tuple(
        sorted(child.name for child in skills_dir.iterdir() if child.is_dir())
        if skills_dir.is_dir()
        else ()
    )

    # Asserted, not assumed — the §3.5 invariant is the one that silently ruins every run.
    leaked = sorted(
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file() and names_machinery_dir(path.relative_to(destination).parts)
    )
    if leaked:
        raise SkillError(
            f"refusing to install the bundle: {', '.join(leaked)} reached the staging "
            "directory, which would let a skill detect that it is being evaluated (§3.5)"
        )

    return StagedBundle(
        root=destination,
        install_path=resolved_install,
        files=tuple(sorted(staged)),
        skill_names=skill_names,
        refused_machinery=tuple(sorted(refused_machinery)),
        refused_symlinks=tuple(sorted(refused_symlinks)),
        refused_vcs=tuple(sorted(refused_vcs)),
        refused_special=tuple(sorted(refused_special)),
    )
