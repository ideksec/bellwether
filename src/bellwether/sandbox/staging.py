"""Staging the skill payload for installation into the container (§9.1 step 3, §3.5).

Only the portable skill payload is copied: the files a normal harness would load.
``evals/`` and everything under it MUST NOT be copied, because a skill that can see the
test machinery can behave only while it is being watched.

The payload is defined by an **allowlist** (:mod:`bellwether.skill.payload`), so a new
Bellwether file added later cannot leak into the container by omission. This module is
the second half of that guarantee: it copies what the allowlist selected, and it asserts
the outcome rather than trusting the filter — the cost of being wrong here is that every
run of every skill is silently observing a different thing than it reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from bellwether.errors import SkillError
from bellwether.sandbox.fixtures import normalize_metadata
from bellwether.skill import EVALS_DIR, SkillPackage

__all__ = ["StagedPayload", "stage_payload"]


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
        normalize_metadata(target, is_dir=False, executable=bool(origin.stat().st_mode & 0o100))
        staged.append(relative)

    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir() and not path.is_symlink()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        normalize_metadata(directory, is_dir=True, executable=False)
    normalize_metadata(destination, is_dir=True, executable=False)

    payload = StagedPayload(
        root=destination,
        install_path=PurePosixPath(install_path) / package.name,
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
