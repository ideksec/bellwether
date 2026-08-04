"""Reading the filesystem diff from a host-side overlay upper directory (§9.1 step 9, §10.2).

The workspace is mounted as an overlayfs whose upper directory lives on the host, outside
the container's reach. After the run, Bellwether reads that directory directly: created,
modified and deleted paths fall out of it with no in-container component at all, which is
what makes ``--cap-drop=ALL`` achievable (§10.0).

**This is O(changes), not O(tree).** A full pre/post walk per run dominates wall clock
across a large matrix — a 20-repetition set over a repository fixture would re-hash the
whole tree forty times to learn that three files moved. Full-tree hashing stays available
behind ``--paranoid`` for storage drivers with no accessible upper directory.

Overlayfs records a deletion as a **character device with major and minor 0** at the
deleted path, and an opaque directory with the ``trusted.overlay.opaque`` xattr. Reading
those correctly is the difference between "the skill deleted your source tree" and "no
changes observed".
"""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from bellwether.determinism import stable_hash_bytes
from bellwether.errors import BellwetherError

__all__ = [
    "ChangeKind",
    "OverlayMount",
    "PathChange",
    "mount_overlay",
    "overlay_available",
    "read_overlay_diff",
]

#: What happened to a path. ``modified`` and ``created`` are not distinguishable from the
#: upper directory alone — a copy-up looks identical either way — so they are separated by
#: comparing against the lower directory, which is cheap because only changed paths are
#: consulted.
ChangeKind = Literal["created", "modified", "deleted", "mode_changed"]

_WHITEOUT_MODE = 0


@dataclass(frozen=True)
class PathChange:
    """One changed path, workspace-relative."""

    path: str
    kind: ChangeKind
    #: Content digest after the change. ``None`` for a deletion.
    sha256: str | None = None
    size_bytes: int | None = None
    #: Recorded separately from content so a mode change is visible without polluting the
    #: content diff (§9.1 step 5).
    mode: int | None = None
    is_directory: bool = False


@dataclass(frozen=True)
class OverlayMount:
    """A mounted overlayfs, and the pieces needed to unmount it."""

    merged: Path
    lower: Path
    upper: Path
    work: Path

    def unmount(self) -> None:
        result = subprocess.run(
            ["umount", str(self.merged)], capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise BellwetherError(
                f"could not unmount {self.merged}: {result.stderr.strip() or result.returncode}"
            )


def overlay_available() -> tuple[bool, str]:
    """Whether a host-side overlay upper directory is obtainable, and why not where not.

    Checked explicitly because the fallback — full-tree hashing behind ``--paranoid`` —
    is a large wall-clock regression, and §10.7 requires a degraded plane to carry a
    reason a user can act on rather than an enum.
    """
    try:
        filesystems = Path("/proc/filesystems").read_text(encoding="utf-8")
    except OSError:
        return False, "could not read /proc/filesystems; this host may not be Linux"
    if "overlay" not in filesystems:
        return False, "the kernel does not provide overlayfs"
    if os.geteuid() != 0:
        return False, (
            "mounting overlayfs needs root, and this process is not root; "
            "run the container integration tests under sudo, or accept full-tree "
            "hashing via --paranoid"
        )
    return True, "overlayfs mountable"


def mount_overlay(lower: Path, upper: Path, work: Path, merged: Path) -> OverlayMount:
    """Mount an overlayfs with a host-side upper directory.

    Requires privileges the *host* has and the container does not — which is the whole
    architecture in one line (§10.0).
    """
    for directory in (lower, upper, work, merged):
        directory.mkdir(parents=True, exist_ok=True)

    options = f"lowerdir={lower},upperdir={upper},workdir={work}"
    result = subprocess.run(
        ["mount", "-t", "overlay", "overlay", "-o", options, str(merged)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise BellwetherError(
            f"could not mount overlayfs at {merged}: "
            f"{result.stderr.strip() or result.returncode}. "
            "Without an accessible upper directory the filesystem plane falls back to "
            "full-tree hashing, which is a large wall-clock regression — so this is "
            "reported rather than absorbed (§10.7)."
        )
    return OverlayMount(merged=merged, lower=lower, upper=upper, work=work)


def read_overlay_diff(upper: Path, lower: Path | None = None) -> list[PathChange]:
    """Read the changed-path set from an overlay upper directory.

    Sorted, so the same set of changes produces the same order on every machine (§24).
    """
    changes: list[PathChange] = []

    for absolute in sorted(upper.rglob("*"), key=lambda path: path.as_posix()):
        relative = absolute.relative_to(upper).as_posix()
        info = absolute.lstat()

        if _is_whiteout(info):
            changes.append(PathChange(path=relative, kind="deleted"))
            continue

        if stat.S_ISDIR(info.st_mode):
            # A directory in the upper layer is usually just the parent of a changed
            # file, copied up so the child can exist. Reporting every one would bury the
            # actual changes; an opaque directory is different and is reported.
            if _is_opaque(absolute):
                changes.append(
                    PathChange(
                        path=relative,
                        kind="modified",
                        mode=stat.S_IMODE(info.st_mode),
                        is_directory=True,
                    )
                )
            continue

        if absolute.is_symlink():
            target = str(absolute.readlink())
            changes.append(
                PathChange(
                    path=relative,
                    kind=_kind_for(relative, lower),
                    sha256=stable_hash_bytes(f"symlink:{target}".encode()),
                    size_bytes=0,
                    mode=stat.S_IMODE(info.st_mode),
                )
            )
            continue

        content = absolute.read_bytes()
        changes.append(
            PathChange(
                path=relative,
                kind=_kind_for(relative, lower),
                sha256=stable_hash_bytes(content),
                size_bytes=len(content),
                mode=stat.S_IMODE(info.st_mode),
            )
        )

    return changes


def _kind_for(relative: str, lower: Path | None) -> ChangeKind:
    """``created`` where the path did not exist below, ``modified`` where it did."""
    if lower is None:
        return "modified"
    return "modified" if (lower / relative).exists() else "created"


def _is_whiteout(info: os.stat_result) -> bool:
    """Overlayfs marks a deletion as a character device with device number 0."""
    return stat.S_ISCHR(info.st_mode) and info.st_rdev == _WHITEOUT_MODE


def _is_opaque(path: Path) -> bool:
    """An opaque directory replaced, rather than merged with, the one below it."""
    try:
        return b"y" in os.getxattr(path, "trusted.overlay.opaque")
    except OSError:
        # Reading a trusted xattr needs CAP_SYS_ADMIN; absent it, treat the directory as
        # ordinary rather than guessing. The files inside it are still reported.
        return False
