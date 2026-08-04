"""Fixture materialisation with normalized metadata (§9.1 step 1, §9.3).

Bellwether's job is to *measure* nondeterminism, so it must hold everything else
constant. An ordinary copy does not: it stamps each repetition with the time it happened
and whatever umask the runner had, so every repetition starts from a workspace that
differs from the last in mtime and mode. That is non-identical in exactly the way §9.3
forbids, and it adds metadata churn to the filesystem diff that reads as skill behaviour.

Fixtures are therefore re-materialised per repetition — never reused — with mtimes,
modes and ownership normalised, so that two materialisations of the same fixture are
byte- and metadata-identical.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from bellwether.determinism import sorted_walk, stable_hash_bytes

__all__ = [
    "DIRECTORY_MODE",
    "EXECUTABLE_MODE",
    "FILE_MODE",
    "FIXTURE_DIGEST_FORMAT",
    "NORMALIZED_MTIME",
    "MaterializedFixture",
    "fixture_digest",
    "materialize_fixture",
    "normalize_metadata",
]

#: The fixed epoch every materialised file is stamped with: 1980-01-01T00:00:00Z. Chosen
#: because it is the earliest timestamp several archive formats can represent, so a
#: fixture that later travels through one is not silently re-stamped.
NORMALIZED_MTIME = 315_532_800

FILE_MODE = 0o644
EXECUTABLE_MODE = 0o755
DIRECTORY_MODE = 0o755

#: Domain separator for the fixture digest. Distinct from the skill digest's, so a
#: fixture and a skill package containing identical bytes do not produce the same digest
#: and cannot be confused for one another in a cache key.
FIXTURE_DIGEST_FORMAT = "bellwether/fixture-digest/1"


@dataclass(frozen=True)
class MaterializedFixture:
    """The result of materialising one fixture into a workspace."""

    source: Path
    root: Path
    #: Digest over content and relative path, with canary paths excluded (§9.3).
    digest: str
    file_count: int
    total_bytes: int
    #: Paths excluded from the digest because a canary was planted there. Recorded so the
    #: exclusion is auditable rather than implicit.
    excluded_paths: tuple[str, ...] = ()
    #: Symlinks copied as links. Recorded because a fixture that links out of itself is
    #: worth knowing about before it is mounted into a container.
    symlinks: tuple[str, ...] = ()


def normalize_metadata(path: Path, *, is_dir: bool, executable: bool) -> None:
    """Flatten metadata on one materialised entry.

    Modes collapse to a fixed pair, except that the executable bit is preserved: a
    fixture whose script stops being executable is a broken fixture, and the run would
    fail for a reason that has nothing to do with the skill.

    Ownership is left to the copying process's own uid — the container runs as a
    non-root user with a fixed uid, and attempting to chown here would need privileges
    the host process deliberately does not have.
    """
    if is_dir:
        path.chmod(DIRECTORY_MODE)
    else:
        path.chmod(EXECUTABLE_MODE if executable else FILE_MODE)
    os.utime(path, (NORMALIZED_MTIME, NORMALIZED_MTIME), follow_symlinks=False)


def materialize_fixture(
    source: Path,
    destination: Path,
    *,
    exclude_from_digest: frozenset[str] | None = None,
) -> MaterializedFixture:
    """Copy ``source`` to ``destination`` with normalised metadata.

    Args:
        source: The fixture directory.
        destination: A fresh directory, created if absent. It must be empty: reusing a
            workspace across repetitions is the thing this function exists to prevent.
        exclude_from_digest: Workspace-relative paths whose content is excluded from the
            digest — the canary paths. §3.5 randomises canary markers per evaluation and
            §19 keys the run cache on ``fixture_digest``; without this exclusion the cache
            would miss on every evaluation.
    """
    if not source.is_dir():
        raise FileNotFoundError(f"fixture directory not found: {source}")
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise FileExistsError(
            f"{destination} is not empty; fixtures are re-materialised per repetition, "
            "never reused, so that every repetition starts from identical bytes (§9.3)"
        )

    symlinks: list[str] = []
    for relative in sorted_walk(source):
        origin = source / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)

        if origin.is_symlink():
            target.symlink_to(origin.readlink())
            symlinks.append(relative.as_posix())
            continue

        shutil.copyfile(origin, target)
        normalize_metadata(target, is_dir=False, executable=bool(origin.stat().st_mode & 0o100))

    # Directories are normalised after their contents: writing a file into a directory
    # updates that directory's mtime, so stamping it first would be undone.
    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir() and not path.is_symlink()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        normalize_metadata(directory, is_dir=True, executable=False)
    normalize_metadata(destination, is_dir=True, executable=False)

    excluded = exclude_from_digest or frozenset()
    digest, count, total = _digest_tree(destination, excluded)
    return MaterializedFixture(
        source=source,
        root=destination,
        digest=digest,
        file_count=count,
        total_bytes=total,
        excluded_paths=tuple(sorted(excluded)),
        symlinks=tuple(symlinks),
    )


def fixture_digest(root: Path, exclude: frozenset[str] | None = None) -> str:
    """Digest a materialised workspace, excluding canary paths."""
    return _digest_tree(root, exclude or frozenset())[0]


def _digest_tree(root: Path, exclude: frozenset[str]) -> tuple[str, int, int]:
    """Digest content and paths, length-prefixed so no name can be read as another."""
    hasher = hashlib.sha256()
    _feed(hasher, FIXTURE_DIGEST_FORMAT.encode("utf-8"))

    count = 0
    total = 0
    for relative in sorted_walk(root):
        posix = relative.as_posix()
        if posix in exclude:
            continue
        path = root / relative
        if path.is_symlink():
            content = f"symlink:{path.readlink()}".encode()
        else:
            content = path.read_bytes()
            total += len(content)
        count += 1
        _feed(hasher, posix.encode("utf-8"))
        _feed(hasher, stable_hash_bytes(content).encode("utf-8"))

    hasher.update(count.to_bytes(8, "big"))
    return "sha256:" + hasher.hexdigest(), count, total


def _feed(hasher: hashlib._Hash, data: bytes) -> None:
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)
