"""File hashing and the three skill digests (§6.1).

Three digests are computed and all three are load-bearing:

============================ ========================================= ==========================
Digest                       Covers                                    Used for
============================ ========================================= ==========================
``package_digest``           the full skill directory including        review attestation binding
                             ``evals/``                                (§6.3); library baseline
                                                                       keying (§7.4)
``payload_digest``           only the files installed into the         run-cache key and per-skill
                             container (§9.1 step 3)                   baseline key
``description_digest``       the normalized ``description`` field      coexistence re-run scoping
                             alone                                     (§7.4, §19.3)
============================ ========================================= ==========================

``payload_digest`` is separate from ``package_digest`` so that changing a scenario does
not invalidate cached runs of an unchanged skill, and changing the skill does.
``description_digest`` is separate again because a description change has library-wide
triggering effects that a package-level digest cannot distinguish from a body-only edit.

**The file walk is sorted, not filesystem-iteration order.** Otherwise digests are not
reproducible across machines and every cache key derived from them becomes machine-local.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from bellwether.determinism import sorted_walk, stable_hash_bytes
from bellwether.skill.frontmatter import normalize_description

__all__ = [
    "DIGEST_FORMAT",
    "RECORDED_REVIEW_PLACEHOLDER",
    "FileRecord",
    "description_digest",
    "merkle_digest",
    "read_file_records",
]

#: Stand-in for the digest recorded in ``metadata.review.last_human_review`` while
#: computing the digest that review binds to.
#:
#: §6.2 records ``package_digest`` inside ``evals/manifest.yaml``, which ``package_digest``
#: itself covers. Taken literally that is self-referential: writing the digest into the
#: file changes the file, which changes the digest, so a review could never be ``current``.
#: The attestation digest resolves it by blanking the recorded value before hashing —
#: everything a reviewer read is still covered, including the rest of the manifest, and
#: recording the result does not disturb it. See ``docs/spec-notes.md``.
RECORDED_REVIEW_PLACEHOLDER = "<recorded-review-digest>"

#: Domain separator and version for the merkle construction below. Recorded in the digest
#: itself so that a future change to the construction is visible as a changed digest
#: rather than as a silent comparison between two different things.
DIGEST_FORMAT = "bellwether/skill-digest/1"


@dataclass(frozen=True, order=True)
class FileRecord:
    """One file in a skill package.

    Attributes:
        path: POSIX path relative to the skill root. The sort key.
        sha256: Content digest, or the digest of ``symlink:<target>`` for a symlink.
        size_bytes: Content length; zero for a symlink.
        is_symlink: A symlink is hashed as its target string, never followed. A package
            containing a link to ``/etc/passwd`` must hash the link — following it would
            make the digest depend on the host and would hide the link itself.
        symlink_target: The raw target, recorded because it is the interesting part.
        is_executable: The owner-execute bit. Recorded in the inventory rather than mixed
            into the digest: the bit does not survive every checkout, and a digest that
            varies by clone configuration would make every cache key machine-local.
    """

    path: str
    sha256: str
    size_bytes: int
    is_symlink: bool = False
    symlink_target: str | None = None
    is_executable: bool = False


def _hash_one(root: Path, relative: Path) -> FileRecord:
    absolute = root / relative
    posix = PurePosixPath(relative.as_posix()).as_posix()

    if absolute.is_symlink():
        target = str(absolute.readlink())
        return FileRecord(
            path=posix,
            sha256=stable_hash_bytes(f"symlink:{target}".encode()),
            size_bytes=0,
            is_symlink=True,
            symlink_target=target,
        )

    data = absolute.read_bytes()
    return FileRecord(
        path=posix,
        sha256=stable_hash_bytes(data),
        size_bytes=len(data),
        is_executable=bool(absolute.stat().st_mode & 0o100),
    )


def read_file_records(root: Path) -> list[FileRecord]:
    """Hash every file under ``root``, in sorted-walk order."""
    return [_hash_one(root, relative) for relative in sorted_walk(root)]


def merkle_digest(records: list[FileRecord]) -> str:
    """Digest a set of files, order-independently.

    The input is ``DIGEST_FORMAT`` followed by one ``<path>\\n<sha256>\\n`` pair per file,
    sorted by path. Sorting here as well as in the walk means the result does not depend
    on the caller having preserved the walk's order — a subset such as the payload file
    list is built by filtering, and a filter that reordered would otherwise change the
    digest without changing the files.
    """
    hasher = hashlib.sha256()
    hasher.update(DIGEST_FORMAT.encode("utf-8"))
    hasher.update(b"\n")
    for record in sorted(records, key=lambda item: item.path):
        hasher.update(record.path.encode("utf-8"))
        hasher.update(b"\n")
        hasher.update(record.sha256.encode("utf-8"))
        hasher.update(b"\n")
    return "sha256:" + hasher.hexdigest()


def description_digest(description: str | None) -> str:
    """Digest the normalized ``description`` frontmatter field alone (§6.1)."""
    return stable_hash_bytes(
        (DIGEST_FORMAT + "\ndescription\n" + normalize_description(description or "")).encode(
            "utf-8"
        )
    )
