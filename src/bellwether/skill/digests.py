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
    "has_unusual_path_characters",
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
#:
#: Version 2 length-prefixes every field. Version 1 delimited them with newlines, and
#: newlines are legal in POSIX filenames — so a package containing a file named
#: ``a\nsha256:<hash>\nb`` produced the same digest as a package containing files ``a``
#: and ``b``. A forgeable ``package_digest`` is a forgeable review attestation (§6.3) and
#: a forgeable cache key (§19.2), so this is an integrity property, not a formatting
#: preference.
DIGEST_FORMAT = "bellwether/skill-digest/2"


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
    """Digest a set of files, order-independently and unambiguously.

    The input is ``DIGEST_FORMAT``, then the file count, then for each file — sorted by
    path — the byte length of the path followed by the path, and the byte length of the
    digest followed by the digest.

    **Every field is length-prefixed**, so no arrangement of file names can be read as a
    different arrangement. Delimiting with a separator instead makes the encoding
    ambiguous the moment a filename can contain that separator, and POSIX filenames can
    contain almost anything.

    Sorting here as well as in the walk means the result does not depend on the caller
    having preserved the walk's order: a subset such as the payload file list is built by
    filtering, and a filter that reordered would otherwise change the digest without
    changing the files.
    """
    hasher = hashlib.sha256()
    _feed(hasher, DIGEST_FORMAT.encode("utf-8"))
    ordered = sorted(records, key=lambda item: item.path)
    hasher.update(len(ordered).to_bytes(8, "big"))
    for record in ordered:
        _feed(hasher, record.path.encode("utf-8"))
        _feed(hasher, record.sha256.encode("utf-8"))
    return "sha256:" + hasher.hexdigest()


def _feed(hasher: hashlib._Hash, data: bytes) -> None:
    """Absorb one length-prefixed field."""
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)


def description_digest(description: str | None) -> str:
    """Digest the normalized ``description`` frontmatter field alone (§6.1)."""
    hasher = hashlib.sha256()
    _feed(hasher, DIGEST_FORMAT.encode("utf-8"))
    _feed(hasher, b"description")
    _feed(hasher, normalize_description(description or "").encode("utf-8"))
    return "sha256:" + hasher.hexdigest()


def has_unusual_path_characters(path: str) -> bool:
    """True where a path holds control characters worth a reviewer's attention.

    Length-prefixing already makes the digest unambiguous, so this is not a correctness
    control. A skill shipping a file whose name contains a newline is doing something a
    reviewer should see, which is a different reason to report it.
    """
    return any(character < " " or character == "\x7f" for character in path)
