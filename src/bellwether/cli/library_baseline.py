"""The library baseline-update pull request (§7.4, §17.5, §18.4 step 5).

The scheduled coexistence run uploads its trigger-collision matrix; a maintainer who wants that
matrix to become the library's stored baseline (``_library.coexistence.json``) dispatches the
workflow with ``set_baseline``, and a job that evaluates nothing fetches the matrix from the
run's artifact, checks it against the checked-out tree, writes the file onto a bot branch and
opens a pull request — never a push to ``main`` (§17.5).

What is re-derived, and what is read: the matrix carries each member's package digest, and the
library key is their sorted hash. Those are recomputed here from the tree the job checked out
and must match, member by member, so a matrix of an earlier run — one measured before a skill
changed, or before one was added or removed — is refused with the difference named rather than
proposed as this library's baseline. What the run *observed* (who won each activation) cannot
be re-derived without spending again; the pull request body says so, and the maintainer
approving it is the control.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from pydantic import ValidationError

from bellwether.cli.baseline_pr import read_member
from bellwether.cli.coexistence import (
    LIBRARY_BASELINE_FILE,
    NOT_PORTABLE,
    CoexistenceMatrix,
    LibraryDelta,
    coexistence_findings,
    coexistence_status,
    library_key,
    render_coexistence_json,
)
from bellwether.errors import BellwetherError
from bellwether.report.mdsafe import code, text
from bellwether.skill import SkillPackage

__all__ = [
    "MATRIX_FILE",
    "LibraryBaselinePlan",
    "library_mismatch",
    "plan_library_baseline",
    "read_matrix_artifact",
    "render_library_baseline_pr_body",
]

#: The file ``bellwether coexistence`` writes and the workflow uploads on its own.
MATRIX_FILE = "coexistence.json"
#: A cap on the matrix member (uncompressed), checked before decompression. A matrix is a few
#: kilobytes per cell; a megabyte is already a thousand cells.
_MAX_MATRIX_BYTES = 8 * 1024 * 1024


def read_matrix_artifact(zip_bytes: bytes) -> CoexistenceMatrix:
    """The one ``coexistence.json`` in the matrix artifact, as a matrix.

    The artifact holds exactly one member named :data:`MATRIX_FILE`, wherever upload-artifact
    rooted it (at the archive root for a single uploaded file; under its run directory if the
    action kept one). Zero members, two or more, an oversized one or one that is not a matrix
    are each refused: a baseline proposal that picked one of several, or guessed, is the partial
    result §17.5 calls worse than a refusal.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise BellwetherError("the matrix artifact is not a zip archive") from None
    with archive:
        names = sorted(
            info.filename
            for info in archive.infolist()
            if not info.is_dir() and info.filename.rsplit("/", 1)[-1] == MATRIX_FILE
        )
        if len(names) != 1:
            raise BellwetherError(
                f"the matrix artifact holds {len(names)} member(s) named {MATRIX_FILE!r}"
                + (f" ({', '.join(names)})" if names else "")
                + "; exactly one is a run's matrix"
            )
        data = read_member(archive, names[0], _MAX_MATRIX_BYTES)
    assert data is not None  # the name came from the listing
    try:
        return CoexistenceMatrix.model_validate_json(data)
    except ValidationError as error:
        raise BellwetherError(
            f"{names[0]} in the artifact is not a coexistence matrix: {error}"
        ) from None


def library_mismatch(matrix: CoexistenceMatrix, packages: Sequence[SkillPackage]) -> str | None:
    """Why ``matrix`` is not a matrix of ``packages``' library, or ``None`` when it is.

    Member by member: a skill in the tree the matrix lacks (*added* since the run), one in the
    matrix the tree lacks (*removed*), one whose package digest moved (*changed*); then the key
    itself, which is the hash of the sorted digests and must agree whenever the members do.
    """
    now = {package.name: package.package_digest for package in packages}
    then = dict(matrix.member_digests)
    added = sorted(set(now) - set(then))
    removed = sorted(set(then) - set(now))
    changed = sorted(name for name in set(now) & set(then) if now[name] != then[name])
    parts = [
        f"{label}: {', '.join(names)}"
        for label, names in (("added", added), ("removed", removed), ("changed", changed))
        if names
    ]
    if parts:
        return (
            "the matrix is not this library's — since the run, " + "; ".join(parts) + " (by "
            "package digest); re-run the matrix on this tree before proposing it as the baseline"
        )
    if library_key(packages) != matrix.library_key:
        return (
            f"the matrix's library key {matrix.library_key[:19]}… is not the key of the members "
            f"it names ({library_key(packages)[:19]}…)"
        )
    return None


class LibraryBaselinePlan(NamedTuple):
    """What ``baseline library`` decided: the file, whether it changes, and what it replaces."""

    path: Path
    #: The stored file differs from (or lacks) the record about to be written.
    changed: bool
    #: A file was stored when the plan was made (whether or not it read as a baseline). Captured
    #: here because the body is rendered after the write, when the path always exists.
    stored: bool
    #: The stored baseline, where one could be read; ``None`` where none is stored.
    previous: CoexistenceMatrix | None
    #: How this matrix reads against the stored one (§7.4), for the body.
    delta: LibraryDelta


def plan_library_baseline(
    matrix: CoexistenceMatrix, baselines_dir: Path, *, delta: LibraryDelta
) -> LibraryBaselinePlan:
    """Decide whether writing ``matrix`` as the library baseline changes the stored file.

    What git would see decides: the bytes about to be written against the bytes stored. An
    identical record is not rewritten and nothing is proposed. A stored file that is not a valid
    baseline is *replaced*, not refused — the proposal is what fixes it, and the body says so.
    """
    path = baselines_dir / LIBRARY_BASELINE_FILE
    previous: CoexistenceMatrix | None = None
    stored: str | None = None
    if path.is_file():
        stored = path.read_text(encoding="utf-8")
        try:
            previous = CoexistenceMatrix.model_validate_json(stored)
        except ValidationError:
            previous = None
    rendered = render_coexistence_json(matrix)
    return LibraryBaselinePlan(
        path=path,
        changed=stored != rendered,
        stored=stored is not None,
        previous=previous,
        delta=delta,
    )


def _describe(matrix: CoexistenceMatrix) -> str:
    return (
        f"{len(matrix.members)} skill(s), key {code(matrix.library_key[:19] + '…')}, on "
        f"{code(matrix.target)} at N={matrix.n} ({code(matrix.harness)})"
    )


def render_library_baseline_pr_body(
    matrix: CoexistenceMatrix,
    plan: LibraryBaselinePlan,
    *,
    run_id: int,
    run_url: str | None,
    baselines_dir: str,
) -> str:
    """The library baseline pull request's body: which run, what it replaces, what it shows."""
    lines = ["## Bellwether library baseline update", ""]
    lines.append(
        f"Proposes the trigger-collision matrix (§7.4) that coexistence run {run_id} recorded as "
        f"the library's stored baseline, `{baselines_dir.rstrip('/')}/{LIBRARY_BASELINE_FILE}`."
    )
    lines.append("")
    lines.append(f"- Library: {_describe(matrix)}")
    if not matrix.portable:
        lines.append(f"- **{NOT_PORTABLE}** — measured on `api-loop` (§9.4)")
    if run_url:
        lines.append(f"- Run and matrix: {run_url}")
    if plan.previous is None:
        replaces = (
            "a stored file that is not a valid library baseline"
            if plan.stored
            else "no stored baseline"
        )
    else:
        replaces = f"the stored baseline of {_describe(plan.previous)}"
    lines.append(f"- Replaces: {replaces}")
    lines += ["", "**What the matrix shows**", ""]
    # Composed from code spans no name can close (coexistence_findings); not escaped again.
    findings = coexistence_findings(matrix, plan.delta)
    status = coexistence_status(matrix, plan.delta)
    collisions = [item for item in findings if item not in plan.delta.changes]
    lines += [f"- {item}" for item in collisions] or [
        "- No probe's activation was won by another skill."
    ]
    lines += ["", "**Against the stored baseline**", ""]
    if not plan.delta.comparable:
        lines.append(f"- Not compared: {text(plan.delta.reason)}.")
    elif not plan.delta.changes:
        lines.append("- No change.")
    else:
        lines += [f"- {change}" for change in plan.delta.changes]
    lines += [
        "",
        "### Before approving",
        "",
        (
            "Every member's package digest in the matrix was recomputed from this commit's tree "
            "and matches, so this is a matrix of the library as it is here. What the run "
            "*observed* — which skill won each activation — was not re-run: it is read from the "
            "run's artifact, so read the run's report before approving."
        ),
        "",
        (
            "The next scheduled run is compared against this record. A collision it records "
            "still opens the library's issue — collisions are read from each run on its own — "
            "but a winner count recorded here stops reading as a change."
            if status == "collisions"
            else (
                "The next scheduled run is compared against this record: a winner count "
                "recorded here stops reading as a change, and a collision still opens the "
                "library's issue on its own."
            )
        ),
        "",
        (
            "Two proposals for the library baseline conflict; regenerate it on `main` rather "
            "than merging the two by hand."
        ),
    ]
    return "\n".join(lines) + "\n"
