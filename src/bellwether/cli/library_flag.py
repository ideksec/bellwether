"""The §19.3 coexistence flag: a pull request that changes a description flags the library.

§19.3: "A change to any skill's ``description_digest`` (§6.1) additionally flags the library for
coexistence re-run on the next scheduled build (§7.4) — it does not trigger a synchronous
library-wide matrix on the pull request, which at the costs above is not affordable. The PR
comment says the library was flagged and when the scheduled run will resolve it."

The description is the trigger surface: it is what a harness shows the model when it decides
which skill to load, so a changed description can start winning activations meant for another
skill — or stop winning its own — without any other file moving. A pull request that touches
only a skill's body or scripts changes nothing about collisions, and is not flagged.

``description_changed`` compares each changed skill's ``SKILL.md`` at the pull request's head
with the same file in a tree of the base commit (the workflow extracts it with ``git archive``;
this module runs no git). The comparison is the §6.1 ``description_digest``, which normalises
whitespace, so a pure reflow of the same sentence is not a change. A skill the base lacks is
*added*, one the head lacks is *removed*: both change the library's composition, and both flag.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from bellwether.errors import BellwetherError
from bellwether.report.mdsafe import code
from bellwether.skill import SKILL_FILE, description_digest, parse_skill_markdown

__all__ = [
    "FLAG_MARKER",
    "DescriptionChange",
    "description_changed",
    "render_flag_markdown",
]

#: The first line of the flag comment, by which ``pr-comment`` recognises it (one per PR).
FLAG_MARKER = "<!-- bellwether-coexistence-flag -->"

#: When the scheduled run that resolves a flag fires (``bellwether-coexistence.yml``).
SCHEDULE_HINT = "Mondays at 05:23 UTC"

ChangeStatus = Literal["changed", "added", "removed", "unchanged"]


@dataclass(frozen=True)
class DescriptionChange:
    """One changed skill's description, head against base."""

    skill: str
    status: ChangeStatus

    @property
    def flags(self) -> bool:
        return self.status != "unchanged"


def _digest_at(skill_md: Path) -> str | None:
    """The description digest of a ``SKILL.md``, or ``None`` where there is no file."""
    if not skill_md.is_file():
        return None
    try:
        text = skill_md.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise BellwetherError(f"cannot read {skill_md}: {type(error).__name__}") from None
    parsed = parse_skill_markdown(text)
    description = parsed.frontmatter.description if parsed.frontmatter is not None else None
    return description_digest(description)


def description_changed(
    skills: Sequence[str], *, head: Path, base: Path | None
) -> list[DescriptionChange]:
    """Compare each skill's description at ``head`` with the same path under ``base``.

    ``skills`` are repository-relative skill directories as ``changed-skills`` printed them.
    ``base`` is a tree holding the base commit's files at the same relative paths; ``None``
    (no base tree at all) reads every skill as added, which is what a first commit is.
    """
    out: list[DescriptionChange] = []
    for skill in skills:
        now = _digest_at(head / skill / SKILL_FILE)
        then = _digest_at(base / skill / SKILL_FILE) if base is not None else None
        if now is None and then is None:
            raise BellwetherError(
                f"{skill} has no {SKILL_FILE} at the head or the base; it is not a skill in either"
            )
        if then is None:
            status: ChangeStatus = "added"
        elif now is None:
            status = "removed"
        elif now != then:
            status = "changed"
        else:
            status = "unchanged"
        out.append(DescriptionChange(skill=skill, status=status))
    return out


def render_flag_markdown(changes: Sequence[DescriptionChange]) -> str:
    """The pull-request comment: flagged, with what changed and when it resolves — or not."""
    flagged = [change for change in changes if change.flags]
    lines = [FLAG_MARKER]
    if not flagged:
        lines += [
            "### Library not flagged for a coexistence re-run",
            "",
            "No skill in this pull request changed its description, was added or was removed, "
            "so the trigger-collision matrix (§7.4) is unaffected.",
        ]
        return "\n".join(lines) + "\n"
    words = {"changed": "changed its description", "added": "is new", "removed": "is removed"}
    lines += [
        "### Library flagged for a coexistence re-run (§7.4, §19.3)",
        "",
        "A description is the trigger surface a harness shows the model, so this pull request "
        "can change which skill wins an activation:",
        "",
    ]
    lines += [f"- {code(change.skill)} {words[change.status]}" for change in flagged]
    lines += [
        "",
        (
            "The library-wide trigger-collision matrix does **not** run on a pull request. It "
            f"runs on the schedule ({SCHEDULE_HINT}, `Bellwether coexistence`) when the "
            "repository variable `BELLWETHER_COEXISTENCE` is set, or when a maintainer runs that "
            "workflow by hand; its report compares the matrix with the committed library "
            "baseline and keeps one issue open while a probe is won by another skill."
        ),
    ]
    return "\n".join(lines) + "\n"
