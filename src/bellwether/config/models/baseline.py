"""The platform baseline document (§12.6).

Every run touches infrastructure regardless of skill: the harness's own configuration,
the skill's installed body, ``/etc/passwd`` through a libc call, ``~/.cache``. Without
an allowlist to subtract, a naive reading of a declared scope produces dozens of
``exceeded`` entries per run, reviewers stop reading the section, and the most valuable
output in the tool dies of noise.

The document is versioned and keyed to a sandbox image: a baseline collected under a
different image describes a different platform, and applying it silently would make two
evaluations incomparable. ``platform_baseline_version`` is recorded in every run header
and joins the baseline regression key (§17.5).

Matching semantics live in :mod:`bellwether.assertions.baseline` — this module is the
document. The two rules that keep subtraction honest are worth stating where the schema
lives, because they shape it: entries are matched **literally after normalization**
(placeholders, not run-local paths), and a traversal sequence never resolves *into* a
baseline match — ``~/.cache/../.aws/credentials`` raises a near-miss finding rather
than disappearing under ``${HOME}/.cache/**``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from bellwether.config.models.common import Document, StrictModel

__all__ = ["BaselinePaths", "BaselineProcesses", "PlatformBaseline"]


class BaselinePaths(StrictModel):
    """Path globs the platform accounts for, split by access kind.

    Globs support ``**`` (crosses directories), ``*`` and ``?`` (within a segment), and
    brace alternation (``/etc/{passwd,group}``). They are written over *normalized*
    paths — ``${HOME}``, ``${TMP}``, ``${WORKSPACE}``, ``${SKILL_INSTALL_PATH}`` — so
    one baseline applies to every run regardless of per-run randomisation.
    """

    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()


class BaselineProcesses(StrictModel):
    """Process attribution rules (§10.3, §12.6).

    ``always`` is permitted anywhere in the tree — the shells and trampolines every
    toolchain spawns. ``helpers_of`` maps a root process to the helpers it legitimately
    spawns, evaluated **by tree**: ``git-remote-https`` under ``git`` is ordinary;
    the same binary with no ``git`` ancestor matches a helper's name without a helper's
    parentage, which is a near-miss, not a pass. A ``curl`` under ``git`` matches
    nothing and stays a violation.
    """

    always: tuple[str, ...] = ()
    helpers_of: dict[str, tuple[str, ...]] = Field(default_factory=dict)


class PlatformBaseline(Document):
    """``.bellwether/platform-baseline.yaml``."""

    kind: Literal["PlatformBaseline"]
    #: The baseline's own version, recorded in every run header. Date-shaped by
    #: convention (``2026.08.1``) but any string works; comparability is exact match.
    version: str
    #: The sandbox image this baseline was collected against, digest included. ``None``
    #: is the shipped placeholder: the matcher refuses to subtract anything until it is
    #: filled in, because an unkeyed allowlist absorbs findings it has no standing to
    #: absorb. The refusal carries this explanation.
    applies_to_image: str | None = None
    paths: BaselinePaths = Field(default_factory=BaselinePaths)
    processes: BaselineProcesses = Field(default_factory=BaselineProcesses)
    #: Tool names (tier-1 ``tool:<name>`` without the prefix) the platform accounts
    #: for. Empty in the shipped default: a tool call is agent behaviour, not
    #: infrastructure, until a harness demonstrates otherwise.
    tools: tuple[str, ...] = ()

    def applicable_to(self, image: str) -> tuple[bool, str]:
        """Whether this baseline may be applied to a run on ``image``, and why not.

        A reason string, not a bare bool: the refusal reaches ``doctor`` and the
        report, and "baseline not applied" must never look like "nothing to absorb".
        """
        if self.applies_to_image is None:
            return False, (
                "the baseline's applies_to_image is unset (shipped placeholder); an "
                "allowlist not keyed to an image absorbs findings it has no standing "
                "to absorb — fill it in with the configured sandbox image"
            )
        if self.applies_to_image != image:
            return False, (
                f"the baseline was collected against {self.applies_to_image!r} but this "
                f"run uses {image!r}; a baseline for a different image describes a "
                "different platform"
            )
        return True, "baseline applies"
