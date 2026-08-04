"""Shared error types.

This module is a leaf: it imports nothing from the rest of the package, so every layer
in the §8.1 stack may depend on it without creating a cycle.

The rule for every error surfaced to a user: it names *what* file, *where* in that file,
and *what would have been acceptable*. A stack trace is not an error message (§21).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "BellwetherError",
    "ConfigurationError",
    "PreconditionError",
    "SkillError",
    "TraceError",
    "UserFacingProblem",
]


class BellwetherError(Exception):
    """Base class for every error Bellwether raises deliberately."""


@dataclass(frozen=True)
class UserFacingProblem:
    """One human-readable problem with one input file.

    Attributes:
        path: Location within the document, dotted, e.g. ``sandbox.pids_limit``.
            Empty for problems about the document as a whole.
        message: A sentence. Lower case, no trailing period, no exception class names.
        hint: Optional second sentence naming the remedy or the allowed values.
    """

    path: str
    message: str
    hint: str | None = None

    def render(self) -> str:
        where = self.path or "<document root>"
        line = f"  {where}: {self.message}"
        if self.hint:
            line += f"\n      {self.hint}"
        return line


class ConfigurationError(BellwetherError):
    """A configuration, policy, manifest, or scenario document could not be used.

    Rendered as a block of sentences naming the file and the path within it. Never
    re-raise the underlying pydantic error to a user.
    """

    def __init__(self, source: Path | str, problems: list[UserFacingProblem]) -> None:
        self.source = str(source)
        self.problems = problems
        super().__init__(self.render())

    def render(self) -> str:
        count = len(self.problems)
        noun = "problem" if count == 1 else "problems"
        head = f"{self.source}: {count} {noun}"
        body = "\n".join(problem.render() for problem in self.problems)
        return f"{head}\n{body}"


class SkillError(BellwetherError):
    """A skill package could not be read.

    Reserved for problems that make the package unusable — no ``SKILL.md``, an
    unreadable file. Problems that are *findings about* the skill, such as missing
    frontmatter or a pinned model, are recorded on the package and reported, because a
    skill Bellwether refuses to load is a skill Bellwether cannot tell you anything about.
    """


class TraceError(BellwetherError):
    """An ARF trace could not be written or read as a well-formed document.

    Distinct from an *incomplete* trace, which is not an error: a run that crashed has no
    footer, and that absence is the signal that the trace is ``not_evaluable`` (§11.1).
    """


@dataclass
class PreconditionError(BellwetherError):
    """A policy/target combination cannot be satisfied, caught before any run executes.

    §16.4 requires this to be raised *before* a single API call is made, and requires the
    message to name the gate, the target, and the remedy. A precondition failure that
    surfaces after a matrix has been paid for is a bug.
    """

    gate: str
    target: str
    reason: str
    remedies: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            f"Cannot start: policy gate '{self.gate}' cannot be satisfied "
            f"for target '{self.target}': {self.reason}"
        ]
        if self.remedies:
            lines.append("  → " + ", or ".join(self.remedies))
        return "\n".join(lines)
