"""What gets installed into the container, and what never does (§9.1 step 3, §3.5).

The payload is defined by an **allowlist**, not a denylist. A skill that can see
Bellwether's own machinery can behave only while observed, and a denylist fails open: a
new Bellwether file added later leaks into the container by omission, and nobody notices
because nothing breaks.

The allowlist fails the other way — a new kind of skill file is *excluded* until someone
adds it — which is why exclusions are reported rather than silent. An excluded file that
a harness would have loaded is a real problem; it is just a visible one.
"""

from __future__ import annotations

import fnmatch
import unicodedata
from dataclasses import dataclass

__all__ = ["DEFAULT_PAYLOAD_ALLOWLIST", "EVALS_DIR", "PayloadAllowlist", "PayloadSplit"]

#: Everything under this directory is Bellwether machinery and MUST NOT be installed.
#: Consolidating it into one directory is what makes the exclusion a single rule rather
#: than a growing list of filenames (§5).
EVALS_DIR = "evals/"


def _is_machinery(path: str) -> bool:
    """True where ``path`` is (or is under) the ``evals/`` machinery directory (§5).

    Case- and form-insensitive: ``EVALS/manifest.yaml`` is Bellwether machinery just as
    much as ``evals/manifest.yaml`` and must not slip into the container merely because a
    checkout upper-cased the directory. The allowlist already fails closed — an unmatched
    path is excluded anyway — so this only fixes the *label*: such a file is machinery,
    not an unmatched skill file a reviewer should chase.
    """
    folded = unicodedata.normalize("NFC", path).casefold()
    prefix = EVALS_DIR.casefold()
    return folded == prefix.rstrip("/") or folded.startswith(prefix)


#: Files a harness would load. Globs are matched against the POSIX path relative to the
#: skill root, so ``reference/**`` covers any depth.
DEFAULT_PAYLOAD_ALLOWLIST: tuple[str, ...] = (
    "SKILL.md",
    "*.md",
    "reference/**",
    "references/**",
    "scripts/**",
    "assets/**",
    "templates/**",
    "LICENSE",
    "LICENSE.*",
)


@dataclass(frozen=True)
class PayloadSplit:
    """The result of applying an allowlist to a skill's file list."""

    included: tuple[str, ...]
    #: Excluded because they are Bellwether machinery. Expected, never reported as a
    #: problem.
    excluded_machinery: tuple[str, ...]
    #: Excluded because nothing in the allowlist matched. Worth surfacing: if a harness
    #: would have loaded one of these, the skill under test is not the skill installed.
    excluded_unmatched: tuple[str, ...]

    def has_unmatched(self) -> bool:
        return bool(self.excluded_unmatched)


@dataclass(frozen=True)
class PayloadAllowlist:
    """Decides which files of a skill package are installed into the container."""

    patterns: tuple[str, ...] = DEFAULT_PAYLOAD_ALLOWLIST

    def matches(self, path: str) -> bool:
        if _is_machinery(path):
            return False
        return any(self._match(path, pattern) for pattern in self.patterns)

    @staticmethod
    def _match(path: str, pattern: str) -> bool:
        if pattern.endswith("/**"):
            prefix = pattern[:-2]
            return path.startswith(prefix)
        if "/" not in pattern:
            # A bare pattern applies at the skill root only. `*.md` must not silently
            # pull in `some-other-dir/notes.md`.
            return "/" not in path and fnmatch.fnmatch(path, pattern)
        return fnmatch.fnmatch(path, pattern)

    def split(self, paths: list[str]) -> PayloadSplit:
        included: list[str] = []
        machinery: list[str] = []
        unmatched: list[str] = []
        for path in sorted(paths):
            if _is_machinery(path):
                machinery.append(path)
            elif self.matches(path):
                included.append(path)
            else:
                unmatched.append(path)
        return PayloadSplit(
            included=tuple(included),
            excluded_machinery=tuple(machinery),
            excluded_unmatched=tuple(unmatched),
        )
