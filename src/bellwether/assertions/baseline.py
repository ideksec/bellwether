"""Applying the platform baseline: matching, subtraction, near-miss flagging (§12.6).

The baseline exists so that infrastructure noise does not bury the Declared vs Observed
section — and an allowlist in a security tool is a liability unless its edges are
sharp. Two of those edges are enforced here rather than documented:

- **A traversal sequence never resolves into a baseline match.** The path a skill
  *named* and the path it *reached* are both known; where they differ by ``..`` and the
  named path sits under a baseline entry, that is a near-miss finding at ``medium`` —
  ``~/.cache/../.aws/credentials`` is an attempt to make an interesting read look
  infrastructural, and absorbing it would be the allowlist working for the adversary.
- **A helper's name without a helper's parentage is a near-miss, not a pass.**
  ``git-remote-https`` under ``git`` is plumbing; the same argv0 with no permitted root
  in its ancestry matches the letter of an entry and none of its meaning.

Everything here is pure matching: the *absorbed* set feeds
``canonicalize(platform_baseline_t3=...)`` and the scope evaluation of WP-9; the
near-misses become findings there. Nothing is judged in this module beyond
"the baseline accounts for this, or it does not, or it suspiciously almost does".
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Literal

from bellwether.config.models.baseline import PlatformBaseline
from bellwether.sandbox import normalize_container_path

__all__ = [
    "BaselineApplication",
    "NearMiss",
    "ObservedPath",
    "ObservedProcess",
    "ProcessAttribution",
    "apply_path_baseline",
    "apply_tool_baseline",
    "attribute_process",
    "expand_braces",
    "glob_to_regex",
]


@dataclass(frozen=True)
class ObservedPath:
    """One observed filesystem access, in both the named and the reached form.

    ``raw`` is the path as the skill spelled it, placeholder-normalized but with any
    traversal preserved; ``resolved`` is the lexically collapsed form the capability
    tiers use. They differ exactly when the skill used ``..`` — and that difference is
    the near-miss signal, which is why both are required rather than one derived from
    the other after the fact.
    """

    raw: str
    resolved: str

    @property
    def used_traversal(self) -> bool:
        return ".." in self.raw.split("/")


@dataclass(frozen=True)
class NearMiss:
    """Activity that differs from a baseline entry only by a suspicious margin."""

    kind: Literal["traversal_past_entry", "helper_without_parent"]
    observed: str
    rule: str
    severity: Literal["medium"] = "medium"

    @property
    def detail(self) -> str:
        if self.kind == "traversal_past_entry":
            return (
                f"{self.observed!r} names a path under baseline entry {self.rule!r} but "
                "traverses out of it; traversal never resolves into a baseline match"
            )
        return (
            f"{self.observed!r} matches helper pattern {self.rule!r} but has no "
            "permitted root process in its ancestry"
        )


@dataclass(frozen=True)
class BaselineApplication:
    """What the baseline absorbed, and what it suspiciously almost absorbed."""

    #: Resolved paths the baseline accounts for — the ``platform_baseline_t3`` input to
    #: canonicalization, and the subtrahend of §12.6's ``observed − baseline``.
    absorbed: frozenset[str]
    #: Resolved path → the entry that matched, for the report's audit trail.
    matched_rules: dict[str, str] = field(default_factory=dict)
    near_misses: tuple[NearMiss, ...] = ()


def apply_tool_baseline(
    observed: Sequence[str],
    baseline: PlatformBaseline,
    *,
    sandbox_image: str,
) -> frozenset[str]:
    """The tier-1 ``tool:<name>`` capabilities the §12.6 baseline accounts for.

    The third of §12.6's three areas, and the last one a capture plane does not block.
    ``paths`` has absorbed since the baseline landed; ``processes`` waits on the §10.3
    process plane (v0.3), because tree attribution is what its ``helpers_of`` rules are
    written in terms of and there are no process trees to attribute against. ``tools``
    needs neither: a tool call is Plane A evidence, which every run already has.

    Matched by exact name, not by glob. A path baseline is written in globs because paths
    are hierarchical and unbounded; a tool name is a fixed identifier from the harness's own
    vocabulary, and a glob there would let ``*`` quietly absorb the whole tool surface —
    exactly the failure the allowlist exists to prevent.

    Ships empty, and that is the point: §12.6's own default says ``tools: []`` because a tool
    call is agent behaviour, not infrastructure, until a harness demonstrates otherwise. This
    gives a harness that *does* demonstrate it somewhere to say so, rather than leaving the
    field parsed and inert.

    Refuses — absorbing nothing — where the baseline is not keyed to this run's image, the
    same rule and for the same reason as the path half.
    """
    applicable, _ = baseline.applicable_to(sandbox_image)
    if not applicable or not baseline.tools:
        return frozenset()
    accounted = set(baseline.tools)
    return frozenset(cap for cap in observed if cap.partition(":")[2] in accounted)


def apply_path_baseline(
    observed: list[ObservedPath],
    baseline: PlatformBaseline,
    *,
    access: Literal["read", "write"],
    sandbox_image: str,
) -> BaselineApplication:
    """Match observed paths against the baseline's entries for one access kind.

    Refuses — by absorbing nothing and saying why through ``applicable_to`` — where the
    baseline is not keyed to this run's image. The caller surfaces the reason;
    "baseline not applied" must never read as "nothing infrastructural happened".
    """
    applicable, _ = baseline.applicable_to(sandbox_image)
    if not applicable:
        return BaselineApplication(absorbed=frozenset())

    entries = baseline.paths.read if access == "read" else baseline.paths.write
    patterns = [(entry, glob_to_regex(entry)) for entry in entries]

    absorbed: set[str] = set()
    matched: dict[str, str] = {}
    near_misses: list[NearMiss] = []

    for path in observed:
        if path.used_traversal:
            # Never absorbed, whatever it resolves to. If the path as *named* sits
            # under an entry, the traversal is escaping that entry: near-miss.
            for entry, pattern in patterns:
                if pattern.fullmatch(path.raw) or pattern.fullmatch(_collapse_within(path.raw)):
                    near_misses.append(
                        NearMiss(kind="traversal_past_entry", observed=path.raw, rule=entry)
                    )
                    break
            continue
        for entry, pattern in patterns:
            if pattern.fullmatch(path.resolved):
                absorbed.add(path.resolved)
                matched[path.resolved] = entry
                break

    return BaselineApplication(
        absorbed=frozenset(absorbed),
        matched_rules=matched,
        near_misses=tuple(near_misses),
    )


@dataclass(frozen=True)
class ObservedProcess:
    """One executed process: its argv0 and the argv0s above it, nearest first."""

    argv0: str
    ancestors: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProcessAttribution:
    """How one process relates to the baseline and the declared scope (§10.3)."""

    verdict: Literal["baseline_always", "declared", "helper", "near_miss", "unmatched"]
    rule: str | None = None
    near_miss: NearMiss | None = None

    @property
    def accounted_for(self) -> bool:
        return self.verdict in ("baseline_always", "declared", "helper")


def attribute_process(
    process: ObservedProcess,
    baseline: PlatformBaseline,
    *,
    declared: frozenset[str] = frozenset(),
) -> ProcessAttribution:
    """Attribute one process by tree (§12.6's ``helpers_of``, §10.3's rule).

    ``git`` legitimately spawns helpers; ``rg`` through a shell legitimately produces an
    ``sh`` in the tree. A ``curl`` under ``git`` matches nothing and stays unmatched —
    the violation decision belongs to the scope evaluation, not here. A process whose
    argv0 matches a helper pattern but whose ancestry contains no permitted root gets
    the near-miss, because it wears a helper's name without a helper's parentage.
    """
    always = baseline.processes.always
    if process.argv0 in always:
        return ProcessAttribution(verdict="baseline_always", rule=process.argv0)
    if process.argv0 in declared:
        return ProcessAttribution(verdict="declared", rule=process.argv0)

    permitted_roots = declared | set(always)
    for root, helper_patterns in sorted(baseline.processes.helpers_of.items()):
        if root not in permitted_roots:
            # The mapping is inert for a root the run has no standing to spawn: an
            # undeclared standalone `git` is a plain scope violation, not a near-miss,
            # and its helpers gain nothing from a mapping their root cannot use.
            continue
        for helper in helper_patterns:
            if not fnmatch.fnmatchcase(process.argv0, helper):
                continue
            if root in process.ancestors:
                return ProcessAttribution(verdict="helper", rule=f"{root}: {helper}")
            return ProcessAttribution(
                verdict="near_miss",
                rule=f"{root}: {helper}",
                near_miss=NearMiss(
                    kind="helper_without_parent", observed=process.argv0, rule=helper
                ),
            )

    return ProcessAttribution(verdict="unmatched")


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile one baseline glob: ``**`` crosses directories, ``*`` and ``?`` stay
    within a segment, ``{a,b}`` alternates, everything else — placeholders included —
    is literal."""
    alternatives = _expand_braces(pattern)
    return re.compile("|".join(f"(?:{_translate(alt)})" for alt in alternatives))


#: The most alternatives one entry may stand for. Expansion is 2ⁿ in the number of groups, and
#: the manifest is part of the package *under review* — a 121-character entry with 22 groups
#: expands to 4.2 million alternatives in 13 seconds, and 26 groups exhausts memory. Past the cap
#: the entry is matched literally: it stops being a convenience, never a crash.
_MAX_BRACE_ALTERNATIVES = 1024


@lru_cache(maxsize=4096)
def expand_braces(pattern: str) -> tuple[str, ...]:
    """The public name for brace expansion, for callers matching declarations themselves.

    Cached and capped. The §13.5.4 declaration rule re-expands the same entry for every
    (hit, entry) pair of every run, so an uncached expansion multiplies a cost the manifest
    author controls.

    The §13.5.4 declaration rule anchors a literal prefix rather than compiling a regex, so it
    needs the alternatives a braced entry stands for. Without this, one manifest line is
    simultaneously a supported declaration in the Declared-vs-Observed table (which compiles
    through :func:`glob_to_regex`, and so expands braces) and an *undeclared* sensitive access
    to the gate — a false positive on a declaration the author correctly believes they wrote.
    """
    # Counted before recursing, not while: checking the accumulated length only trims the
    # *result*, and the recursion has already walked 2ⁿ branches to build it. The groups are
    # cheap to count and bound the size exactly.
    groups = sum(
        1
        for index, char in enumerate(pattern)
        if char == "{" and (index == 0 or pattern[index - 1] != "$")
    )
    if groups and 2**groups > _MAX_BRACE_ALTERNATIVES:
        return (pattern,)
    return tuple(_expand_braces(pattern))


def _expand_braces(pattern: str, *, limit: int | None = None) -> list[str]:
    """``/etc/{passwd,group}`` → ``["/etc/passwd", "/etc/group"]``, recursively.

    A ``{`` preceded by ``$`` is a placeholder, not alternation: expanding
    ``${HOME}`` into a one-choice brace group would quietly rewrite it to ``$HOME``,
    every placeholder entry would match nothing, and the baseline would fail silently
    in the direction that looks clean — the failure mode this whole project distrusts.
    """
    start = -1
    for index, char in enumerate(pattern):
        if char == "{" and (index == 0 or pattern[index - 1] != "$"):
            start = index
            break
    if start < 0:
        return [pattern]
    depth = 0
    for index in range(start, len(pattern)):
        if pattern[index] == "{":
            depth += 1
        elif pattern[index] == "}":
            depth -= 1
            if depth == 0:
                head, body, tail = pattern[:start], pattern[start + 1 : index], pattern[index + 1 :]
                expanded: list[str] = []
                for choice in _split_alternatives(body):
                    expanded.extend(_expand_braces(head + choice + tail, limit=limit))
                    if limit is not None and len(expanded) > limit:
                        # Past the cap the pattern is its own single alternative: a manifest
                        # cannot spend the evaluation's time on expansion it controls.
                        return [pattern]
                return expanded
    return [pattern]  # unbalanced brace: treat literally rather than guessing


def _split_alternatives(body: str) -> list[str]:
    """Split on commas at depth zero, so nested braces survive."""
    parts: list[str] = []
    depth = 0
    current = ""
    for char in body:
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        current += char
    parts.append(current)
    return parts


def _translate(pattern: str) -> str:
    """One brace-free glob to a regex. ``**`` first, so it is not eaten as ``*``."""
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if pattern[index : index + 2] == "**":
                out.append(".*")
                index += 2
                # A `/**` that matched nothing should also match the bare directory
                # boundary: `/a/**` covers `/a/b` via `.*` after the slash.
                continue
            out.append("[^/]*")
            index += 1
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        out.append(re.escape(char))
        index += 1
    return "".join(out)


def _collapse_within(raw: str) -> str:
    """The raw path with traversal collapsed, placeholders preserved.

    Used only for near-miss detection: "would the *named prefix* have matched?" is
    asked against both the raw spelling and its collapse, because
    ``${HOME}/.cache/../.aws/x`` should be recognised as escaping ``.cache`` whether or
    not the entry's ``**`` happens to match a literal ``..`` segment.
    """
    prefix = ""
    remainder = raw
    if raw.startswith("${"):
        end = raw.find("}")
        if end > 0:
            prefix, remainder = raw[: end + 1], raw[end + 1 :]
    return prefix + str(normalize_container_path(remainder))
