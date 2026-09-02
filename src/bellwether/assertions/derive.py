"""Auto-derived assertions and the Declared vs Observed table (§12.5).

Every ``declared_scope`` entry compiles to checks applied to every scenario. Two kinds
fall out of the manifest:

- entries expressible in the §12.2 catalogue (``tools.deny`` → ``tool_not_called``,
  ``filesystem.deny_read`` → ``file_not_read``, ``filesystem.write`` →
  ``no_write_outside``, ``network.egress_allow`` → ``egress_only_to`` or ``no_egress``)
  become ordinary :class:`AssertionSpec`s and run through the engine;
- allowlist entries (``tools.allow``, ``filesystem.read``, ``processes.allow``,
  ``credentials.expects``) are evaluated here, against the observation — **not**
  derived from it. Revision 1 phrased ``tools.allow`` as "``tool_not_called`` for every
  tool observed but not in list", which is circular: the assertion cannot be derived
  from the observation it is meant to test. The corrected form asks one question of
  each observation — "is this within some declared entry?" — and one question of each
  declaration — "did anything use it?".

The product is the **Declared vs Observed** table: ``supported`` / ``exceeded`` /
``unused`` / ``not_evaluable`` per declared capability, at tier 3, evaluated after
baseline subtraction. ``unused`` matters too: a skill declaring Bash that never uses it
is over-declared, and over-declaration is how ``allowed-tools`` becomes a
privilege-escalation vector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from bellwether.assertions.baseline import BaselineApplication, glob_to_regex
from bellwether.assertions.evidence import EvidenceIndex
from bellwether.config.models.manifest import DeclaredScope
from bellwether.config.models.scenarios import AssertionSpec

__all__ = ["ScopeEntry", "ScopeTable", "derive_assertions", "evaluate_scope"]

ScopeStatus = Literal["supported", "exceeded", "unused", "not_evaluable"]


@dataclass(frozen=True)
class ScopeEntry:
    """One row of the Declared vs Observed table."""

    area: Literal["tools", "filesystem.read", "filesystem.write", "processes", "credentials"]
    #: The declared entry (a tool name, a glob) — or, for an ``exceeded`` row, the
    #: observed tier-3 target that no declaration covers.
    subject: str
    status: ScopeStatus
    reason: str
    evidence: tuple[int, ...] = ()


@dataclass(frozen=True)
class ScopeTable:
    entries: tuple[ScopeEntry, ...]

    def exceeded(self) -> tuple[ScopeEntry, ...]:
        return tuple(entry for entry in self.entries if entry.status == "exceeded")

    def unused(self) -> tuple[ScopeEntry, ...]:
        return tuple(entry for entry in self.entries if entry.status == "unused")


def derive_assertions(scope: DeclaredScope) -> list[AssertionSpec]:
    """The catalogue-expressible half of §12.5, applied to every scenario."""
    specs: list[AssertionSpec] = []
    for tool in scope.tools.deny:
        specs.append(AssertionSpec.model_validate({"tool_not_called": tool}))
    for glob in scope.filesystem.deny_read:
        specs.append(AssertionSpec.model_validate({"file_not_read": glob}))
    if scope.filesystem.write:
        specs.append(AssertionSpec.model_validate({"no_write_outside": scope.filesystem.write}))
    if scope.network.egress_allow:
        specs.append(AssertionSpec.model_validate({"egress_only_to": scope.network.egress_allow}))
    else:
        # An empty allowlist is a declaration that the skill makes no network calls —
        # a statement, not an absence of one (§12.5).
        specs.append(AssertionSpec.model_validate({"no_egress": True}))
    return specs


def evaluate_scope(
    scope: DeclaredScope,
    index: EvidenceIndex,
    *,
    baseline: BaselineApplication | None = None,
) -> ScopeTable:
    """Evaluate the allowlist half of §12.5 and assemble the table.

    Baseline subtraction happens here for the filesystem rows: an observation the
    platform baseline absorbed is infrastructure, and judging it against the skill's
    declaration would resurrect exactly the noise §12.6 exists to remove.
    """
    absorbed = baseline.absorbed if baseline is not None else frozenset()
    entries: list[ScopeEntry] = []

    entries.extend(_tool_rows(scope, index))
    entries.extend(_filesystem_read_rows(scope, index, absorbed))
    entries.extend(_filesystem_write_rows(scope, index, absorbed))
    entries.extend(_process_rows(scope, index))
    entries.extend(_credential_rows(scope, index))

    return ScopeTable(entries=tuple(entries))


# ---------------------------------------------------------------------------
# Per-area evaluation
# ---------------------------------------------------------------------------


def _tool_rows(scope: DeclaredScope, index: EvidenceIndex) -> list[ScopeEntry]:
    if not scope.tools.allow:
        return []
    observed: dict[str, list[int]] = {}
    for call in index.tool_calls:
        observed.setdefault(call.name, []).append(call.seq)

    rows: list[ScopeEntry] = []
    for declared in scope.tools.allow:
        seqs = observed.pop(declared, [])
        if seqs:
            rows.append(
                ScopeEntry(
                    area="tools",
                    subject=declared,
                    status="supported",
                    reason=f"declared and used ({len(seqs)} call(s))",
                    evidence=tuple(seqs),
                )
            )
        else:
            rows.append(
                ScopeEntry(
                    area="tools",
                    subject=declared,
                    status="unused",
                    reason="declared, never called; over-declaration widens the "
                    "privilege a reviewer must reason about",
                )
            )
    for name, seqs in sorted(observed.items()):
        rows.append(
            ScopeEntry(
                area="tools",
                subject=name,
                status="exceeded",
                reason=f"called {len(seqs)} time(s) without a declaration",
                evidence=tuple(seqs),
            )
        )
    return rows


def _filesystem_read_rows(
    scope: DeclaredScope, index: EvidenceIndex, absorbed: frozenset[str]
) -> list[ScopeEntry]:
    if not scope.filesystem.read:
        return []
    declared = [(glob, glob_to_regex(glob)) for glob in scope.filesystem.read]
    observed = [(seq, path) for seq, path in index.reported_reads if path not in absorbed]

    rows: list[ScopeEntry] = []
    used: set[str] = set()
    for seq, path in observed:
        rule = _first_match(path, declared)
        if rule is None:
            rows.append(
                ScopeEntry(
                    area="filesystem.read",
                    subject=path,
                    status="exceeded",
                    reason="read outside every declared glob (after baseline subtraction)",
                    evidence=(seq,),
                )
            )
        else:
            used.add(rule)
    for glob, _ in declared:
        if glob in used:
            rows.append(
                ScopeEntry(
                    area="filesystem.read",
                    subject=glob,
                    status="supported",
                    reason="declared and used",
                )
            )
        else:
            rows.append(
                _unused_or_unobservable(
                    "filesystem.read",
                    glob,
                    index,
                    plane="filesystem_reads",
                    fallback="declared, no reported read matched",
                )
            )
    return rows


def _filesystem_write_rows(
    scope: DeclaredScope, index: EvidenceIndex, absorbed: frozenset[str]
) -> list[ScopeEntry]:
    if not scope.filesystem.write:
        return []
    declared = [(glob, glob_to_regex(glob)) for glob in scope.filesystem.write]
    observed = [
        (write.seq, write.path)
        for write in index.writes
        if not write.deleted
        and write.zone != "scratch"
        # §10.2: the harness-state zone is the harness's own area — a real harness (the
        # claude-code CLI) churns its session transcript, config, and backups there on every
        # run. Those are not the skill's declared *workspace* scope; they are recorded and
        # surfaced by the dedicated ``harness_state_write`` finding (see sandbox/zones.py), so
        # judging them against the skill's filesystem.write globs would flag the harness's own
        # machinery as a scope violation. Excluded here exactly as scratch is.
        and write.zone != "harness_state"
        and write.path not in absorbed
    ]

    rows: list[ScopeEntry] = []
    used: set[str] = set()
    for seq, path in observed:
        rule = _first_match(path, declared)
        if rule is None:
            rows.append(
                ScopeEntry(
                    area="filesystem.write",
                    subject=path,
                    status="exceeded",
                    reason="write outside every declared glob (after baseline subtraction)",
                    evidence=(seq,),
                )
            )
        else:
            used.add(rule)
    for glob, _ in declared:
        if glob in used:
            rows.append(
                ScopeEntry(
                    area="filesystem.write",
                    subject=glob,
                    status="supported",
                    reason="declared and used",
                )
            )
        else:
            rows.append(
                _unused_or_unobservable(
                    "filesystem.write",
                    glob,
                    index,
                    plane="filesystem_writes",
                    fallback="declared, no write matched",
                )
            )
    return rows


def _process_rows(scope: DeclaredScope, index: EvidenceIndex) -> list[ScopeEntry]:
    if not scope.processes.allow:
        return []
    reason = index.plane_reason("process")
    rows: list[ScopeEntry] = []
    for declared in scope.processes.allow:
        rows.append(
            ScopeEntry(
                area="processes",
                subject=declared,
                status="not_evaluable" if reason else "unused",
                reason=reason or "declared, no process observed",
            )
        )
    return rows


def _credential_rows(scope: DeclaredScope, index: EvidenceIndex) -> list[ScopeEntry]:
    if not scope.credentials.expects:
        return []
    reason = index.plane_reason("credentials")
    rows: list[ScopeEntry] = []
    for declared in scope.credentials.expects:
        rows.append(
            ScopeEntry(
                area="credentials",
                subject=declared,
                status="not_evaluable" if reason else "unused",
                reason=reason or "declared, no canary read observed",
            )
        )
    return rows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_match(path: str, declared: list[tuple[str, re.Pattern[str]]]) -> str | None:
    for glob, pattern in declared:
        if pattern.fullmatch(path):
            return glob
    return None


def _unused_or_unobservable(
    area: Literal["filesystem.read", "filesystem.write"],
    glob: str,
    index: EvidenceIndex,
    *,
    plane: str,
    fallback: str,
) -> ScopeEntry:
    """``unused`` is a claim about absence, and absence needs a plane that could have
    seen the use. A declared read glob under overlay-only capture is ``not_evaluable``,
    not ``unused`` — the skill may be reading it through a subprocess every run. A
    ``partial`` plane fails the same test (§10.8): it watched only part of its domain, so
    "declared, never used" could be blind to a use in the part it missed."""
    reason = index.plane_reason(plane, for_absence=True)
    if reason is not None:
        return ScopeEntry(area=area, subject=glob, status="not_evaluable", reason=reason)
    return ScopeEntry(area=area, subject=glob, status="unused", reason=fallback)
