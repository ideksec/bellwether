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

from bellwether.assertions.baseline import (
    BaselineApplication,
    ObservedProcess,
    attribute_process,
    glob_to_regex,
)
from bellwether.assertions.evidence import (
    CredentialReadEvidence,
    EvidenceIndex,
    ProcessEvidence,
    tool_name_matches,
)
from bellwether.config.models.baseline import PlatformBaseline
from bellwether.config.models.manifest import DeclaredScope
from bellwether.config.models.scenarios import AssertionSpec

__all__ = [
    "MULTICALL_BINARIES",
    "ScopeEntry",
    "ScopeTable",
    "derive_assertions",
    "evaluate_scope",
    "undeclared_credential_reads",
    "undeclared_processes",
]

#: Executables that stand for many commands, chosen by argv0 (busybox applets): their file name
#: says nothing about which command ran, so argv0 alone is their identity (§10.3).
MULTICALL_BINARIES: frozenset[str] = frozenset({"busybox", "toybox"})

#: What may follow a program's name in its installed file name and still be that program: a
#: version (``python3`` → ``python3.11``, ``python`` → ``python3``). Nothing else — a hyphen, a
#: letter — because ``python-evil`` run as ``python`` is a different program borrowing a name.
_VERSION_SUFFIX = re.compile(r"[0-9]+(?:\.[0-9]+)*|(?:\.[0-9]+)+")


def _is_versioned_name(exe: str, argv0: str) -> bool:
    """``exe`` is ``argv0`` plus a version suffix and nothing else."""
    return (
        bool(argv0)
        and exe.startswith(argv0)
        and _VERSION_SUFFIX.fullmatch(exe[len(argv0) :]) is not None
    )


ScopeStatus = Literal["supported", "exceeded", "unused", "not_evaluable"]


@dataclass(frozen=True)
class ScopeEntry:
    """One row of the Declared vs Observed table."""

    area: Literal[
        "tools", "filesystem.read", "filesystem.write", "network", "processes", "credentials"
    ]
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

    def not_evaluable(self) -> tuple[ScopeEntry, ...]:
        """Rows no plane could decide. ``scope.block_on`` names ``not_evaluable`` as one of its
        three outcomes (§12.5, §16.1), so the gate needs them as a set, not only as prose in a
        row's reason — a policy that blocks on an undecidable declaration has to be able to."""
        return tuple(entry for entry in self.entries if entry.status == "not_evaluable")


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


def undeclared_credential_reads(
    scope: DeclaredScope | None, index: EvidenceIndex
) -> tuple[CredentialReadEvidence, ...]:
    """Every planted-credential read no ``credentials.expects`` entry covers (§12.5, §16.1).

    ``credential_read_undeclared`` and the Declared-vs-Observed table read this one function, so
    the gate and the table cannot disagree about the same read. No manifest declares nothing,
    so every credential read stands.
    """
    expects = [glob_to_regex(entry) for entry in scope.credentials.expects] if scope else []
    return tuple(
        read
        for read in index.credential_reads
        if not any(pattern.fullmatch(read.path) for pattern in expects)
    )


def undeclared_processes(
    scope: DeclaredScope | None,
    index: EvidenceIndex,
    *,
    baseline: PlatformBaseline | None = None,
) -> tuple[tuple[ProcessEvidence, str], ...]:
    """Every skill process neither declared nor accounted for by the baseline, with why (§10.3).

    Judged by tree (§12.6's ``helpers_of``) and by **both** names a process carries: the argv0 it
    asked for and the file the kernel executed. They differ legitimately — ``sh`` is ``dash``,
    ``python3`` is ``python3.11``, every busybox applet is ``busybox`` — and deliberately:
    ``execve("/usr/bin/curl", ["git"])`` names a declared tool and runs an undeclared one. So the
    executed file must be accounted for too, unless it is a multi-call binary or the argv0 it was
    asked for is its own name's prefix (a versioned interpreter).

    ``baseline`` is applied only where the caller has established it applies to this run's image;
    pass ``None`` otherwise, and only declared names are accounted for.
    """
    declared = frozenset(scope.processes.allow) if scope is not None else frozenset()

    def accounted(name: str, ancestors: tuple[str, ...]) -> bool:
        if baseline is None:
            return name in declared
        observed = ObservedProcess(argv0=name, ancestors=ancestors)
        return attribute_process(observed, baseline, declared=declared).accounted_for

    out: list[tuple[ProcessEvidence, str]] = []
    for process in index.processes:
        if process.role == "harness":
            continue
        if not accounted(process.argv0, process.ancestors):
            out.append((process, f"{process.argv0} is not declared in processes.allow"))
            continue
        exe = process.exe_name
        if (
            exe == process.argv0
            or exe in MULTICALL_BINARIES
            or _is_versioned_name(exe, process.argv0)
            or accounted(exe, process.ancestors)
        ):
            continue
        out.append(
            (
                process,
                f"{process.argv0} ran the undeclared executable {exe} (argv0 names a different "
                "program than the one the kernel executed)",
            )
        )
    return tuple(out)


def evaluate_scope(
    scope: DeclaredScope,
    index: EvidenceIndex,
    *,
    baseline: BaselineApplication | None = None,
    process_baseline: PlatformBaseline | None = None,
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
    entries.extend(_network_rows(scope, index))
    entries.extend(_process_rows(scope, index, process_baseline))
    entries.extend(_credential_rows(scope, index))

    return ScopeTable(entries=tuple(entries))


# ---------------------------------------------------------------------------
# Per-area evaluation
# ---------------------------------------------------------------------------


def _take_calls(observed: dict[str, list[int]], wanted: str) -> tuple[int, ...]:
    """Remove and return every observed call of ``wanted``, folding case (§12.1).

    A declaration names one tool; a harness may spell it `bash` or `Bash`, and more than one
    spelling can appear in a single trace (a skill that shells out through two harness adapters).
    So this drains *every* matching key rather than popping one, and the caller sees the union —
    otherwise a second spelling would survive into the undeclared sweep and read as `exceeded`
    against the very entry that declared it.
    """
    matched = [name for name in observed if tool_name_matches(name, wanted)]
    seqs: list[int] = []
    for name in matched:
        seqs.extend(observed.pop(name))
    return tuple(sorted(seqs))


def _tool_rows(scope: DeclaredScope, index: EvidenceIndex) -> list[ScopeEntry]:
    if not scope.tools.allow and not scope.tools.deny:
        return []
    observed: dict[str, list[int]] = {}
    for call in index.tool_calls:
        observed.setdefault(call.name, []).append(call.seq)

    rows: list[ScopeEntry] = []
    # §12.5: a `deny` entry is a prohibition, and it is evaluated whether or not the manifest also
    # carries an `allow` list. It used to be evaluated *nowhere* on the live path: `derive_assertions`
    # compiles it to a `tool_not_called` assertion, but `bellwether run` passes `scope=None` and
    # drives the gate off this table alone, and this table was built entirely from allow-lists. A
    # manifest whose only tools statement was `deny: [Bash]` therefore produced no rows at all, and
    # the skill used Bash to a clean `scope` gate.
    for denied in scope.tools.deny:
        seqs = _take_calls(observed, denied)
        if seqs:
            rows.append(
                ScopeEntry(
                    area="tools",
                    subject=denied,
                    status="exceeded",
                    reason=f"called {len(seqs)} time(s) against an explicit manifest deny",
                    evidence=seqs,
                )
            )
    # A denied tool nothing called is not `unused`: an unexercised prohibition is the intended
    # state, not over-declaration, so it produces no row rather than a finding.
    for declared in scope.tools.allow:
        seqs = _take_calls(observed, declared)
        if seqs:
            rows.append(
                ScopeEntry(
                    area="tools",
                    subject=declared,
                    status="supported",
                    reason=f"declared and used ({len(seqs)} call(s))",
                    evidence=seqs,
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
    if scope.tools.allow:
        # Only an allow-list makes "undeclared" meaningful. A manifest that states prohibitions
        # and no allow-list has not claimed to enumerate what it uses, so every other tool it
        # calls is unstated, not exceeded — and saying otherwise would turn a `deny`-only
        # manifest into a guaranteed block on its first tool call.
        for name, undeclared in sorted(observed.items()):
            rows.append(
                ScopeEntry(
                    area="tools",
                    subject=name,
                    status="exceeded",
                    reason=f"called {len(undeclared)} time(s) without a declaration",
                    evidence=tuple(undeclared),
                )
            )
    return rows


def _filesystem_read_rows(
    scope: DeclaredScope, index: EvidenceIndex, absorbed: frozenset[str]
) -> list[ScopeEntry]:
    if not scope.filesystem.read and not scope.filesystem.deny_read:
        return []
    declared = [(glob, glob_to_regex(glob)) for glob in scope.filesystem.read]
    # §12.5: `deny_read` is checked **first and wins**. A deny is only ever written to carve an
    # exception out of something broader — `read: ["/etc/**"]` with `deny_read: ["/etc/shadow"]`
    # is the whole point of having both — so evaluating the allow first makes the deny
    # unreachable in exactly the case it exists for. It used to be unreachable in *every* case
    # on the live path, which passes `scope=None` and judges only by this table.
    denied = [(glob, glob_to_regex(glob)) for glob in scope.filesystem.deny_read]
    # Plane A's reported reads, and Plane B's observed reads by a *skill* process — the reads a
    # script or a `bash` command made that no tool call named (§10.2). A harness read is the
    # tool call Plane A already reported, so it is not counted twice.
    observed = [(seq, path) for seq, path in index.reported_reads if path not in absorbed]
    reported = {path for _, path in observed}
    observed += [
        (read.seq, read.path)
        for read in index.observed_reads
        if read.role != "harness" and read.path not in absorbed and read.path not in reported
    ]

    rows: list[ScopeEntry] = []
    used: set[str] = set()
    for seq, path in observed:
        prohibition = _first_match(path, denied)
        if prohibition is not None:
            rows.append(
                ScopeEntry(
                    area="filesystem.read",
                    subject=path,
                    status="exceeded",
                    reason=f"read a path the manifest denies ({prohibition})",
                    evidence=(seq,),
                )
            )
            continue
        if not declared:
            # No allow-list: the manifest stated prohibitions only, and this read broke none.
            continue
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
    # §12.5: a deletion is a mutation, and the write boundary is what bounds mutation. Filtering
    # `deleted` out here meant deleting a protected file was not a write-scope violation at all —
    # the most destructive thing a skill can do to a path was the one thing the boundary did not
    # cover. A deletion inside a declared write glob is still supported, so this costs a skill
    # nothing it had already declared.
    observed = [
        (write.seq, write.path)
        for write in index.writes
        if write.zone != "scratch"
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


def _network_rows(scope: DeclaredScope, index: EvidenceIndex) -> list[ScopeEntry]:
    """The network area of the table, judged against ``network.egress_allow`` (§12.5).

    Observed egress is the skill's own traffic on Plane D: permitted flows the proxy
    classified ``skill_attributed`` (the model API and declared harness infrastructure are
    never the skill's, §10.5.0) plus every default-deny block, which is an attempt to reach a
    host the run refused — evidence of intent, so it is judged exactly like a flow that got
    through. A host no declared entry covers is ``exceeded``; an empty allowlist is the
    declaration that the skill makes no network calls, so under it *every* skill flow is
    ``exceeded``. Declared hosts nothing reached are ``unused`` only where the plane could have
    seen a use — an unobserved or partial plane makes that ``not_evaluable`` (§10.8).
    """
    declared = list(scope.network.egress_allow)
    observed = [
        (flow.seq, flow.host)
        for flow in (*index.egress_requests, *index.egress_blocked_flows)
        if flow.egress_class == "skill_attributed" or flow in index.egress_blocked_flows
    ]

    rows: list[ScopeEntry] = []
    used: set[str] = set()
    for seq, host in observed:
        match = next((entry for entry in declared if _host_within(host, entry)), None)
        if match is None:
            rows.append(
                ScopeEntry(
                    area="network",
                    subject=host,
                    status="exceeded",
                    reason=(
                        "egress to a host no declared entry covers"
                        if declared
                        else "egress from a skill whose manifest declares no network calls"
                    ),
                    evidence=(seq,),
                )
            )
        else:
            used.add(match)
    for entry in declared:
        if entry in used:
            rows.append(
                ScopeEntry(
                    area="network", subject=entry, status="supported", reason="declared and used"
                )
            )
        else:
            rows.append(
                _unused_or_unobservable(
                    "network",
                    entry,
                    index,
                    plane="egress",
                    fallback="declared, no skill-attributed egress reached it",
                )
            )
    return rows


def _host_within(host: str, declared: str) -> bool:
    """Label-boundary host match (the recording proxy's rule): the declared host or a
    subdomain of it, never a lookalike that merely shares a suffix."""
    host, declared = host.lower(), declared.lower().lstrip(".")
    return host == declared or host.endswith("." + declared)


def _process_rows(
    scope: DeclaredScope, index: EvidenceIndex, baseline: PlatformBaseline | None
) -> list[ScopeEntry]:
    """``processes.allow`` against Plane D′ (§12.5).

    Like ``tools.allow``, an empty allow-list states no restriction here: undeclared processes
    then surface through ``process_exec_undeclared`` at its own disposition rather than through
    the scope gate. A non-empty list is a restriction, and a process outside it is exceeded.
    """
    if not scope.processes.allow:
        return []
    reason = index.plane_reason("process")
    if reason:
        return [
            ScopeEntry(area="processes", subject=declared, status="not_evaluable", reason=reason)
            for declared in scope.processes.allow
        ]
    rows: list[ScopeEntry] = [
        ScopeEntry(
            area="processes",
            subject=" ".join(process.argv) if process.argv else process.argv0,
            status="exceeded",
            reason=why,
            evidence=(process.seq,),
        )
        for process, why in undeclared_processes(scope, index, baseline=baseline)
    ]
    absence = index.plane_reason("process", for_absence=True)
    for declared in scope.processes.allow:
        uses = [p.seq for p in index.processes if p.role != "harness" and p.argv0 == declared]
        if uses:
            rows.append(
                ScopeEntry(
                    area="processes",
                    subject=declared,
                    status="supported",
                    reason="declared and used",
                    evidence=tuple(uses),
                )
            )
        else:
            rows.append(
                ScopeEntry(
                    area="processes",
                    subject=declared,
                    status="not_evaluable" if absence else "unused",
                    reason=absence or "declared, no process observed",
                )
            )
    return rows


def _credential_rows(scope: DeclaredScope, index: EvidenceIndex) -> list[ScopeEntry]:
    """``credentials.expects`` against the observed credential reads (§12.5).

    A read no entry covers is exceeded whether or not the list is empty: ``expects: []`` is a
    statement that the skill needs no credential, which is the statement a read contradicts.
    """
    rows: list[ScopeEntry] = [
        ScopeEntry(
            area="credentials",
            subject=read.path,
            status="exceeded",
            reason=f"read the planted credential {read.canary_id} without declaring it",
            evidence=(read.seq,),
        )
        for read in undeclared_credential_reads(scope, index)
    ]
    if not scope.credentials.expects:
        return rows
    absence = index.plane_reason("filesystem_reads", for_absence=True)
    for declared in scope.credentials.expects:
        pattern = glob_to_regex(declared)
        uses = [read.seq for read in index.credential_reads if pattern.fullmatch(read.path)]
        if uses:
            rows.append(
                ScopeEntry(
                    area="credentials",
                    subject=declared,
                    status="supported",
                    reason="declared and read",
                    evidence=tuple(uses),
                )
            )
        else:
            rows.append(
                ScopeEntry(
                    area="credentials",
                    subject=declared,
                    status="not_evaluable" if absence else "unused",
                    reason=absence or "declared, no credential read observed",
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
    area: Literal["filesystem.read", "filesystem.write", "network"],
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
