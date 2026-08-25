"""Plane precedence: when planes disagree (§10.8 — WP-18).

The blanket rule — "host-side planes win, any disagreement is a ``trace_inconsistency``" —
is wrong in two ways the spec calls out: planes are not comparable across their full
domains (Plane A is the *only* source for activation, tool names, and model turns), and
absence is only meaningful at sufficient fidelity (at overlay-diff, Plane B legitimately
misses transient files). Implemented literally it would fire on nearly every run while the
``high`` profile blocks on it. So this module encodes the §10.8 matrix: a finding is raised
only where both planes are in-domain **and** the plane whose *silence* is being read is at a
fidelity where absence is meaningful. The general rule throughout: a lower-fidelity plane
may confirm but never refute a higher-fidelity one — failing to corroborate is not a
finding.

What each §10.8 row does in this version:

* **File write (persisted)** — Plane B is authoritative, A corroborates: a workspace-zone
  file B shows persisted with no Plane A tool call claiming it is an inconsistency. B's
  *positive* observation is trustworthy even at overlay-diff (the file is really on disk);
  the absence being read is A's, and Plane A must support an absence claim. Deletes are
  excluded: the shipped harness has no delete tool, so there is no A-side claim channel and
  a raised finding could only ever be a false positive. Non-workspace zones are excluded
  for the same reason — harness-state and tmp writes are the harness's own machinery.
* **Egress request** — Plane D is authoritative, A corroborates: a *skill-attributed* flow
  (§10.5.0) whose host no Plane A tool call mentions is an inconsistency. ``model_api``
  and ``harness_infrastructure`` flows have no A-side claim by construction and are never
  compared. A *blocked* flow is deliberately not re-raised here: it is already first-class
  evidence with its own scored gate, and a second finding on the same event is noise.
* **Never raised, by design** — skill activation and DNS queries (single-source rows);
  transient writes and file reads (need ``filesystem_reads`` capture, not built);
  process execs (need the eBPF/ptrace plane, not built); A-stdout vs A-hooks disagreement
  (the ``api-loop`` harness has one Plane A source; the hook stream arrives with the
  ``claude-code`` adapter). Each becomes implementable when its plane does; none may be
  approximated from a plane that cannot support it.

The claim test is deliberately generous to the skill: a Plane B path or Plane D host is
"claimed" if it appears anywhere in *any* tool call's arguments — a ``write`` path, a
``bash`` command line, a ``fetch`` URL. A generous match can only suppress a finding,
never fabricate one, which is the correct failure direction for a check the ``high``
profile blocks on.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from bellwether.assertions.evidence import EvidenceIndex

__all__ = ["TraceInconsistency", "trace_inconsistencies"]


@dataclass(frozen=True)
class TraceInconsistency:
    """One §10.8 disagreement: an authoritative plane observed what A never claimed."""

    #: The §10.8 signal row: ``file_write_persisted`` or ``egress_request``.
    signal: str
    #: The normalized path or host the planes disagree about.
    subject: str
    #: The action ``seq`` of the authoritative plane's observation.
    seq: int
    #: A full sentence naming both planes and what disagreed (§10.7: a bare enum gives
    #: the reader nothing to act on).
    reason: str


def trace_inconsistencies(index: EvidenceIndex) -> tuple[TraceInconsistency, ...]:
    """Evaluate the §10.8 precedence matrix over one run's evidence.

    Returns the disagreements sorted by ``(signal, subject, seq)`` — deterministic under
    §24 whatever order the planes were indexed in. An empty result on a benign run at
    overlay-diff fidelity is WP-18's done-when: the check must not manufacture findings
    out of fidelity gaps.
    """
    findings: list[TraceInconsistency] = []
    findings.extend(_unclaimed_persisted_writes(index))
    findings.extend(_unclaimed_skill_egress(index))
    return tuple(sorted(findings, key=lambda f: (f.signal, f.subject, f.seq)))


def _a_supports_absence(index: EvidenceIndex) -> bool:
    """Whether Plane A's silence is meaningful (§10.8).

    Both implemented rows read an *absence* on Plane A ("A never claimed it"), so Plane A
    must be at a fidelity that supports absence claims. The authoritative plane's own
    observation is positive evidence and needs only presence-usability — which its
    producing an action already demonstrates.
    """
    return index.plane_reason("harness_events", for_absence=True) is None


def _claimed(index: EvidenceIndex, *needles: str) -> bool:
    """Whether any Plane A tool call mentions any of ``needles`` in its arguments."""
    candidates = [needle for needle in needles if needle]
    return any(needle in call.args_json for call in index.tool_calls for needle in candidates)


def _unclaimed_persisted_writes(index: EvidenceIndex) -> list[TraceInconsistency]:
    """§10.8 row: file write (persisted) — B shows a write A never claimed."""
    if index.plane_reason("filesystem_writes") is not None or not _a_supports_absence(index):
        return []
    findings: list[TraceInconsistency] = []
    for write in index.writes:
        if write.zone != "workspace" or write.deleted:
            continue
        relative = _workspace_relative(write.path)
        if _claimed(index, write.path, relative):
            continue
        findings.append(
            TraceInconsistency(
                signal="file_write_persisted",
                subject=write.path,
                seq=write.seq,
                reason=(
                    f"Plane B shows a persisted workspace write at {write.path} that no "
                    "Plane A tool call claimed (§10.8: for persisted writes B is "
                    "authoritative and A corroborates)"
                ),
            )
        )
    return findings


def _unclaimed_skill_egress(index: EvidenceIndex) -> list[TraceInconsistency]:
    """§10.8 row: egress request — D shows a skill-attributed request A never claimed."""
    if index.plane_reason("egress") is not None or not _a_supports_absence(index):
        return []
    findings: list[TraceInconsistency] = []
    for flow in index.egress_requests:
        if flow.egress_class != "skill_attributed":
            continue
        if _claimed(index, flow.host):
            continue
        findings.append(
            TraceInconsistency(
                signal="egress_request",
                subject=flow.host,
                seq=flow.seq,
                reason=(
                    f"Plane D recorded a skill-attributed egress request to {flow.host} "
                    "that no Plane A tool call mentions (§10.8: for egress D is "
                    "authoritative and A corroborates)"
                ),
            )
        )
    return findings


def _workspace_relative(path: str) -> str:
    """The path a tool call would have named: relative to the workspace root token."""
    pure = PurePosixPath(path)
    parts = pure.parts
    if parts and parts[0] == "${WORKSPACE}":
        return str(PurePosixPath(*parts[1:])) if len(parts) > 1 else ""
    return path
