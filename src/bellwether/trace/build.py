"""Building ARF records from capture and harness output (WP-5, WP-6).

This sits in :mod:`bellwether.trace` rather than in the layers that produce the events,
because the module layering runs ``harness -> capture -> trace``: producers emit
plane-native events and must not know the wire format; this module knows both and does
the translation.

WP-5 landed the filesystem plane and the coverage block; WP-6 adds the harness event
stream (Plane A). The capability/scope enrichment on every record belongs to the
normalizer (WP-7) — a record built here carries what was *observed*, not what it
*means*.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from bellwether.capture import FilesystemEvent, PlaneStatus
from bellwether.capture.egress import EgressFlow
from bellwether.harness import RawHarnessEvent
from bellwether.trace.models import Action, Actor, Coverage, ExitReason, PlaneCoverage, TokenTotals

__all__ = [
    "assemble_coverage",
    "egress_actions",
    "exit_reason_from_events",
    "filesystem_actions",
    "harness_actions",
    "token_totals_from_events",
]


def harness_actions(events: list[RawHarnessEvent], *, start_seq: int = 0) -> list[Action]:
    """Turn the adapter's raw event stream into Plane A action records (§10.1, §11.2).

    A mapping, not a guess: adapters speak in §11.3 kinds already. Two things happen on
    the way through — ``None`` values are dropped from payloads (the writer omits
    ``null`` fields for the same reason), and the originating ``tool_call_id`` is kept
    on both the call and its result, because explicit correlation is the strong path
    for cross-plane attribution (§11.5).

    Plane A is the ordering spine: sequence numbers here follow event order, which is
    the loop's genuine causal sequence. Order is a quality question — a skill that lies
    about it degrades a quality metric; it cannot hide a capability, which is built
    from the host-side planes (§10.1).
    """
    actions: list[Action] = []
    for offset, event in enumerate(events):
        payload: dict[str, Any] = {k: v for k, v in event.data.items() if v is not None}
        if event.tool_call_id is not None:
            payload["tool_call_id"] = event.tool_call_id
        actions.append(
            Action(
                seq=start_seq + offset,
                ts=event.ts,
                plane="harness",
                kind=event.kind,
                actor=Actor(role="assistant", turn=event.turn) if event.turn else None,
                action=payload,
            )
        )
    return actions


def token_totals_from_events(events: list[RawHarnessEvent]) -> TokenTotals:
    """Sum token accounting across model turns, cache reads and writes separate (§9.3)."""
    totals = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    for event in events:
        if event.kind != "model_turn":
            continue
        tokens = event.data.get("tokens") or {}
        for key in totals:
            totals[key] += int(tokens.get(key, 0))
    return TokenTotals(**totals)


def exit_reason_from_events(events: list[RawHarnessEvent]) -> ExitReason | None:
    """How the run ended, as the event stream tells it.

    ``None`` where the stream ended without either a final output or a limit event —
    the run crashed mid-way, and the caller must not write a footer at all, because a
    footer's absence is the incomplete-trace signal (§11.1).
    """
    for event in reversed(events):
        if event.kind == "final_output":
            return "completed"
        if event.kind == "harness_error":
            reason = event.data.get("exit_reason")
            if reason == "timeout":
                return "timeout"
            if reason == "budget_exceeded":
                return "budget_exceeded"
            return "harness_error"
    return None


def filesystem_actions(
    events: list[FilesystemEvent],
    *,
    observed_at: dt.datetime,
    start_seq: int = 0,
) -> list[Action]:
    """Turn zone-partitioned filesystem events into ARF action records (§10.2, §11.2).

    Every record carries its zone membership, because the assertion engine and the
    capability builder consume it differently — that is the point of WP-5's partitioning.

    ``observed_at`` is the instant the overlay diff was read, and every record gets it:
    overlay capture observes a post-run *set*, not a sequence, so per-event timestamps do
    not exist and inventing a spread would manufacture an ordering §11.5 would then
    trust. At this fidelity Plane B contributes no ordering — ``CanonBlock.traj_planes``
    already excludes it — and identical timestamps are how a set says it is a set.

    ``seq`` values are assigned in the events' deterministic sorted order from
    ``start_seq``. The caller owns the sequence space; WP-7's cross-plane merge decides
    where these records sit relative to Plane A's.
    """
    actions: list[Action] = []
    for offset, event in enumerate(events):
        change = event.change
        payload: dict[str, Any] = {
            "path": event.absolute,
            "zone": event.zone,
            "zone_relative": event.relative,
            "change": change.kind,
        }
        if change.sha256 is not None:
            payload["sha256"] = change.sha256
        if change.size_bytes is not None:
            payload["size_bytes"] = change.size_bytes
        if change.mode is not None:
            payload["mode"] = f"{change.mode:04o}"
        if change.file_type != "regular":
            payload["file_type"] = change.file_type
        if change.is_special:
            # A FIFO, socket or device: the *presence* is the evidence, and it is never
            # opened (§10.0 — the collector must not block on what the container made).
            payload["special"] = True
        if event.canary_path:
            payload["canary_path"] = True

        actions.append(
            Action(
                seq=start_seq + offset,
                ts=observed_at,
                plane="filesystem",
                kind=event.kind,
                action=payload,
            )
        )
    return actions


def egress_actions(flows: list[EgressFlow], *, start_seq: int = 0) -> list[Action]:
    """Turn classified proxy flows into Plane D action records (§10.5, §11.2).

    A permitted request is ``kind: "egress"``; a default-deny block is ``kind:
    "egress_blocked"`` — the two are drawn apart deliberately, because a blocked attempt is
    evidence of intent (§10.5.0) and must never read like an ordinary request. Every record
    carries its ``egress_class`` so the ``no_egress`` assertion can count only
    skill-attributed traffic without re-deriving the classification. The request body is
    never here — only its digest and length (§10.5): the record ends up in an artifact, and
    a body may hold a credential or a canary.

    ``seq`` values follow the flows' given order from ``start_seq``; the caller owns the
    sequence space and WP-7's cross-plane merge places these relative to the other planes.
    """
    actions: list[Action] = []
    for offset, flow in enumerate(flows):
        payload: dict[str, Any] = {
            "method": flow.method,
            "scheme": flow.scheme,
            "host": flow.host,
            "port": flow.port,
            "path": flow.path,
            "egress_class": flow.egress_class,
            "headers": dict(flow.request_headers),
            "request_body_bytes": flow.request_body_bytes,
        }
        if flow.request_body_sha256:
            payload["request_body_sha256"] = flow.request_body_sha256
        if flow.response_status is not None:
            payload["response_status"] = flow.response_status
        if flow.response_size is not None:
            payload["response_size"] = flow.response_size
        if flow.sni:
            payload["sni"] = flow.sni
        if flow.blocked:
            payload["block_reason"] = flow.block_reason

        actions.append(
            Action(
                seq=start_seq + offset,
                ts=dt.datetime.fromisoformat(flow.ts),
                plane="egress",
                kind="egress_blocked" if flow.blocked else "egress",
                action=payload,
            )
        )
    return actions


def assemble_coverage(
    *,
    harness_events: PlaneStatus | None = None,
    filesystem_writes: PlaneStatus | None = None,
    egress: PlaneStatus | None = None,
) -> Coverage:
    """Build the §10.7 coverage block from what WP-5 can actually capture.

    Every plane is stated, including the ones that do not exist yet: a check silently
    left out reads as a check that passed, so the planes later work packages bring are
    listed as unavailable with the work package named — a reason a user can act on,
    which here means "do not expect this evidence yet".

    ``egress`` is set when the recording-proxy sidecar ran for this run (WP-13): the proxy
    writing its flow log is proof the plane was captured, even when it recorded zero flows —
    an observed-clean run, not an unobserved one. Absent it, egress stays ``unavailable``.
    """
    return Coverage(
        harness_events=_from_status(
            harness_events, absent="no event sink was attached to this run"
        ),
        filesystem_writes=_from_status(
            filesystem_writes, absent="no zone overlay was mounted for this run"
        ),
        filesystem_reads=PlaneCoverage(
            fidelity="unavailable",
            reason="read capture is the v0.2 fanotify mechanism; overlay diff records writes only",
        ),
        credentials=PlaneCoverage(fidelity="unavailable", reason="canary planting lands in WP-16"),
        egress=_from_status(egress, absent="the recording proxy was not wired into this run"),
        dns=PlaneCoverage(fidelity="unavailable", reason="the controlled resolver lands in WP-15"),
        process=PlaneCoverage(fidelity="unavailable", reason="process capture lands in WP-18"),
        server_side_tools=PlaneCoverage(
            fidelity="unavailable", reason="proxy-side body parsing lands in WP-13"
        ),
    )


def _from_status(status: PlaneStatus | None, *, absent: str) -> PlaneCoverage:
    if status is None:
        return PlaneCoverage(fidelity="unavailable", reason=absent)
    return PlaneCoverage(fidelity=status.fidelity, reason=status.reason)
