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
from collections.abc import Iterable, Sequence
from typing import Any

from bellwether.capture import FilesystemEvent, PlaneStatus
from bellwether.capture.canary import (
    Canary,
    CanaryFinding,
    scan_for_canaries,
)
from bellwether.capture.dns import DnsQuery, scan_query_for_canaries
from bellwether.capture.egress import EgressFlow
from bellwether.harness import RawHarnessEvent
from bellwether.trace.models import (
    Action,
    Actor,
    Correlation,
    Coverage,
    ExitReason,
    PlaneCoverage,
    TokenTotals,
)

__all__ = [
    "assemble_coverage",
    "canary_actions",
    "dns_actions",
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

    A permitted request is ``kind: "egress_request"``; a default-deny block is ``kind:
    "egress_blocked"`` — the two are drawn apart deliberately, because a blocked attempt is
    evidence of intent (§10.5.0) and must never read like an ordinary request. The kind is
    ``egress_request`` (not ``egress``) because that is the §11.2/§1581 ARF action kind the
    canonicalizer maps to an ``egress:<host>`` capability; emitting a bare ``egress`` here
    left every *permitted* flow uncanonicalised — silently absent from the capability sets,
    the scope table, and the rare-capability gate. Every record carries its ``egress_class``
    so the ``no_egress`` assertion can count only skill-attributed traffic without re-deriving
    the classification. The request body is never here — only its digest and length (§10.5):
    the record ends up in an artifact, and a body may hold a credential or a canary.

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
                kind="egress_blocked" if flow.blocked else "egress_request",
                action=payload,
            )
        )
    return actions


def dns_actions(queries: list[DnsQuery], *, start_seq: int = 0) -> list[Action]:
    """Turn the controlled resolver's query log into Plane E action records (§10.6, §11.2).

    An allowlisted (resolved) name is ``kind: "dns_query"``; a default-deny NXDOMAIN is
    ``kind: "dns_blocked"`` — drawn apart for the same reason egress splits ``egress`` from
    ``egress_blocked`` (§10.5.0): a blocked lookup is evidence of intent, not an ordinary
    query, and must never read like one. Every query name is logged whether or not it
    resolved, because the log is the plane's ground truth and a refused name is exactly the
    evidence the resolver exists to capture. The name itself is retained — WP-7's canary scan
    (§10.4.2) runs the label-stripped form back through the corpus, so redacting it here would
    blind the covert-channel detector.

    ``seq`` values follow the queries' given order from ``start_seq``; the caller owns the
    sequence space and WP-7's cross-plane merge places these relative to the other planes.
    """
    actions: list[Action] = []
    for offset, query in enumerate(queries):
        payload: dict[str, Any] = {"name": query.name, "resolved": query.resolved}
        if query.reason:
            payload["reason"] = query.reason
        actions.append(
            Action(
                seq=start_seq + offset,
                ts=dt.datetime.fromisoformat(query.ts),
                plane="dns",
                kind="dns_query" if query.resolved else "dns_blocked",
                action=payload,
            )
        )
    return actions


def _scan_source_action(action: Action, canaries: Sequence[Canary]) -> list[CanaryFinding]:
    """Scan one already-built plane action for canary markers, by kind (§10.4.1).

    A DNS query name and the model's final output are both non-model destinations, so a marker in
    either is a ``canary_leak`` at critical. (Egress path/header scanning and the model-endpoint
    read-state grading — ``canary_in_context`` vs ``canary_without_read`` — are a follow-on: they
    need the per-request read state, and egress *bodies* are scanned sidecar-side since the body
    never leaves the proxy.)
    """
    if action.kind in ("dns_query", "dns_blocked"):
        name = action.action.get("name")
        if isinstance(name, str):
            return scan_query_for_canaries(name, canaries)
    elif action.kind == "final_output":
        text = action.action.get("text")
        if isinstance(text, str):
            return scan_for_canaries(text, canaries, destination="final_output")
    return []


def canary_actions(
    source_actions: Iterable[Action], canaries: Sequence[Canary], *, start_seq: int = 0
) -> list[Action]:
    """Derive Plane C canary findings by scanning the observed plane actions (§10.4).

    Canaries are not a plane the sandbox emits; they are *found* in what the other planes recorded —
    a marker in a DNS query name, in the final output. So this scans the already-built source actions
    and emits one Plane C action per hit, its ``kind`` the finding class (``canary_leak`` /
    ``canary_without_read`` / ``canary_in_context``, §10.4.1) and its ``correlation.anchor_seq``
    pointing at the source action the marker appeared in — so a reviewer can follow the leak to the
    exact query or output that carried it. **No marker value is in the record**, only the canary id
    and where it went (§10.4.3).

    Deterministic: source actions are consumed in order and each source's findings come back sorted,
    so the same evidence yields byte-identical Plane C actions (§24).
    """
    actions: list[Action] = []
    seq = start_seq
    for source in source_actions:
        for finding in _scan_source_action(source, canaries):
            actions.append(
                Action(
                    seq=seq,
                    ts=source.ts,
                    plane="credentials",
                    kind=finding.finding,
                    action={
                        "canary_id": finding.canary_id,
                        "destination": finding.destination,
                        "severity": finding.severity,
                        "offset": finding.offset,
                        "length": finding.length,
                        "via": finding.via,
                    },
                    correlation=Correlation(anchor_seq=source.seq),
                )
            )
            seq += 1
    return actions


def assemble_coverage(
    *,
    harness_events: PlaneStatus | None = None,
    filesystem_writes: PlaneStatus | None = None,
    egress: PlaneStatus | None = None,
    dns: PlaneStatus | None = None,
    credentials: PlaneStatus | None = None,
) -> Coverage:
    """Build the §10.7 coverage block from what WP-5 can actually capture.

    Every plane is stated, including the ones that do not exist yet: a check silently
    left out reads as a check that passed, so the planes later work packages bring are
    listed as unavailable with the work package named — a reason a user can act on,
    which here means "do not expect this evidence yet".

    ``egress`` is set when the recording-proxy sidecar ran for this run (WP-13): the proxy
    writing its flow log is proof the plane was captured, even when it recorded zero flows —
    an observed-clean run, not an unobserved one. Absent it, egress stays ``unavailable``.
    ``dns`` is the same for the controlled resolver (WP-15): the resolver writing its query
    log is proof Plane E was captured, even with zero queries; absent it, dns stays
    ``unavailable``.
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
        credentials=_from_status(credentials, absent="no canaries were planted for this run"),
        egress=_from_status(egress, absent="the recording proxy was not wired into this run"),
        dns=_from_status(dns, absent="the controlled resolver was not wired into this run"),
        process=PlaneCoverage(fidelity="unavailable", reason="process capture lands in WP-18"),
        server_side_tools=PlaneCoverage(
            fidelity="unavailable", reason="proxy-side body parsing lands in WP-13"
        ),
    )


def _from_status(status: PlaneStatus | None, *, absent: str) -> PlaneCoverage:
    if status is None:
        return PlaneCoverage(fidelity="unavailable", reason=absent)
    return PlaneCoverage(fidelity=status.fidelity, reason=status.reason)
