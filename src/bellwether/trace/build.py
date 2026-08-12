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
    classify_canary_hit,
    redact_canaries,
    scan_for_canaries,
)
from bellwether.capture.dns import DnsQuery, scan_query_for_canaries
from bellwether.capture.egress import EgressCanaryHit, EgressFlow
from bellwether.determinism import canonical_json
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
    "egress_body_actions",
    "exit_reason_from_events",
    "filesystem_actions",
    "harness_actions",
    "redact_trace_actions",
    "token_totals_from_events",
    "written_file_actions",
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

    A DNS query name, the model's final output, a tool call's arguments, and a non-model egress
    request's URL are all non-model destinations, so a marker in any is a ``canary_leak`` at critical.
    A tool-argument hit catches the skill that reads a credential and then exfiltrates it *through* a
    tool — a ``fetch`` URL, a ``bash`` ``curl``/``nc`` command — which is how a sandbox with no direct
    socket still gets a secret out; the whole argument object is scanned (canonicalised) so a marker in
    any nested field surfaces. An egress hit scans the request line the proxy recorded — path, host,
    SNI — which catches the classic ``GET /exfil?d=<secret>`` to an attacker host; requests to the
    model API are skipped here because their URL is harness-built and their body-side, read-state
    grading (``canary_in_context`` vs ``canary_without_read``) is a follow-on, and egress *bodies* are
    scanned sidecar-side since the body never leaves the proxy.
    """
    if action.kind in ("dns_query", "dns_blocked"):
        name = action.action.get("name")
        if isinstance(name, str):
            return scan_query_for_canaries(name, canaries)
    elif action.kind == "final_output":
        text = action.action.get("text")
        if isinstance(text, str):
            return scan_for_canaries(text, canaries, destination="final_output")
    elif action.kind == "tool_call":
        tool_input = action.action.get("input")
        if tool_input is not None:
            return scan_for_canaries(canonical_json(tool_input), canaries, destination="tool_args")
    elif action.kind in ("egress_request", "egress_blocked"):
        # The model API's URL is harness-built (no skill marker) and its grading is body-side and
        # read-state-dependent — a follow-on — so only non-model requests are scanned here. A marker
        # in the path, host, or SNI the proxy recorded is exfiltration to an arbitrary host, a
        # critical leak needing no read state (§10.4.1). The path is scanned case-sensitively and
        # decode-aware, since a URL path can carry a case-exact base64 marker. The host and SNI are
        # scanned the way a DNS name is — case-folded and label-split: a hostname is case-insensitive
        # and `_norm_host` records it lowercased (urlsplit), so a case-sensitive scan would miss a
        # mixed-case marker tunnelled through a subdomain (`<marker>.attacker.com`), and a marker
        # chunked across dot-labels must read as contiguous. A canary is reported at most once per
        # request even if it lands in more than one field.
        if action.action.get("egress_class") != "model_api":
            findings: dict[str, CanaryFinding] = {}
            path = action.action.get("path")
            if isinstance(path, str) and path:
                for finding in scan_for_canaries(path, canaries, destination="other_host"):
                    findings.setdefault(finding.canary_id, finding)
            host_parts = [action.action.get(field) for field in ("host", "sni")]
            host_line = " ".join(part for part in host_parts if isinstance(part, str))
            if host_line:
                for finding in scan_for_canaries(
                    host_line, canaries, destination="other_host", is_dns=True
                ):
                    findings.setdefault(finding.canary_id, finding)
            return sorted(findings.values(), key=lambda f: (f.canary_id, f.offset))
    return []


def canary_actions(
    source_actions: Iterable[Action], canaries: Sequence[Canary], *, start_seq: int = 0
) -> list[Action]:
    """Derive Plane C canary findings by scanning the observed plane actions (§10.4).

    Canaries are not a plane the sandbox emits; they are *found* in what the other planes recorded —
    a marker in a DNS query name, in the final output, in a tool call's arguments, in a non-model
    egress URL. So this scans the already-built source actions and emits one Plane C action per hit,
    its ``kind`` the finding class
    (``canary_leak`` / ``canary_without_read`` / ``canary_in_context``, §10.4.1) and its
    ``correlation.anchor_seq`` pointing at the source action the marker appeared in — so a reviewer can
    follow the leak to the exact query, output, or tool call that carried it. **No marker value is in
    the record**, only the canary id and where it went (§10.4.3).

    Deterministic: source actions are consumed in order and each source's findings come back sorted,
    so the same evidence yields byte-identical Plane C actions (§24).
    """
    actions: list[Action] = []
    seq = start_seq
    for source in source_actions:
        for finding in _scan_source_action(source, canaries):
            actions.append(_plane_c_action(finding, seq=seq, ts=source.ts, anchor_seq=source.seq))
            seq += 1
    return actions


def _plane_c_action(
    finding: CanaryFinding, *, seq: int, ts: dt.datetime, anchor_seq: int
) -> Action:
    """Build one Plane C (``credentials``) action from a canary finding, correlated to its source.

    Shared by every scan source (the plane-action scan and the written-file content scan) so a
    finding is recorded the same way wherever it was found: ``kind`` is the finding class, the payload
    holds the canary id / destination / severity / offset / length / via — **never the marker** — and
    ``anchor_seq`` points at the source action the marker rode out on (§10.4.3).
    """
    return Action(
        seq=seq,
        ts=ts,
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
        correlation=Correlation(anchor_seq=anchor_seq),
    )


def written_file_actions(
    sources: Iterable[tuple[Action, str]], canaries: Sequence[Canary], *, start_seq: int = 0
) -> list[Action]:
    """Derive Plane C findings by scanning the *contents* of files the skill wrote (§10.4).

    Plane B records a write by its hash, not its bytes, so the content cannot be scanned from the
    trace — the executor reads each written regular file host-side and passes it in as a
    ``(write_action, content)`` pair. A marker in a file the skill wrote is a ``written_file`` leak,
    critical and needing no read state (§10.4.1), anchored to the Plane B write that created it. The
    content never enters the trace (Plane B stays hash-only), so there is nothing to redact here — the
    Plane C record is marker-free by construction.

    Deterministic: pairs are consumed in order and each file's findings come back sorted (§24).
    """
    actions: list[Action] = []
    seq = start_seq
    for source, content in sources:
        for finding in scan_for_canaries(content, canaries, destination="written_file"):
            actions.append(_plane_c_action(finding, seq=seq, ts=source.ts, anchor_seq=source.seq))
            seq += 1
    return actions


def egress_body_actions(
    sources: Iterable[tuple[Action, Sequence[EgressCanaryHit]]], *, start_seq: int = 0
) -> list[Action]:
    """Derive Plane C findings from canaries the proxy found in request *bodies* (§10.5.2).

    An egress body never leaves the proxy, so it is scanned sidecar-side and the hits arrive already
    located on the flow as marker-free :class:`EgressCanaryHit`\\s — this pairs each egress action with
    its flow's hits, grades each by its destination (a non-model body is an ``other_host``
    ``canary_leak``), and records it as a Plane C action anchored to the egress request that carried
    it. The value was never on the record; only the by-reference hit crosses from the sidecar.

    Deterministic: sources are consumed in order and each flow's hits in the order the sidecar found
    them (§24).
    """
    actions: list[Action] = []
    seq = start_seq
    for source, hits in sources:
        for hit in hits:
            finding_kind, severity = classify_canary_hit(
                hit.destination,  # type: ignore[arg-type]
                preceded_by_read=False,
            )
            finding = CanaryFinding(
                canary_id=hit.canary_id,
                destination=hit.destination,  # type: ignore[arg-type]
                finding=finding_kind,  # type: ignore[arg-type]
                severity=severity,  # type: ignore[arg-type]
                offset=hit.offset,
                length=hit.length,
                via=hit.via,
            )
            actions.append(_plane_c_action(finding, seq=seq, ts=source.ts, anchor_seq=source.seq))
            seq += 1
    return actions


def _redact_value(value: Any, canaries: Sequence[Canary]) -> Any:
    """Redact every exact canary marker in ``value``, recursing into dicts and lists.

    Payloads are free-form (§11.2) — a marker can sit in the model's final-output string, a nested
    tool-call input dict, a DNS name, an egress path or header — so the walk redacts every string it
    reaches. Only string *values* are rewritten; dict keys are left alone, because a high-entropy
    marker never legitimately names a field and rewriting a key would corrupt the record's shape.
    """
    if isinstance(value, str):
        return redact_canaries(value, canaries)
    if isinstance(value, dict):
        return {k: _redact_value(v, canaries) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v, canaries) for v in value]
    return value


def redact_trace_actions(actions: Iterable[Action], canaries: Sequence[Canary]) -> list[Action]:
    """Replace every exact planted-canary marker in the actions with its fingerprint (§10.4.3).

    The trace is uploaded to CI, so a marker a skill *leaked* — into its final output, a DNS query
    name, an egress path — must never reach the artifact raw. The Plane C finding already records
    that the value escaped and where; this strips the value itself, leaving
    ``<canary:c1@offset=,len=>`` in its place. It runs after :func:`canary_actions` (which needs the
    raw marker to find the leak) and before the trace is written.

    A no-op when nothing was planted, and it copies an action only when a marker was actually present,
    so an unrelated record keeps its identity. Pure per-string rewrite, so the output is byte-stable
    for the same input (§24).
    """
    if not canaries:
        return list(actions)
    redacted: list[Action] = []
    for action in actions:
        new_payload = _redact_value(action.action, canaries)
        if new_payload == action.action:
            redacted.append(action)
        else:
            redacted.append(action.model_copy(update={"action": new_payload}))
    return redacted


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
