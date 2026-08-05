"""Building ARF records from capture-plane output (WP-5).

This sits in :mod:`bellwether.trace` rather than :mod:`bellwether.capture` because the
module layering runs ``capture -> trace``: capture produces plane-native events and must
not know the wire format; this module knows both and does the translation.

What lands here in WP-5 is the filesystem plane and the coverage block. Harness events
(Plane A) are translated by the harness adapter that defines their schema (WP-6), and the
capability/scope enrichment on every record belongs to the normalizer (WP-7) — a record
built here carries what was *observed*, not what it *means*.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from bellwether.capture import FilesystemEvent, PlaneStatus
from bellwether.trace.models import Action, Coverage, PlaneCoverage

__all__ = ["assemble_coverage", "filesystem_actions"]


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


def assemble_coverage(
    *,
    harness_events: PlaneStatus | None = None,
    filesystem_writes: PlaneStatus | None = None,
) -> Coverage:
    """Build the §10.7 coverage block from what WP-5 can actually capture.

    Every plane is stated, including the ones that do not exist yet: a check silently
    left out reads as a check that passed, so the planes later work packages bring are
    listed as unavailable with the work package named — a reason a user can act on,
    which here means "do not expect this evidence yet".
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
        egress=PlaneCoverage(fidelity="unavailable", reason="the recording proxy lands in WP-13"),
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
