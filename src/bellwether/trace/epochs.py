"""Cross-plane ordering: epoch anchoring (§11.5).

The step sequence feeds trajectory clustering, which is a headline metric and a gate.
If the sequence is unstable for reasons unrelated to the skill, the instrument has an
uncalibrated noise floor and the differentiating metric of the whole project is
measuring its own jitter.

**Never sort across planes by wall-clock time.** Planes observe events at different
removes — a proxy timestamps when *it* receives a request, not when the tool fired —
and flush cadences differ per plane, so time-sorted merging makes behaviourally
identical runs produce distinct sequences, biased toward longer runs and busier
runners. The algorithm here uses time for exactly one thing: assigning a non-spine
event to the *epoch* of the tool call whose execution window contains it. Everything
else is causal or content-ordered:

1. Plane A events, in the order the harness reported them, are the **spine** — the only
   plane with a genuine single-threaded causal sequence. Tool calls within it open
   epochs.
2. A non-spine event with ``correlation.anchor_seq`` set is assigned to that tool
   call's epoch and its timestamp is ignored entirely. Explicit correlation always
   beats timing.
3. Otherwise the event's timestamp places it: inside a tool call's reported window →
   that epoch; between windows → the gap epoch after the last tool call that preceded
   it; before the first call → epoch 0; after the last window → the trailing epoch.
4. Within an epoch, order is by content — ``(plane_priority, kind, normalized_target,
   stable_hash)`` — which produces the same order for the same set of events on every
   machine. The normalized target must already be machine-independent (``${WORKSPACE}``
   form), which is why the caller supplies the normalizer.

Known residual, stated in §11.5: a detached process outliving its tool call lands
wherever timing puts it. That is only fixable with PID attribution from Plane D′, and
it is why the §24 noise-floor calibration is a release requirement.
"""

from __future__ import annotations

import bisect
import datetime as dt
from collections.abc import Callable
from typing import Any

from bellwether.determinism import canonical_json, stable_hash
from bellwether.trace.models import Action

__all__ = ["PLANE_PRIORITY", "anchor_events", "content_sort_key"]

#: Fixed, versioned under ``canon_version``: changing it reorders within-epoch events
#: and therefore invalidates trajectory baselines. The spine plane is not listed —
#: spine events are never content-sorted against other planes.
PLANE_PRIORITY: dict[str, int] = {
    "credentials": 0,
    "filesystem": 1,
    "egress": 2,
    "dns": 3,
    "process": 4,
    "proxy_inferred": 5,
    "normalizer": 6,
    "harness": 7,  # non-spine harness events never occur today; listed for totality
}

#: Fields dropped from the content hash. ``ts`` and ``seq`` are run-local; correlation
#: carries ids assigned at capture time. What remains is what the event *was*.
_VOLATILE_FIELDS = ("ts", "seq", "correlation")


def content_sort_key(
    action: Action, normalized_target: Callable[[Action], str]
) -> tuple[int, str, str, str]:
    """The §11.5 step-4 within-epoch key: content, never time."""
    return (
        PLANE_PRIORITY.get(action.plane, len(PLANE_PRIORITY)),
        action.kind,
        normalized_target(action),
        _content_hash(action),
    )


def anchor_events(
    actions: list[Action],
    *,
    normalized_target: Callable[[Action], str],
) -> list[Action]:
    """Order a full multi-plane event set by epoch anchoring (§11.5).

    Args:
        actions: All action records of one run, any order. Plane A events must carry
            ``seq`` values reflecting the harness's reported order (they do: the
            adapter emits them in stream order and ``harness_actions`` preserves it).
        normalized_target: Returns the machine-independent target string for an event
            (``${WORKSPACE}/src/auth.py``, a URL, an argv0). Supplied by the
            canonicalizer so ordering never depends on a run-local path.

    Returns:
        The merged sequence: spine events in reported order, each tool call followed by
        its in-window events, gap events emitted before the next spine element, and
        trailing events at the end.
    """
    spine = sorted((a for a in actions if a.plane == "harness"), key=lambda a: a.seq)
    others = [a for a in actions if a.plane != "harness"]

    tool_calls = [a for a in spine if a.kind == "tool_call"]
    windows = _monotonic_windows(_windows(tool_calls, spine))
    window_starts = [w[0] for w in windows]

    #: epoch index -> events. Epoch i (1-based) is tool call i's window; gap epochs are
    #: keyed by the same index with a flag; epoch 0 is before the first call.
    in_window: dict[int, list[Action]] = {}
    in_gap: dict[int, list[Action]] = {}

    seq_to_epoch = {call.seq: index for index, call in enumerate(tool_calls, start=1)}

    for action in others:
        anchor = action.correlation.anchor_seq
        if anchor is not None and anchor in seq_to_epoch:
            # Explicit correlation: the timestamp is ignored entirely (§11.5 step 3).
            in_window.setdefault(seq_to_epoch[anchor], []).append(action)
            continue
        epoch, gap = _epoch_for(action.ts, windows, window_starts)
        if gap:
            in_gap.setdefault(epoch, []).append(action)
        else:
            in_window.setdefault(epoch, []).append(action)

    key = lambda a: content_sort_key(a, normalized_target)  # noqa: E731

    ordered: list[Action] = []
    epoch = 0
    for element in spine:
        if element.kind == "tool_call":
            # The gap after the previous epoch closes when the next call opens: its
            # events belong between the two, which in stream terms is right here.
            # For the first call this emits epoch 0 — everything before T₁.
            ordered.extend(sorted(in_gap.pop(epoch, []), key=key))
            epoch += 1
            ordered.append(element)
            ordered.extend(sorted(in_window.pop(epoch, []), key=key))
            continue
        # Non-call spine events (results, model turns) keep their stream position.
        ordered.append(element)
    # Everything left is after the last window (or there were no calls at all):
    # the trailing epoch, plus anything clock skew pushed beyond it.
    trailing: list[Action] = []
    for index in sorted(in_gap):
        trailing.extend(in_gap[index])
    for index in sorted(in_window):
        trailing.extend(in_window[index])
    ordered.extend(sorted(trailing, key=key))
    return ordered


def _windows(
    tool_calls: list[Action], spine: list[Action]
) -> list[tuple[dt.datetime, dt.datetime]]:
    """Each tool call's execution window: ``[call.ts, call.ts + duration]``.

    Duration comes from the matching ``tool_result`` (matched by ``tool_call_id``,
    §11.2 makes duration load-bearing for exactly this). A call with no result — the
    run died mid-call — gets a zero-width window; its events fall to the gap after it,
    which is the honest reading of "nothing was observed to complete".
    """
    durations: dict[str, int] = {}
    for action in spine:
        if action.kind != "tool_result":
            continue
        call_id = action.action.get("tool_call_id")
        duration = action.action.get("duration_ms")
        if isinstance(call_id, str) and isinstance(duration, int):
            durations[call_id] = duration

    windows: list[tuple[dt.datetime, dt.datetime]] = []
    for call in tool_calls:
        call_id = call.action.get("tool_call_id")
        duration_ms = durations.get(call_id, 0) if isinstance(call_id, str) else 0
        windows.append((call.ts, call.ts + dt.timedelta(milliseconds=duration_ms)))
    return windows


def _monotonic_windows(
    windows: list[tuple[dt.datetime, dt.datetime]],
) -> list[tuple[dt.datetime, dt.datetime]]:
    """Force the window boundaries non-decreasing in spine (seq) order (§11.5).

    The spine's causal order is its *seq* order, not its clock: epoch ``i`` cannot begin
    before epoch ``i-1``. But spine timestamps are not guaranteed monotonic — clock skew
    across a runner, or genuinely parallel tool calls whose start instants interleave, can
    place a later call's timestamp before an earlier one's. ``_epoch_for`` then locates an
    event with ``bisect``, which requires ``window_starts`` sorted and silently misassigns
    when it is not.

    Clamping each window's start up to the previous start restores a sorted boundary list
    using seq order rather than the untrusted clock, and holds every window's end at or
    after its (possibly raised) start. It is a no-op on an already-monotonic spine — so
    the ordinary run is untouched — and deterministic, so §24 still holds.
    """
    clamped: list[tuple[dt.datetime, dt.datetime]] = []
    floor: dt.datetime | None = None
    for start, end in windows:
        clamped_start = start if floor is None else max(start, floor)
        clamped.append((clamped_start, max(end, clamped_start)))
        floor = clamped_start
    return clamped


def _epoch_for(
    ts: dt.datetime,
    windows: list[tuple[dt.datetime, dt.datetime]],
    window_starts: list[dt.datetime],
) -> tuple[int, bool]:
    """``(epoch index, is_gap)`` for a timestamp (§11.5 step 2).

    Inside window ``i`` (1-based) → ``(i, False)``. After window ``i`` closed but
    before window ``i+1`` opens → ``(i, True)``. Before the first window → ``(0,
    True)`` — the epoch-0 events of the spec.
    """
    if not windows:
        return 0, True
    # Index of the last window whose start is <= ts.
    position = bisect.bisect_right(window_starts, ts)
    if position == 0:
        return 0, True
    start, end = windows[position - 1]
    if start <= ts <= end:
        return position, False
    return position, True


def _content_hash(action: Action) -> str:
    """A hash of what the event was, not when it happened.

    Last element of the sort key, so the only ties it ever breaks are between events
    identical in plane, kind *and* normalized target — where any stable rule serves,
    and swapping them cannot change the reduced step sequence.
    """
    payload: dict[str, Any] = action.model_dump(mode="json", by_alias=True, exclude_none=True)
    for field in _VOLATILE_FIELDS:
        payload.pop(field, None)
    return stable_hash(canonical_json(payload))
