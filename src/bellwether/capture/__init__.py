"""The capture planes: host-side collection of ground truth (§10).

Responsibility
    Plane A (harness events via a host-owned sink), Plane B (filesystem, overlay diff,
    partitioned into the three zones of §10.2), Plane C (canaries), Plane D (network
    egress via the recording proxy), Plane D′ (process execution), Plane E (DNS).
    Produce raw plane events and the coverage block of §10.7.

MUST NOT
    Interpret semantics. A plane records that a path was read; deciding whether that
    read exceeded declared scope belongs to :mod:`bellwether.assertions`.

MUST NOT, more importantly
    Run inside the sandbox. §10.0: no component that produces evidence may execute
    inside the container it observes. Revision 1 violated this and the violation
    invalidated the ground-truth claim.

WP-5 built Plane A's host-owned sink and Plane B's zone-partitioned overlay capture.
WP-13, WP-15, WP-16 and WP-18 bring the proxy, DNS, canaries and process planes.
``mypy --strict`` from the first commit.
"""

from __future__ import annotations

from bellwether.capture.filesystem import (
    FilesystemEvent,
    PlaneStatus,
    collect_filesystem_events,
    filesystem_writes_status,
)
from bellwether.capture.sink import HostEventSink, SinkEvent, SinkStats

__all__ = [
    "FilesystemEvent",
    "HostEventSink",
    "PlaneStatus",
    "SinkEvent",
    "SinkStats",
    "collect_filesystem_events",
    "filesystem_writes_status",
]
