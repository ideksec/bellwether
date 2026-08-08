"""WP-5, offline half: the event sink and the filesystem plane, without a daemon.

The container end of both planes is exercised by the §24 capture-plane integration tests
in ``test_capture_docker.py``; everything here runs on any machine, because the sink is
just a FIFO and the filesystem plane is pure translation.
"""

from __future__ import annotations

import datetime as dt
import os
import stat
import threading
import time
from pathlib import Path

import pytest

from bellwether.capture import (
    HostEventSink,
    PlaneStatus,
    collect_filesystem_events,
    filesystem_writes_status,
)
from bellwether.errors import BellwetherError
from bellwether.sandbox import PathChange, ZoneMap
from bellwether.trace import assemble_coverage, filesystem_actions, serialize_record

OBSERVED_AT = dt.datetime(2026, 8, 5, 10, 0, 0, tzinfo=dt.UTC)


# ---------------------------------------------------------------------------
# Plane A: the host-owned sink (§10.1)
# ---------------------------------------------------------------------------


def write_lines(path: Path, lines: list[bytes]) -> None:
    fd = os.open(path, os.O_WRONLY)
    try:
        for line in lines:
            os.write(fd, line)
    finally:
        os.close(fd)


def test_the_sink_records_json_lines_in_order(tmp_path: Path) -> None:
    with HostEventSink(tmp_path / "events") as sink:
        write_lines(sink.path, [b'{"event": "one"}\n', b'{"event": "two"}\n'])
        time.sleep(0.5)
    events = sink.events

    assert [event.payload for event in events] == [{"event": "one"}, {"event": "two"}]
    assert [event.index for event in events] == [0, 1]
    assert all(event.ok for event in events)


def test_the_sink_is_write_only_once_started(tmp_path: Path) -> None:
    """A FIFO delivers data to whichever reader gets it first, so a readable sink is a
    sink whose evidence can be *stolen* — worse than truncation, because theft leaves no
    trace. The host opens its descriptor first, then drops the node to write-only."""
    with HostEventSink(tmp_path / "events") as sink:
        mode = stat.S_IMODE(sink.path.lstat().st_mode)
        assert mode == 0o222

        if os.geteuid() != 0:  # root bypasses permission checks entirely
            with pytest.raises(PermissionError):
                os.open(sink.path, os.O_RDONLY | os.O_NONBLOCK)

        # Write access is what the container needs, and it still works.
        write_lines(sink.path, [b'{"still": "writable"}\n'])
        time.sleep(0.5)
    assert sink.events[0].payload == {"still": "writable"}


def test_a_malformed_line_is_recorded_not_dropped(tmp_path: Path) -> None:
    """A skill spraying garbage into the evidence stream is itself evidence."""
    with HostEventSink(tmp_path / "events") as sink:
        write_lines(sink.path, [b"not json at all\n", b"[1, 2, 3]\n", b'{"fine": true}\n'])
        time.sleep(0.5)
    events = sink.events

    assert len(events) == 3
    assert events[0].malformed and events[0].raw == "not json at all"
    assert events[1].malformed, "a bare array is not an event object"
    assert events[2].ok
    assert sink.stats.malformed == 2


def test_a_writer_that_dies_mid_line_leaves_a_truncated_event(tmp_path: Path) -> None:
    with HostEventSink(tmp_path / "events") as sink:
        write_lines(sink.path, [b'{"complete": true}\n{"cut off'])
        time.sleep(0.5)
    events = sink.events

    assert events[0].ok
    assert events[1].truncated
    assert events[1].raw == '{"cut off'


def test_an_oversized_line_is_truncated_and_marked(tmp_path: Path) -> None:
    sink = HostEventSink(tmp_path / "events", max_line_bytes=64)
    with sink:
        write_lines(sink.path, [b'{"filler": "' + b"x" * 500 + b'"}\n'])
        time.sleep(0.5)
    (event,) = sink.events

    assert event.truncated
    assert len(event.raw.encode()) == 64
    assert sink.stats.truncated == 1


def test_the_total_byte_cap_counts_what_it_declines_to_store(tmp_path: Path) -> None:
    """§10.7: degraded capture must say so. A flood that silently stopped being recorded
    would read as a run that went quiet."""
    sink = HostEventSink(tmp_path / "events", max_total_bytes=64)
    with sink:
        write_lines(sink.path, [b'{"n": %d}\n' % n for n in range(20)])
        time.sleep(0.5)

    assert sink.stats.dropped_after_cap > 0
    assert len(sink.events) < 20
    status = sink.status()
    assert status.fidelity == "partial"
    assert status.reason is not None and "cap" in status.reason


def test_stopping_with_no_writer_does_not_hang(tmp_path: Path) -> None:
    """The observed process must never decide whether the observer finishes (§10.0).
    The WP-4 review found exactly this hang; this is the regression test for the sink."""
    sink = HostEventSink(tmp_path / "events")
    sink.start()
    began = time.monotonic()
    assert sink.stop(drain_seconds=1.0) == []
    assert time.monotonic() - began < 5.0


def test_the_sink_refuses_a_pre_existing_path(tmp_path: Path) -> None:
    """A node that existed before the host created it could be anyone's plant."""
    path = tmp_path / "events"
    path.write_text("planted", encoding="utf-8")
    with pytest.raises(BellwetherError, match="refusing to reuse"):
        HostEventSink(path).start()


def test_a_healthy_sink_reports_full_fidelity(tmp_path: Path) -> None:
    with HostEventSink(tmp_path / "events") as sink:
        write_lines(sink.path, [b'{"ok": true}\n'])
        time.sleep(0.5)
    assert sink.status().fidelity == "full"


def test_concurrent_writers_are_all_recorded(tmp_path: Path) -> None:
    """Hook processes can overlap. Writes at or under PIPE_BUF are atomic, so distinct
    small events never interleave; this asserts none are lost either."""
    with HostEventSink(tmp_path / "events") as sink:
        threads = [
            threading.Thread(target=write_lines, args=(sink.path, [b'{"writer": %d}\n' % n]))
            for n in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        time.sleep(0.5)

    payloads = [event.payload for event in sink.events]
    assert sorted(p["writer"] for p in payloads if p) == list(range(8))


# ---------------------------------------------------------------------------
# Plane B: zone partitioning (§10.2)
# ---------------------------------------------------------------------------


def change(path: str, kind: str = "created") -> PathChange:
    return PathChange(
        path=path,
        kind=kind,  # type: ignore[arg-type]
        sha256=None if kind == "deleted" else "sha256:abc",
        size_bytes=None if kind == "deleted" else 3,
        mode=None if kind == "deleted" else 0o644,
    )


def test_events_carry_zone_membership_and_absolute_paths() -> None:
    events = collect_filesystem_events(
        {
            "workspace": [change("report.md")],
            "harness_state": [change("state/session.json")],
            "scratch": [change("probe.txt")],
        },
        ZoneMap(),
    )

    by_zone = {event.zone: event for event in events}
    assert by_zone["workspace"].absolute == "/work/report.md"
    assert by_zone["harness_state"].absolute == "/home/agent/.claude/state/session.json"
    assert by_zone["scratch"].absolute == "/tmp/probe.txt"
    assert all(event.relative == event.change.path for event in events)


def test_event_order_is_deterministic() -> None:
    """§24: the same observed set produces the same list on every machine."""
    changes = {
        "scratch": [change("z.txt"), change("a.txt")],
        "workspace": [change("b.md"), change("a.md")],
    }
    first = collect_filesystem_events(dict(changes), ZoneMap())
    second = collect_filesystem_events(dict(reversed(changes.items())), ZoneMap())

    assert [e.absolute for e in first] == [e.absolute for e in second]
    assert [e.zone for e in first] == ["workspace", "workspace", "scratch", "scratch"]
    assert [e.relative for e in first] == ["a.md", "b.md", "a.txt", "z.txt"]


def test_canary_plant_sites_are_flagged() -> None:
    events = collect_filesystem_events(
        {"workspace": [change(".env"), change("src/main.py")]},
        ZoneMap(),
        canary_paths=frozenset({".env"}),
    )
    flags = {event.relative: event.canary_path for event in events}
    assert flags == {".env": True, "src/main.py": False}


def test_an_unobserved_zone_is_absent_not_empty() -> None:
    events = collect_filesystem_events({"workspace": [change("a.md")]}, ZoneMap())
    assert {event.zone for event in events} == {"workspace"}

    status = filesystem_writes_status({"workspace"})
    assert status.fidelity == "partial"
    assert status.reason is not None
    assert "harness_state" in status.reason and "scratch" in status.reason


def test_all_zones_observed_is_overlay_diff_fidelity() -> None:
    """`overlay_diff`, not `full`: writes are captured, reads and transients are not,
    and §10.8 depends on that distinction — this fidelity may confirm but never refute."""
    assert filesystem_writes_status({"workspace", "harness_state", "scratch"}).fidelity == (
        "overlay_diff"
    )


def test_nothing_observed_is_unavailable() -> None:
    assert filesystem_writes_status(set()).fidelity == "unavailable"


def test_a_deletion_becomes_a_file_delete_kind() -> None:
    events = collect_filesystem_events({"workspace": [change("gone.txt", "deleted")]}, ZoneMap())
    assert events[0].kind == "file_delete"


# ---------------------------------------------------------------------------
# Capture events to ARF records (§11.2)
# ---------------------------------------------------------------------------


def test_filesystem_actions_carry_zone_membership_on_every_record() -> None:
    events = collect_filesystem_events(
        {
            "workspace": [change("report.md"), change("old.txt", "deleted")],
            "scratch": [change("t.txt")],
        },
        ZoneMap(),
    )
    actions = filesystem_actions(events, observed_at=OBSERVED_AT)

    assert [action.seq for action in actions] == [0, 1, 2]
    assert all(action.plane == "filesystem" for action in actions)
    assert all("zone" in action.action for action in actions)
    assert [action.kind for action in actions] == ["file_delete", "file_write", "file_write"]

    delete = actions[0]
    assert delete.action == {
        "path": "/work/old.txt",
        "zone": "workspace",
        "zone_relative": "old.txt",
        "change": "deleted",
    }
    write = actions[1]
    assert write.action["sha256"] == "sha256:abc"
    assert write.action["mode"] == "0644"


def test_a_special_file_is_recorded_by_presence() -> None:
    """§10.0: a FIFO's *presence* is the evidence; its content is never opened."""
    fifo = PathChange(path="trap", kind="created", mode=0o644, file_type="fifo")
    events = collect_filesystem_events({"workspace": [fifo]}, ZoneMap())
    (action,) = filesystem_actions(events, observed_at=OBSERVED_AT)

    assert action.action["special"] is True
    assert action.action["file_type"] == "fifo"
    assert "sha256" not in action.action


def test_filesystem_records_serialise_compactly() -> None:
    """The reason the null-emission question had to be settled before this plane: a run
    produces thousands of these."""
    events = collect_filesystem_events({"workspace": [change("a.md")]}, ZoneMap())
    (action,) = filesystem_actions(events, observed_at=OBSERVED_AT)
    line = serialize_record(action)

    assert ":null" not in line
    assert len(line) < 300


def test_seq_assignment_respects_the_callers_sequence_space() -> None:
    events = collect_filesystem_events({"workspace": [change("a.md")]}, ZoneMap())
    (action,) = filesystem_actions(events, observed_at=OBSERVED_AT, start_seq=41)
    assert action.seq == 41


# ---------------------------------------------------------------------------
# The coverage block (§10.7)
# ---------------------------------------------------------------------------


def test_every_plane_is_stated_including_the_unbuilt_ones() -> None:
    """A check silently left out reads as a check that passed."""
    coverage = assemble_coverage()
    unavailable = coverage.unavailable()

    assert set(unavailable) == {
        "harness_events",
        "filesystem_writes",
        "filesystem_reads",
        "credentials",
        "egress",
        "dns",
        "process",
        "server_side_tools",
    }
    # Each absent plane names the work package that brings it, or why it is off. Egress and
    # DNS are wireable now (the recording proxy and the controlled resolver are built), so
    # their reasons name why they were not captured *this run* rather than a work package.
    assert "recording proxy" in unavailable["egress"]
    assert "controlled resolver" in unavailable["dns"]
    assert "WP-16" in unavailable["credentials"]
    assert "WP-18" in unavailable["process"]


def test_active_planes_reach_the_coverage_block(tmp_path: Path) -> None:
    with HostEventSink(tmp_path / "events") as sink:
        pass
    coverage = assemble_coverage(
        harness_events=sink.status(),
        filesystem_writes=filesystem_writes_status({"workspace", "harness_state", "scratch"}),
        dns=PlaneStatus(fidelity="full"),
    )

    assert coverage.harness_events is not None
    assert coverage.harness_events.fidelity == "full"
    assert coverage.filesystem_writes is not None
    assert coverage.filesystem_writes.fidelity == "overlay_diff"
    # The controlled resolver ran for this run, so Plane E is observed, not unavailable.
    assert coverage.dns is not None
    assert coverage.dns.fidelity == "full"
    assert "harness_events" not in coverage.unavailable()
    assert "filesystem_writes" not in coverage.unavailable()
    assert "dns" not in coverage.unavailable()
