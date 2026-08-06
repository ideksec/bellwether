"""WP-5, container half: the §24 capture-plane integration tests.

Small non-agentic container workloads with known behaviour, asserting each host-side
plane records exactly the expected events — not "at least", not "roughly": a plane that
over-records attributes machinery noise to the skill, and one that under-records reads
as a skill that did nothing. These are the tests the build plan flags as mattering more
than they look; the revision-1 capability contradiction would have died here.

Marked ``docker``; they skip with a stated reason where the daemon or the overlay
privilege is missing.
"""

from __future__ import annotations

import os
import time
from pathlib import Path, PurePosixPath

import pytest

from bellwether.capture import (
    HostEventSink,
    collect_filesystem_events,
    filesystem_writes_status,
)
from bellwether.determinism import SeededRng
from bellwether.sandbox import DockerBackend, overlay_available, prepare_sandbox
from bellwether.skill import load_skill
from bellwether.trace import assemble_coverage, filesystem_actions

pytestmark = pytest.mark.docker

TEST_IMAGE = os.environ.get(
    "BELLWETHER_TEST_IMAGE",
    "mcr.microsoft.com/cbl-mariner/base/core:2.0@sha256:c833841d2dcfd3081d2ee807050d19368854f70d9b6faef027463e2c6f45ee41",
)

#: Where the sink is bound inside the container. `/dev` because it is a tmpfs in every
#: Docker container, so the mountpoint needs no writable rootfs. A production adapter
#: draws an innocuous name per run (§3.5); a fixed name is fine for a test that is not
#: hiding from anyone.
SINK_PATH = PurePosixPath("/dev/events")


@pytest.fixture(scope="session")
def backend() -> DockerBackend:
    docker = DockerBackend(image=TEST_IMAGE)
    usable, reason = docker.available()
    if not usable:
        pytest.skip(f"no Docker daemon: {reason}")
    return docker


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    root = tmp_path / "probe-skill"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: probe-skill\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n  - id: s\n    expectation: should_trigger\n"
        '    prompt: "p"\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    return root


@pytest.fixture
def fixture_source(tmp_path: Path) -> Path:
    source = tmp_path / "fixture"
    (source / "src").mkdir(parents=True)
    (source / "src" / "auth.py").write_text("def login(): ...\n", encoding="utf-8")
    (source / "README.md").write_text("# project\n", encoding="utf-8")
    (source / "doomed.txt").write_text("delete me\n", encoding="utf-8")
    return source


@pytest.fixture
def mounted(backend: DockerBackend, skill_dir: Path, fixture_source: Path, tmp_path: Path):  # type: ignore[no-untyped-def]
    usable, reason = overlay_available()
    if not usable:
        pytest.skip(f"no host-side overlay: {reason}")
    prepared = prepare_sandbox(
        load_skill(skill_dir),
        fixture_source,
        tmp_path / "run",
        rng=SeededRng(20260805, "capture-run"),
    )
    backend.mount(prepared)
    try:
        yield prepared
    finally:
        backend.unmount(prepared)


# ---------------------------------------------------------------------------
# Plane B: each zone records exactly its own writes (§10.2)
# ---------------------------------------------------------------------------


def test_each_zone_records_exactly_its_own_writes(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    """The §24 done-when for the filesystem plane: a workload with known behaviour in
    all three zones, and each zone's record contains exactly that zone's changes."""
    result = backend.run(
        mounted,
        [
            "sh",
            "-c",
            "echo revised > README.md; echo new > report.md; rm doomed.txt; "
            "echo temp > /tmp/probe.txt; "
            "mkdir -p /home/agent/.claude/state && echo '{}' > /home/agent/.claude/state/s.json",
        ],
    )
    assert result.exit_code == 0, result.stderr

    zones = backend.zone_changes(mounted)
    assert set(zones) == {"workspace", "harness_state", "scratch"}

    workspace = {change.path: change.kind for change in zones["workspace"]}
    assert workspace == {"README.md": "modified", "report.md": "created", "doomed.txt": "deleted"}

    assert {c.path: c.kind for c in zones["scratch"]} == {"probe.txt": "created"}
    assert {c.path: c.kind for c in zones["harness_state"]} == {"state/s.json": "created"}


def test_a_scratch_write_does_not_pollute_the_workspace_diff(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """§10.2's reason for existing: without the separation, `workspace_unchanged` never
    passes for any skill and the capability set churns for non-skill reasons."""
    result = backend.run(mounted, ["sh", "-c", "echo temp > /tmp/scratch.txt; echo ok"])
    assert result.exit_code == 0, result.stderr

    assert backend.changed_paths(mounted) == []
    zones = backend.zone_changes(mounted)
    assert zones["workspace"] == []
    assert [c.path for c in zones["scratch"]] == ["scratch.txt"]


def test_an_untouched_zone_is_observed_empty_not_absent(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """Empty means observed-and-untouched; absent means unobserved. Conflating them is
    how a capture failure reads as a clean run (§10.7)."""
    result = backend.run(mounted, ["sh", "-c", "cat README.md > /dev/null"])
    assert result.exit_code == 0, result.stderr

    zones = backend.zone_changes(mounted)
    assert zones["scratch"] == []
    assert zones["harness_state"] == []
    assert filesystem_writes_status(set(zones)).fidelity == "overlay_diff"


def test_zone_writes_become_arf_records_with_zone_membership(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """End to end: container workload → per-zone overlay diff → ARF action records that
    name the real container paths, with zone membership on every record."""
    import datetime as dt

    result = backend.run(
        mounted,
        ["sh", "-c", "echo new > report.md; echo temp > /tmp/probe.txt"],
    )
    assert result.exit_code == 0, result.stderr

    events = collect_filesystem_events(
        backend.zone_changes(mounted),
        mounted.zones,
        workspace_root=mounted.identifiers.workspace_root,
    )
    actions = filesystem_actions(events, observed_at=dt.datetime.now(dt.UTC))

    by_path = {action.action["path"]: action for action in actions}
    workspace_report = f"{mounted.identifiers.workspace_root}/report.md"
    assert set(by_path) == {workspace_report, "/tmp/probe.txt"}
    assert by_path[workspace_report].action["zone"] == "workspace"
    assert by_path["/tmp/probe.txt"].action["zone"] == "scratch"
    assert all(action.kind == "file_write" for action in actions)
    assert all(action.plane == "filesystem" for action in actions)


# ---------------------------------------------------------------------------
# Plane A: the host-owned sink, from inside a real container (§10.1)
# ---------------------------------------------------------------------------


def test_the_container_writes_events_and_the_host_records_them(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    with HostEventSink(tmp_path / "events") as sink:
        result = backend.run(
            mounted,
            [
                "sh",
                "-c",
                f"printf '%s\\n' '{{\"tool\": \"Bash\"}}' > {SINK_PATH}; "
                f"printf '%s\\n' '{{\"tool\": \"Read\"}}' > {SINK_PATH}",
            ],
            sink_bind=(sink.path, SINK_PATH),
        )
        assert result.exit_code == 0, result.stderr

    assert [event.payload for event in sink.events] == [{"tool": "Bash"}, {"tool": "Read"}]
    assert sink.status().fidelity == "full"


def test_the_container_cannot_read_the_sink(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    """A readable FIFO is a stealable evidence stream: whichever reader gets a datum
    first keeps it, and theft leaves no trace. Write-only from the container's side."""
    with HostEventSink(tmp_path / "events") as sink:
        result = backend.run(
            mounted,
            ["sh", "-c", f"cat {SINK_PATH}"],
            sink_bind=(sink.path, SINK_PATH),
        )
        assert result.exit_code != 0
        assert "denied" in result.stderr.lower()


def test_the_container_cannot_remove_the_sink(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    """The sink is a bind-mounted single file, so unlink fails with EBUSY — the
    container cannot even remove the evidence channel, only decline to write to it."""
    with HostEventSink(tmp_path / "events") as sink:
        result = backend.run(
            mounted,
            [
                "sh",
                "-c",
                f"rm -f {SINK_PATH}; printf '%s\\n' '{{\"after\": \"rm\"}}' > {SINK_PATH}",
            ],
            sink_bind=(sink.path, SINK_PATH),
        )
        # Whatever rm reported, the sink survived and still accepts events.
        assert result.exit_code == 0, result.stderr

    assert sink.path.exists()
    assert [event.payload for event in sink.events] == [{"after": "rm"}]


def test_garbage_from_the_container_is_recorded_not_dropped(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    with HostEventSink(tmp_path / "events") as sink:
        result = backend.run(
            mounted,
            ["sh", "-c", f"echo 'not an event' > {SINK_PATH}"],
            sink_bind=(sink.path, SINK_PATH),
        )
        assert result.exit_code == 0, result.stderr

    (event,) = sink.events
    assert event.malformed
    assert event.raw == "not an event"


def test_the_sink_does_not_hang_after_the_container_exits(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    """§10.0 in its sharpest form: the WP-4 review found a FIFO that hung the collector
    forever after the container had already exited. The sink's stop is deadline-driven."""
    sink = HostEventSink(tmp_path / "events")
    sink.start()
    result = backend.run(
        mounted,
        ["sh", "-c", f"printf '%s\\n' '{{\"only\": 1}}' > {SINK_PATH}"],
        sink_bind=(sink.path, SINK_PATH),
    )
    assert result.exit_code == 0, result.stderr

    began = time.monotonic()
    events = sink.stop(drain_seconds=2.0)
    assert time.monotonic() - began < 10.0
    assert [event.payload for event in events] == [{"only": 1}]


# ---------------------------------------------------------------------------
# The coverage block, end to end (§10.7)
# ---------------------------------------------------------------------------


def test_a_full_wp5_run_reports_its_actual_coverage(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    with HostEventSink(tmp_path / "events") as sink:
        result = backend.run(
            mounted,
            ["sh", "-c", f"echo done > report.md; printf '%s\\n' '{{\"t\": 1}}' > {SINK_PATH}"],
            sink_bind=(sink.path, SINK_PATH),
        )
        assert result.exit_code == 0, result.stderr

    coverage = assemble_coverage(
        harness_events=sink.status(),
        filesystem_writes=filesystem_writes_status(set(backend.zone_changes(mounted))),
    )

    assert coverage.harness_events is not None
    assert coverage.harness_events.fidelity == "full"
    assert coverage.filesystem_writes is not None
    assert coverage.filesystem_writes.fidelity == "overlay_diff"
    # The planes later work packages bring are stated as unavailable, never omitted.
    unavailable = coverage.unavailable()
    assert {"egress", "dns", "process", "credentials"} <= set(unavailable)
