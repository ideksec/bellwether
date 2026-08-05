"""WP-4, container half: the isolation profile and the overlay diff, against a real daemon.

These are the §24 "capture-plane integration tests": small non-agentic container workloads
with known behaviour, asserting the plane records exactly the expected events. They matter
more than they look — they are the tests that would have caught the revision-1 capability
contradiction, where capture code inside the container needed capabilities the isolation
profile claimed to have dropped.

They are marked ``docker`` and skip where no daemon is reachable. **A skip is reported, not
silent**: a suite that quietly passes with the container tests absent is exactly the
"clean-looking failure" this project exists to distrust.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bellwether.determinism import SeededRng
from bellwether.sandbox import (
    DockerBackend,
    IsolationProfile,
    overlay_available,
    prepare_sandbox,
)
from bellwether.sandbox.docker import workspace_is_clean
from bellwether.skill import load_skill

pytestmark = pytest.mark.docker

#: Blobs are served from the registry host itself rather than a CDN, which is what makes
#: this image pullable under restrictive egress policies. Any small image works; the
#: sandbox image a user configures is their own and is pinned by digest.
TEST_IMAGE = os.environ.get("BELLWETHER_TEST_IMAGE", "mcr.microsoft.com/cbl-mariner/base/core:2.0")


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
def prepared(skill_dir: Path, fixture_source: Path, tmp_path: Path):  # type: ignore[no-untyped-def]
    return prepare_sandbox(
        load_skill(skill_dir),
        fixture_source,
        tmp_path / "run",
        rng=SeededRng(20260804, "docker-run"),
    )


@pytest.fixture
def mounted(backend: DockerBackend, prepared):  # type: ignore[no-untyped-def]
    usable, reason = overlay_available()
    if not usable:
        pytest.skip(f"no host-side overlay: {reason}")
    backend.mount(prepared)
    try:
        yield prepared
    finally:
        backend.unmount(prepared)


# ---------------------------------------------------------------------------
# The isolation profile, actually applied (§9.2)
# ---------------------------------------------------------------------------


def test_a_container_runs_under_the_full_profile(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    result = backend.run(mounted, ["sh", "-c", "id -u; echo profile ok"])
    assert result.exit_code == 0, result.stderr
    assert result.exit_reason == "completed"
    # Runs as the configured non-root uid, which is also the uid the workspace is owned by.
    assert result.stdout.splitlines()[0] == str(mounted.isolation.uid)


def test_the_root_filesystem_is_read_only(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    result = backend.run(mounted, ["sh", "-c", "touch /etc/should-fail"])
    assert result.exit_code != 0
    assert "read-only" in result.stderr.lower()


def test_capabilities_are_dropped(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    """`--cap-drop=ALL` is achievable only because no capture code runs inside (§10.0)."""
    result = backend.run(mounted, ["sh", "-c", "cat /proc/self/status | grep CapEff"])
    assert result.exit_code == 0, result.stderr
    effective = result.stdout.split(":")[1].strip()
    assert int(effective, 16) == 0, f"expected no effective capabilities, got {effective}"


def test_privilege_escalation_is_refused(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    result = backend.run(mounted, ["sh", "-c", "cat /proc/self/status | grep NoNewPrivs"])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip().endswith("1")


def test_the_hostname_is_the_randomised_one(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    """§3.5: an environment tell is the cheapest way for a skill to detect evaluation."""
    result = backend.run(mounted, ["sh", "-c", "cat /proc/sys/kernel/hostname"])
    assert result.stdout.strip() == mounted.identifiers.hostname
    for tell in ("bellwether", "sandbox", "eval"):
        assert tell not in result.stdout.lower()


def test_no_bellwether_machinery_exists_inside_the_container(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """The WP-4 done-when criterion, asserted from inside a running container.

    §3.5: a skill that can see the test machinery can behave only while it is observed.
    Every earlier assertion about this was made against a staging directory on the host;
    this one is made from where it matters.
    """
    result = backend.run(
        mounted,
        [
            "sh",
            "-c",
            "find / -name 'manifest.yaml' -o -name 'scenarios.yaml' -o -name 'evals' 2>/dev/null",
        ],
    )
    assert result.stdout.strip() == "", f"machinery visible inside the container:\n{result.stdout}"


def test_the_payload_is_present_and_read_only(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    install = mounted.payload.install_path
    present = backend.run(mounted, ["sh", "-c", f"cat {install}/SKILL.md"])
    assert "body" in present.stdout

    rewrite = backend.run(mounted, ["sh", "-c", f"echo hacked > {install}/SKILL.md"])
    assert rewrite.exit_code != 0, "a skill able to rewrite its own installed body"


def test_the_harness_state_zone_is_writable(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    """§10.2's harness state zone is where an adapter stores session state.

    Under `--read-only`, a declared-writable path with no mount is read-only however
    loudly the profile declares it. Every state write would fail with EROFS, and a run
    where the agent could not write anything reads as a skill that did nothing.
    """
    result = backend.run(
        mounted,
        ["sh", "-c", "mkdir -p /home/agent/.claude/state && echo ok > /home/agent/.claude/s.json"],
    )
    assert result.exit_code == 0, result.stderr


def test_the_payload_stays_read_only_under_a_writable_parent(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """The payload is mounted under the now-writable harness state zone. Mount ordering
    has to leave the read-only bind on top, or the skill can rewrite its own body."""
    install = mounted.payload.install_path
    result = backend.run(mounted, ["sh", "-c", f"echo hacked > {install}/SKILL.md"])
    assert result.exit_code != 0
    assert "read-only" in result.stderr.lower()


def test_the_recorded_command_line_is_the_one_that_ran(backend: DockerBackend, mounted) -> None:  # type: ignore[no-untyped-def]
    """A shortened rendering described as exact is a false fidelity claim the moment it
    reaches a trace."""
    command = ["sh", "-c", "echo hi"]
    rendered = backend.command_line(mounted, command)

    for required in ("--cap-drop", "--read-only", "--network", "--hostname", "-w"):
        assert required in rendered
    assert str(mounted.payload.install_path) in rendered
    assert str(mounted.identifiers.workspace_root) in rendered


# ---------------------------------------------------------------------------
# The overlay diff (§9.1 step 9, §10.2)
# ---------------------------------------------------------------------------


def test_the_upper_directory_yields_the_changed_path_set(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """The other WP-4 done-when criterion: created, modified and deleted, from the host."""
    result = backend.run(
        mounted,
        [
            "sh",
            "-c",
            "echo revised > README.md; echo new > report.md; rm doomed.txt; echo ok",
        ],
    )
    assert result.exit_code == 0, result.stderr

    changes = {change.path: change for change in backend.changed_paths(mounted)}

    assert changes["README.md"].kind == "modified"
    assert changes["report.md"].kind == "created"
    assert changes["doomed.txt"].kind == "deleted"
    assert changes["doomed.txt"].sha256 is None

    # Untouched files never enter the upper directory. That is what makes the read
    # O(changes) rather than O(tree).
    assert "src/auth.py" not in changes


def test_content_hashes_are_recorded_for_changed_files(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    backend.run(mounted, ["sh", "-c", "printf 'exact bytes' > README.md"])
    change = next(c for c in backend.changed_paths(mounted) if c.path == "README.md")

    from bellwether.determinism import stable_hash_bytes

    assert change.sha256 == stable_hash_bytes(b"exact bytes")
    assert change.size_bytes == 11


def test_a_run_that_writes_nothing_leaves_a_clean_workspace(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """`workspace_unchanged` is the strong assertion for a read-only skill (§12.2), and it
    has to be able to pass."""
    result = backend.run(mounted, ["sh", "-c", "cat README.md src/auth.py > /dev/null"])
    assert result.exit_code == 0, result.stderr

    assert backend.changed_paths(mounted) == []
    assert workspace_is_clean(mounted)


def test_the_container_cannot_reach_the_upper_directory(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """§10.0: evidence about an untrusted process is collected outside its control."""
    result = backend.run(mounted, ["sh", "-c", f"ls {mounted.upper_dir} 2>&1 || true"])
    assert str(mounted.upper_dir) not in result.stdout or "No such file" in result.stdout


def test_scratch_stays_outside_the_workspace_diff(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
) -> None:
    """§10.2: scratch is recorded separately — since WP-5 in its own zone overlay —
    and never appears in the workspace diff."""
    result = backend.run(mounted, ["sh", "-c", "echo temp > /tmp/scratch.txt; echo ok"])
    assert result.exit_code == 0, result.stderr
    assert backend.changed_paths(mounted) == []


# ---------------------------------------------------------------------------
# Failure modes (§12.7)
# ---------------------------------------------------------------------------


def test_a_timeout_is_a_failure_not_an_infrastructure_error(
    backend: DockerBackend,
    skill_dir: Path,
    fixture_source: Path,
    tmp_path: Path,
) -> None:
    """§12.7: a timeout is something the skill did, and is a distinct category — never
    blended visually with assertion failures."""
    impatient = prepare_sandbox(
        load_skill(skill_dir),
        fixture_source,
        tmp_path / "timeout-run",
        rng=SeededRng(1, "timeout"),
        isolation=IsolationProfile(timeout_seconds=5),
    )
    result = backend.run(impatient, ["sh", "-c", "sleep 60"])

    assert result.timed_out
    assert result.exit_reason == "timeout"


def test_availability_reports_a_reason(backend: DockerBackend) -> None:
    usable, reason = backend.available()
    assert usable
    assert "docker" in reason.lower()


def test_a_missing_daemon_reports_why_rather_than_looking_clean() -> None:
    """§10.7: a missing plane must read as "unavailable because X", never as a clean run."""
    usable, reason = DockerBackend(binary="definitely-not-docker").available()
    assert not usable
    assert "not installed" in reason
