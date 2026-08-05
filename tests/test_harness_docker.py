"""WP-6, container half: the api-loop adapter against a real sandbox.

The done-when: a run produces a complete ARF trace with Plane A and Plane B populated,
and tool calls carry their originating id. The model side stays scripted — WP-6 is about
the harness machinery, and a live provider call would make these tests cost money and
flake with the network; the container side is entirely real.
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

import pytest

from bellwether.capture import collect_filesystem_events, filesystem_writes_status
from bellwether.determinism import SeededRng
from bellwether.harness import (
    ApiLoopAdapter,
    ModelTurn,
    OfferedSkill,
    RunLimits,
    SandboxToolset,
    ScriptedClient,
    ToolCallRequest,
    TurnUsage,
)
from bellwether.harness.tools import docker_exec_runner
from bellwether.sandbox import DockerBackend, overlay_available, prepare_sandbox
from bellwether.skill import load_skill
from bellwether.trace import (
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
    assemble_coverage,
    exit_reason_from_events,
    filesystem_actions,
    harness_actions,
    read_trace,
    token_totals_from_events,
    write_trace,
)

pytestmark = pytest.mark.docker

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
    root = tmp_path / "review-skill"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: review-skill\ndescription: Reviews code.\n---\nRead code, write report.\n",
        encoding="utf-8",
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
    return source


@pytest.fixture
def session(backend: DockerBackend, skill_dir: Path, fixture_source: Path, tmp_path: Path):  # type: ignore[no-untyped-def]
    """A mounted sandbox with a running persistent container."""
    usable, reason = overlay_available()
    if not usable:
        pytest.skip(f"no host-side overlay: {reason}")
    prepared = prepare_sandbox(
        load_skill(skill_dir),
        fixture_source,
        tmp_path / "run",
        rng=SeededRng(20260806, "harness-run"),
    )
    backend.mount(prepared)
    backend.start_persistent(prepared)
    try:
        yield prepared
    finally:
        backend.stop_persistent(prepared)
        backend.unmount(prepared)


# ---------------------------------------------------------------------------
# The persistent container and the tools inside it
# ---------------------------------------------------------------------------


def test_the_persistent_container_execs_in_the_workspace(backend: DockerBackend, session) -> None:  # type: ignore[no-untyped-def]
    result = backend.exec_in(session, ["pwd"])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip() == str(session.identifiers.workspace_root)

    # State persists between execs: one filesystem, one session, like a real agent run.
    backend.exec_in(session, ["sh", "-c", "echo persisted > state.txt"])
    again = backend.exec_in(session, ["cat", "state.txt"])
    assert again.stdout.strip() == "persisted"


def test_the_tools_operate_inside_the_container(backend: DockerBackend, session) -> None:  # type: ignore[no-untyped-def]
    toolset = SandboxToolset(docker_exec_runner(backend, session))

    read = toolset.execute("read", {"path": "src/auth.py"})
    assert read.ok and "def login" in read.output

    write = toolset.execute("write", {"path": "notes/report.md", "content": "# findings\n"})
    assert write.ok, write.error

    bash = toolset.execute("bash", {"command": "wc -l < src/auth.py"})
    assert bash.ok and bash.output.strip() == "1"

    changed = {change.path for change in backend.changed_paths(session)}
    assert "notes/report.md" in changed


def test_symlink_resolution_stays_inside_the_container(backend: DockerBackend, session) -> None:  # type: ignore[no-untyped-def]
    """The reason the tools exec in the container: a symlink planted by a skill resolves
    against the container's filesystem. A host-side read tool would resolve it against
    the host — a sandbox escape one `ln -s` away."""
    toolset = SandboxToolset(docker_exec_runner(backend, session))
    planted = toolset.execute("bash", {"command": "ln -s /etc/os-release peek"})
    assert planted.ok, planted.error

    through_link = toolset.execute("read", {"path": "peek"})
    inside = backend.exec_in(session, ["cat", "/etc/os-release"])
    assert through_link.ok
    assert through_link.output == inside.stdout


def test_a_hung_tool_call_fails_that_call_not_the_session(backend: DockerBackend, session) -> None:  # type: ignore[no-untyped-def]
    toolset = SandboxToolset(docker_exec_runner(backend, session), tool_timeout=3.0)
    outcome = toolset.execute("bash", {"command": "sleep 30"})
    assert not outcome.ok

    # The session survives the timeout; the container is still serving.
    followup = backend.exec_in(session, ["echo", "alive"])
    assert followup.stdout.strip() == "alive"


# ---------------------------------------------------------------------------
# The WP-6 done-when: a complete two-plane trace from a real sandbox
# ---------------------------------------------------------------------------


def test_a_run_produces_a_complete_trace_with_both_planes(
    backend: DockerBackend,
    session,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    skill = OfferedSkill(
        name="review-skill", description="Reviews code.", body="Read code, write report.\n"
    )
    transcript = [
        ModelTurn(
            stop_reason="tool_use",
            usage=TurnUsage(input=100, output=30),
            tool_calls=(
                ToolCallRequest(id="toolu_a", name="skill", input={"name": "review-skill"}),
                ToolCallRequest(id="toolu_b", name="read", input={"path": "src/auth.py"}),
            ),
        ),
        ModelTurn(
            stop_reason="tool_use",
            usage=TurnUsage(input=200, output=60),
            tool_calls=(
                ToolCallRequest(
                    id="toolu_c",
                    name="write",
                    input={"path": "report.md", "content": "# Findings\nNone.\n"},
                ),
                ToolCallRequest(
                    id="toolu_d", name="bash", input={"command": "date > /tmp/when.txt"}
                ),
            ),
        ),
        ModelTurn(text="Reviewed; report written.", usage=TurnUsage(input=250, output=20)),
    ]
    adapter = ApiLoopAdapter(
        ScriptedClient(transcript, model_id_reported="served"),
        SandboxToolset(docker_exec_runner(backend, session)),
        skills=(skill,),
    )

    started_at = dt.datetime.now(dt.UTC)
    events = list(adapter.run("Review the project.", model_id="configured", limits=RunLimits()))
    exit_reason = exit_reason_from_events(events)
    assert exit_reason is not None

    plane_a = harness_actions(events)
    observed_at = dt.datetime.now(dt.UTC)
    zone_diffs = backend.zone_changes(session)
    plane_b = filesystem_actions(
        collect_filesystem_events(
            zone_diffs, session.zones, workspace_root=session.identifiers.workspace_root
        ),
        observed_at=observed_at,
        start_seq=len(plane_a),
    )

    header = RunHeader(
        run_id="wp6-integration",
        eval_id="wp6",
        scenario_id="two-planes",
        repetition=1,
        skill=SkillRef(
            name="review-skill",
            package_digest="sha256:" + "0" * 64,
            payload_digest="sha256:" + "0" * 64,
            source=str(session.payload.root),
        ),
        target=TargetRef(
            harness=adapter.name,
            harness_version=adapter.version(),
            provider="scripted",
            model_alias="frontier",
            model_id_requested="configured",
            model_id_reported="served",
            harness_capabilities=adapter.capabilities().as_record(),
        ),
        sandbox=SandboxRef(
            image=TEST_IMAGE, workspace_root=str(session.identifiers.workspace_root)
        ),
        coverage=assemble_coverage(
            harness_events=None if not events else _full_status(),
            filesystem_writes=filesystem_writes_status(set(zone_diffs)),
        ),
        started_at=started_at,
    )
    footer = RunFooter(
        ended_at=observed_at,
        wall_clock_ms=int((observed_at - started_at).total_seconds() * 1000),
        exit_reason=exit_reason,
        tokens=token_totals_from_events(events),
    )
    path = write_trace(tmp_path / "run.jsonl", header, plane_a + plane_b, footer)

    trace = read_trace(path)
    assert trace.is_complete
    assert trace.evaluability() == "evaluable"
    assert trace.exit_reason == "completed"

    # Plane A is populated, and tool calls carry their originating ids.
    assert [a.action["tool_call_id"] for a in trace.actions_of_kind("tool_call")] == [
        "toolu_a",
        "toolu_b",
        "toolu_c",
        "toolu_d",
    ]
    assert len(trace.actions_of_kind("skill_activated")) == 1

    # Plane B is populated: the write tool's file in the workspace zone, the bash
    # tool's file in the scratch zone, each carrying zone membership.
    fs = {a.action["path"]: a.action["zone"] for a in trace.actions_on_plane("filesystem")}
    assert fs[f"{session.identifiers.workspace_root}/report.md"] == "workspace"
    assert fs["/tmp/when.txt"] == "scratch"

    # Coverage states both active planes and the not-yet-built ones.
    coverage = trace.header.coverage
    assert coverage.filesystem_writes is not None
    assert coverage.filesystem_writes.fidelity == "overlay_diff"
    assert "egress" in coverage.unavailable()

    # Token accounting reached the footer with cache lines separate.
    assert trace.footer is not None
    assert trace.footer.tokens.input == 550


def _full_status():  # type: ignore[no-untyped-def]
    from bellwether.capture import PlaneStatus

    return PlaneStatus(fidelity="full")
