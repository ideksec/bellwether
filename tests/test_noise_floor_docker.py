"""Noise-floor calibration against real containers (§24 — WP-19's done-when).

The three §24 assertions, measured rather than assumed:

1. ``benign-stable`` run repeatedly in a **real** sandbox produces trajectory dispersion of
   **exactly 0.0 over Plane A tool calls alone**. Any nonzero value means §11.5 epoch
   anchoring is admitting jitter — the fix is the anchoring, never accepting the number.
2. The **cross-plane residual** (all planes the canon admits) matches the committed
   ``NOISE_FLOOR_TRAJECTORY`` — the constant published in every ``summary.json`` is a
   measurement this test re-takes, the same regenerate-and-diff reflex as the schema.
3. Repeated under **concurrent load**, the floor does not move: content-based ordering must
   not depend on scheduling, so saturating the runner must change nothing. With a floor of
   exactly zero, "not materially" tightens to "not at all".

Needs Docker and root, like every capture test (§10.0). The model side is scripted; the
containers, overlay capture, and epoch anchoring under test are real.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from bellwether.cli.execution import SandboxRunExecutor
from bellwether.cli.orchestrator import ExecutedRun, RunPlan, TargetInfo
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.constants import NOISE_FLOOR_TRAJECTORY
from bellwether.harness import ModelTurn, ScriptedClient, ToolCallRequest, TurnUsage
from bellwether.metrics import summarise_trajectory
from bellwether.sandbox import DockerBackend, overlay_available
from bellwether.skill import load_skill
from bellwether.trace import CanonBlock, canonicalize

pytestmark = pytest.mark.docker

TEST_IMAGE = os.environ.get(
    "BELLWETHER_TEST_IMAGE",
    "mcr.microsoft.com/cbl-mariner/base/core:2.0@sha256:c833841d2dcfd3081d2ee807050d19368854f70d9b6faef027463e2c6f45ee41",
)

_TRANSCRIPT = [
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=120, output=40),
        tool_calls=(
            ToolCallRequest(id="toolu_01", name="skill", input={"name": "security-review"}),
            ToolCallRequest(id="toolu_02", name="read", input={"path": "src/auth.py"}),
        ),
    ),
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=260, output=90),
        tool_calls=(
            ToolCallRequest(
                id="toolu_03",
                name="write",
                input={"path": "report.md", "content": "# Findings\nNone.\n"},
            ),
        ),
    ),
    ModelTurn(text="Reviewed src/auth.py; wrote report.md.", usage=TurnUsage(input=310, output=25)),
]


@pytest.fixture(scope="session")
def backend() -> DockerBackend:
    docker = DockerBackend(image=TEST_IMAGE)
    usable, reason = docker.available()
    if not usable:
        pytest.skip(f"no Docker daemon: {reason}")
    usable, reason = overlay_available()
    if not usable:
        pytest.skip(f"no host-side overlay: {reason}")
    return docker


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    root = tmp_path / "security-review"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: security-review\ndescription: Reviews code for vulnerabilities.\n---\n"
        "Read the code, report findings.\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def fixture_source(tmp_path: Path) -> Path:
    source = tmp_path / "fixture"
    (source / "src").mkdir(parents=True)
    (source / "src" / "auth.py").write_text("def login(): ...\n", encoding="utf-8")
    return source


def _scenario() -> Scenario:
    return Scenario(
        id="benign-stable",
        expectation="should_trigger",
        prompt="Review this project.",
        assertions=[AssertionSpec(name="skill_activated", params=True)],
    )


def _client_factory(_plan: RunPlan) -> tuple[ScriptedClient, str]:
    return ScriptedClient(_TRANSCRIPT, model_id_reported="model-as-served"), "frontier-configured"


def _executor(
    backend: DockerBackend, skill_dir: Path, fixture_source: Path, run_root: Path, eval_id: str
) -> SandboxRunExecutor:
    return SandboxRunExecutor(
        backend=backend,
        package=load_skill(skill_dir),
        fixture=fixture_source,
        client_factory=_client_factory,
        eval_id=eval_id,
        run_root=run_root,
    )


def _dispersion(runs: list[ExecutedRun], traj_planes: list[str]) -> float:
    """Mean pairwise step-sequence distance over the given planes, from real traces."""
    sequences = []
    for executed in runs:
        canon = canonicalize(
            executed.trace.actions, executed.context, canon=CanonBlock(traj_planes=traj_planes)
        )
        sequences.append(canon.step_sequence)
    assert all(sequences), "a run produced an empty step sequence; the calibration input is broken"
    metrics = summarise_trajectory(sequences)
    assert metrics.mean_pairwise_distance is not None
    return metrics.mean_pairwise_distance


def test_noise_floor_sequential_and_the_committed_constant(
    backend: DockerBackend, skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    """§24 assertions 1 and 2: Plane-A-only dispersion is exactly zero across six real
    container runs, and the cross-plane residual equals the committed constant."""
    executor = _executor(backend, skill_dir, fixture_source, tmp_path / "runs", "noisefloor")
    scenario = _scenario()
    target = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")
    runs = [
        executor.execute(RunPlan(scenario=scenario, target=target, repetition=rep))
        for rep in range(1, 7)
    ]
    for executed in runs:
        assert executed.trace.is_complete
        assert executed.trace.exit_reason == "completed"

    # 1. Plane A alone: exactly zero, not a small number. Nonzero here is a WP-7 bug.
    assert _dispersion(runs, ["A"]) == 0.0
    # 2. The cross-plane residual is the committed, published floor — re-measured, not trusted.
    assert _dispersion(runs, ["A", "C", "D", "E"]) == NOISE_FLOOR_TRAJECTORY


def test_noise_floor_does_not_move_under_concurrent_load(
    backend: DockerBackend, skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    """§24 assertion 3: the ordering is content-based (§11.5), so saturating the runner
    with concurrent sandboxes must not move the floor. If it does, ordering is still
    time-dependent somewhere. With a committed floor of exactly zero, "not materially"
    tightens to "not at all"."""
    scenario = _scenario()
    target = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")

    def one_run(repetition: int) -> ExecutedRun:
        # One executor per worker: the load under test is the *runner* (concurrent
        # containers, contended CPU), not executor-object thread-safety.
        executor = _executor(
            backend,
            skill_dir,
            fixture_source,
            tmp_path / f"runs-{repetition}",
            f"noisefloor-load-{repetition}",
        )
        return executor.execute(RunPlan(scenario=scenario, target=target, repetition=repetition))

    with ThreadPoolExecutor(max_workers=4) as pool:
        runs = list(pool.map(one_run, range(1, 5)))
    for executed in runs:
        assert executed.trace.is_complete
        assert executed.trace.exit_reason == "completed"

    assert _dispersion(runs, ["A"]) == 0.0
    assert _dispersion(runs, ["A", "C", "D", "E"]) == NOISE_FLOOR_TRAJECTORY
