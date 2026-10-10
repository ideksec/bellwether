"""`execution.concurrency` against real sandboxes: two runs in flight on one executor (§19.3).

The offline suite proves the driver's ordering and look discipline with a fake. What it cannot
show is that the *real* executor is safe to call from two threads at once: one
:class:`SandboxRunExecutor` and one :class:`DockerBackend` serve every run of an evaluation, and
each run mounts overlays, starts a named container, and (with the resolver on) creates a named
bridge. Here two repetitions go through :func:`drive_evaluation` at ``concurrency=2`` and the
containers are observed alive at the same time; the runs complete with distinct container names,
and afterwards nothing is left behind — no container, no overlay mount, no bridge. A second test
fails one of the two runs mid-flight (after its container started) and asserts the failure is
raised while neither run leaks.

The local tests need Docker and root, like every capture test (§10.0). The resolver variant also
needs the resolver image build, so it is CI-only, as ``test_execution_resolver_docker`` is.
"""

from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from bellwether.capture import DnsAllowlist
from bellwether.cli.dns_run import DnsResolverProvider
from bellwether.cli.execution import SandboxRunExecutor
from bellwether.cli.orchestrator import RunPlan, TargetInfo, drive_evaluation, plan_matrix
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.errors import BellwetherError
from bellwether.harness import ModelTurn, ScriptedClient, ToolCallRequest, TurnUsage
from bellwether.sandbox import DockerBackend, overlay_available
from bellwether.sandbox.session import PreparedSandbox
from bellwether.skill import load_skill
from bellwether.trace import read_trace
from tests.test_driver import _firstlight_profile

pytestmark = pytest.mark.docker

TEST_IMAGE = os.environ.get(
    "BELLWETHER_TEST_IMAGE",
    "mcr.microsoft.com/cbl-mariner/base/core:2.0@sha256:c833841d2dcfd3081d2ee807050d19368854f70d9b6faef027463e2c6f45ee41",
)
_REPO_ROOT = Path(__file__).resolve().parents[1]
_RESOLVER_TAG = "bw-resolver-sidecar:test"
_TARGET = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")

_TRANSCRIPT = [
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=100, output=30),
        tool_calls=(
            ToolCallRequest(id="t1", name="skill", input={"name": "security-review"}),
            ToolCallRequest(id="t2", name="read", input={"path": "README.md"}),
            ToolCallRequest(
                id="t3", name="write", input={"path": "notes.md", "content": "# notes\n"}
            ),
        ),
    ),
    ModelTurn(text="Read README.md; wrote notes.md.", usage=TurnUsage(input=150, output=20)),
]


@dataclass
class _WatchedBackend(DockerBackend):
    """The real backend, recording which sandbox containers are alive at once.

    ``start_persistent`` and ``stop_persistent`` bracket a container's life; the peak of the
    live set is the number of sandboxes that really ran side by side.
    """

    watch_lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    alive: set[str] = field(default_factory=set)
    peak: int = 0
    started: list[str] = field(default_factory=list)

    def start_persistent(self, prepared: PreparedSandbox, **kwargs) -> None:  # type: ignore[no-untyped-def, override]
        super().start_persistent(prepared, **kwargs)
        with self.watch_lock:
            name = prepared.identifiers.container_name
            self.alive.add(name)
            self.started.append(name)
            self.peak = max(self.peak, len(self.alive))

    def stop_persistent(self, prepared: PreparedSandbox) -> None:
        super().stop_persistent(prepared)
        with self.watch_lock:
            self.alive.discard(prepared.identifiers.container_name)


@dataclass
class _HeldClient:
    """A scripted client that waits — bounded — for the other run's container to be up.

    The model side is the first thing a run does once its container has started, so holding the
    first turn until both containers are alive makes the overlap a fact of the test rather than
    a matter of scheduling luck. The wait is bounded so a serial executor fails the assertion
    instead of hanging.
    """

    inner: ScriptedClient
    both_up: threading.Event
    fail: bool = False

    def complete(self, request):  # type: ignore[no-untyped-def]
        self.both_up.wait(timeout=60)
        if self.fail:
            raise BellwetherError("scripted failure in the second run, after its container started")
        return self.inner.complete(request)

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        return getattr(self.inner, name)


@pytest.fixture
def backend() -> _WatchedBackend:
    docker = _WatchedBackend(image=TEST_IMAGE)
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
    source.mkdir()
    (source / "README.md").write_text("# project\n", encoding="utf-8")
    return source


def _scenario() -> Scenario:
    return Scenario(
        id="benign-stable",
        expectation="should_trigger",
        prompt="Review this project.",
        assertions=[AssertionSpec(name="skill_activated", params=True)],
    )


def _containers() -> set[str]:
    listed = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True
    ).stdout
    return set(listed.split())


def _networks() -> set[str]:
    listed = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True
    ).stdout
    return set(listed.split())


def _mounts_under(root: Path) -> list[str]:
    text = Path("/proc/mounts").read_text(encoding="utf-8")
    return [line for line in text.splitlines() if str(root) in line]


def _trace_path(tmp_path: Path, repetition: int) -> Path:
    return tmp_path / "runs" / "benign-stable" / _TARGET.slug / str(repetition) / "trace.arf.jsonl"


def _executor(
    backend: DockerBackend,
    skill_dir: Path,
    fixture_source: Path,
    run_root: Path,
    *,
    fail_repetition: int | None = None,
    resolver: DnsResolverProvider | None = None,
) -> SandboxRunExecutor:
    both_up = threading.Event()
    watched = backend

    def client_factory(plan: RunPlan) -> tuple[_HeldClient, str]:
        client = _HeldClient(
            ScriptedClient(_TRANSCRIPT, model_id_reported="model-as-served"),
            both_up,
            fail=plan.repetition == fail_repetition,
        )
        # Called after `start_persistent`, so this run's container is already alive.
        assert isinstance(watched, _WatchedBackend)
        with watched.watch_lock:
            if len(watched.alive) >= 2:
                both_up.set()
        return client, "frontier-configured"  # type: ignore[return-value]

    return SandboxRunExecutor(
        backend=backend,
        package=load_skill(skill_dir),
        fixture=fixture_source,
        client_factory=client_factory,  # type: ignore[arg-type]
        eval_id="concurrency",
        run_root=run_root,
        resolver=resolver,
    )


def _drive(executor: SandboxRunExecutor) -> list:  # type: ignore[type-arg]
    plans = plan_matrix([_scenario()], [_TARGET], repetitions=2)
    return drive_evaluation(
        plans,
        executor,
        profile=_firstlight_profile(),
        looks_for=lambda _scenario_id: [2],
        concurrency=2,
    )


def test_two_real_sandboxes_run_at_once_without_collision(
    backend: _WatchedBackend, skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    before = _containers()
    executor = _executor(backend, skill_dir, fixture_source, tmp_path / "runs")

    (reading,) = _drive(executor)

    assert backend.peak == 2, "the two sandboxes never ran at the same time"
    assert len(set(backend.started)) == 2, f"container names collided: {backend.started}"
    assert len(reading.runs) == 2
    assert [run.key.repetition for run in reading.runs] == [1, 2]
    for repetition in (1, 2):
        trace = read_trace(_trace_path(tmp_path, repetition))
        assert trace.is_complete and trace.exit_reason == "completed"
        assert trace.header.repetition == repetition
        # Each run's write was observed in its own overlay (Plane B), not lost to a neighbour's.
        writes = [a for a in trace.actions_on_plane("filesystem") if "notes.md" in str(a.action)]
        assert writes, f"repetition {repetition}: the overlay write was not observed"
    assert _containers() == before, "a sandbox container outlived its run"
    assert _mounts_under(tmp_path) == [], "an overlay outlived its run"


def test_a_failing_run_does_not_leak_itself_or_its_neighbour(
    backend: _WatchedBackend, skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    before = _containers()
    executor = _executor(backend, skill_dir, fixture_source, tmp_path / "runs", fail_repetition=2)

    with pytest.raises(BellwetherError, match="scripted failure in the second run"):
        _drive(executor)

    assert backend.peak == 2, "the failing run never overlapped the other"
    assert backend.alive == set()
    assert _containers() == before, "a sandbox container outlived a failed evaluation"
    assert _mounts_under(tmp_path) == [], "an overlay outlived a failed evaluation"
    # The run that did not fail completed and wrote its trace before the error was raised.
    assert read_trace(_trace_path(tmp_path, 1)).exit_reason == "completed"


@pytest.fixture(scope="module")
def resolver_image() -> str:
    if not os.environ.get("CI"):
        pytest.skip("the resolver image build + container networking need open egress; CI only")
    build = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(_REPO_ROOT / "sidecar" / "resolver" / "Dockerfile"),
            "-t",
            _RESOLVER_TAG,
            str(_REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.fail(
            "resolver image build failed:\n"
            f"--- stdout ---\n{build.stdout[-4000:]}\n--- stderr ---\n{build.stderr[-4000:]}"
        )
    return _RESOLVER_TAG


def test_two_runs_with_their_own_resolvers_and_bridges_at_once(
    resolver_image: str,
    backend: _WatchedBackend,
    skill_dir: Path,
    fixture_source: Path,
    tmp_path: Path,
) -> None:
    """Each run stands up its own internal bridge and resolver, named from its coordinate; two at
    once must not collide, both must read DNS observed, and both bridges must be gone after."""
    networks_before = _networks()
    containers_before = _containers()
    provider = DnsResolverProvider(
        backend=DockerBackend(),
        image=resolver_image,
        allowlist=DnsAllowlist(frozenset({"api.anthropic.com"})),
    )
    executor = _executor(backend, skill_dir, fixture_source, tmp_path / "runs", resolver=provider)

    (reading,) = _drive(executor)

    assert backend.peak == 2
    assert len(reading.runs) == 2
    for repetition in (1, 2):
        coverage = read_trace(_trace_path(tmp_path, repetition)).header.coverage
        assert coverage.dns is not None and coverage.dns.fidelity == "full", coverage.dns
    assert _networks() == networks_before, "a per-run bridge outlived its run"
    assert _containers() == containers_before, "a sandbox or resolver outlived its run"
