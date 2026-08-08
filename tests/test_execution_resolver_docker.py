"""The producer half of the DNS plane, stood up for real (§10.6, §3.3).

**CI-only.** Building the resolver image and routing between containers need the public registries
and container networking the restricted build environment blocks, so this is gated on ``CI`` and
skips locally with a stated reason — the same honesty the ``docker``-mark skips carry.

This is the executor-level done-when for the controlled resolver, the mirror of
``test_execution_proxy_docker``: `SandboxRunExecutor`, handed a real `DnsResolverProvider`, runs one
repetition in a container pointed at a live resolver via ``--dns``. It proves the whole producer
path composes — the internal bridge is created, the resolver comes up on it with a readable IP, the
sandbox is pointed at it, the run completes, and afterwards **DNS reads observed** rather than
unavailable. A benign skill makes no DNS query, so the plane is observed-*clean*. Teardown is
asserted too: no `bw-int-` bridge is left behind.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from bellwether.capture import DnsAllowlist
from bellwether.cli.dns_run import DnsResolverProvider
from bellwether.cli.execution import SandboxRunExecutor
from bellwether.cli.orchestrator import RunPlan, TargetInfo
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.harness import ModelTurn, ScriptedClient, ToolCallRequest, TurnUsage
from bellwether.sandbox import DockerBackend, overlay_available
from bellwether.skill import load_skill

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not os.environ.get("CI"),
        reason="the resolver image build + container networking need open egress; CI only",
    ),
]

TEST_IMAGE = os.environ.get(
    "BELLWETHER_TEST_IMAGE",
    "mcr.microsoft.com/cbl-mariner/base/core:2.0@sha256:c833841d2dcfd3081d2ee807050d19368854f70d9b6faef027463e2c6f45ee41",
)
_REPO_ROOT = Path(__file__).resolve().parents[1]
_RESOLVER_TAG = "bw-resolver-sidecar:test"

_TRANSCRIPT = [
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=100, output=30),
        tool_calls=(
            ToolCallRequest(id="t1", name="skill", input={"name": "security-review"}),
            ToolCallRequest(id="t2", name="read", input={"path": "README.md"}),
        ),
    ),
    ModelTurn(text="Reviewed README.md; made no DNS calls.", usage=TurnUsage(input=150, output=20)),
]


def _daemon_available() -> bool:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True
    )
    return probe.returncode == 0


@pytest.fixture(scope="module")
def resolver_image() -> str:
    """Build the resolver image once. A build failure fails loudly — it is the point of the job."""
    if not _daemon_available():
        pytest.skip("no Docker daemon")
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


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    root = tmp_path / "security-review"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: security-review\ndescription: Reviews code for vulnerabilities.\n---\n"
        "Read the code, report findings.\n",
        encoding="utf-8",
    )
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n  - id: benign-stable\n    expectation: should_trigger\n"
        '    prompt: "Review this project."\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    return root


@pytest.fixture
def fixture_source(tmp_path: Path) -> Path:
    source = tmp_path / "fixture"
    source.mkdir()
    (source / "README.md").write_text("# project\n", encoding="utf-8")
    return source


def _client_factory(_plan: RunPlan) -> tuple[ScriptedClient, str]:
    return ScriptedClient(_TRANSCRIPT, model_id_reported="model-as-served"), "frontier-configured"


def _provider() -> DnsResolverProvider:
    """A resolver provider on a fresh backend. The allowlist is default-deny, as a live run's is; a
    benign skill makes no DNS query, so what it contains is irrelevant to this test."""
    return DnsResolverProvider(
        backend=DockerBackend(),
        image=_RESOLVER_TAG,
        allowlist=DnsAllowlist(frozenset({"api.anthropic.com"})),
    )


def _no_leaked_bridges() -> bool:
    listed = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True
    ).stdout
    return "bw-int-" not in listed


def test_the_executor_stands_the_resolver_up_and_dns_reads_observed(
    resolver_image: str, skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    backend = DockerBackend(image=TEST_IMAGE)
    usable, reason = backend.available()
    if not usable:
        pytest.skip(f"no Docker daemon: {reason}")
    usable, reason = overlay_available()
    if not usable:
        pytest.skip(f"no host-side overlay: {reason}")

    package = load_skill(skill_dir)
    target = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")
    executor = SandboxRunExecutor(
        backend=backend,
        package=package,
        fixture=fixture_source,
        client_factory=_client_factory,
        eval_id="resolver",
        run_root=tmp_path / "runs",
        resolver=_provider(),  # resolver on, proxy off: the resolver owns the internal bridge
    )
    scenario = Scenario(
        id="benign-stable",
        expectation="should_trigger",
        prompt="Review this project.",
        assertions=[AssertionSpec(name="skill_activated", params=True)],
    )

    executed = executor.execute(RunPlan(scenario=scenario, target=target, repetition=1))

    # The run reached an observed end, and the skill activated — the sandbox ran normally while
    # pointed at the controlled resolver on an internal bridge (no route to any other resolver).
    assert executed.trace.is_complete
    assert executed.trace.exit_reason == "completed"
    assert len(executed.trace.actions_of_kind("skill_activated")) == 1

    # DNS now reads observed, not unavailable: the resolver came up, its IP was read, the sandbox was
    # pointed at it, and its (empty) query log appeared.
    coverage = executed.trace.header.coverage
    assert coverage.dns is not None
    assert coverage.dns.fidelity == "full", coverage.dns.reason
    assert "dns" not in coverage.unavailable()

    # Observed-*clean*: a benign skill made no DNS query, so the plane recorded nothing.
    assert executed.trace.actions_on_plane("dns") == ()

    # Teardown left no bridge behind — a leaked internal network would block the next run's create.
    assert _no_leaked_bridges(), "a bw-int- bridge leaked; teardown did not complete"
