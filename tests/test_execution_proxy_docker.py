"""The producer half of the egress plane, stood up for real (§10.5, §3.3).

**CI-only.** Building the sidecar image and routing between containers need the public registries and
container networking the restricted build environment blocks, so this is gated on ``CI`` and skips
locally with a stated reason — the same honesty the ``docker``-mark skips carry.

This is the executor-level done-when for the recording proxy: `SandboxRunExecutor`, handed a real
`SidecarProxyProvider`, runs one repetition in a container that is dual-homed behind a live mitmproxy
sidecar. It proves the whole producer path composes — the two bridges are created, the sidecar comes
up on the internal one and is attached to the egress one, its CA is written to the shared volume and
mounted into the sandbox, the sandbox runs routed through it, and afterwards **egress reads observed**
rather than unavailable. A benign skill makes no egress, so the plane is observed-*clean* — which is
exactly the state that lets a benign live run reach `ready` instead of `conditional`. Teardown is
asserted too: no `bw-int-`/`bw-egr-` bridge is left behind.

The CA-to-shared-volume mechanism is the load-bearing unknown this test exercises: if mitmproxy does
not write its CA where the executor expects, `ca_cert_path()` raises and `execute` fails here rather
than silently producing a zero-egress trace (§9.2).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from bellwether.capture import CredentialBroker, EgressAllowlist
from bellwether.cli.execution import SandboxRunExecutor
from bellwether.cli.orchestrator import RunPlan, TargetInfo
from bellwether.cli.proxy_run import SidecarProxyProvider
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.harness import ModelTurn, ScriptedClient, ToolCallRequest, TurnUsage
from bellwether.sandbox import DockerBackend, overlay_available
from bellwether.skill import load_skill

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not os.environ.get("CI"),
        reason="the sidecar image build + container networking need open egress; CI only",
    ),
]

TEST_IMAGE = os.environ.get(
    "BELLWETHER_TEST_IMAGE",
    "mcr.microsoft.com/cbl-mariner/base/core:2.0@sha256:c833841d2dcfd3081d2ee807050d19368854f70d9b6faef027463e2c6f45ee41",
)
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SIDECAR_TAG = "bw-proxy-sidecar:test"

_TRANSCRIPT = [
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=100, output=30),
        tool_calls=(
            ToolCallRequest(id="t1", name="skill", input={"name": "security-review"}),
            ToolCallRequest(id="t2", name="read", input={"path": "README.md"}),
        ),
    ),
    ModelTurn(
        text="Reviewed README.md; made no network calls.", usage=TurnUsage(input=150, output=20)
    ),
]


def _daemon_available() -> bool:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True
    )
    return probe.returncode == 0


@pytest.fixture(scope="module")
def sidecar_image() -> str:
    """Build the sidecar image once. A build failure fails loudly — it is the point of the job."""
    if not _daemon_available():
        pytest.skip("no Docker daemon")
    build = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(_REPO_ROOT / "sidecar" / "proxy" / "Dockerfile"),
            "-t",
            _SIDECAR_TAG,
            str(_REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.fail(
            "sidecar image build failed:\n"
            f"--- stdout ---\n{build.stdout[-4000:]}\n--- stderr ---\n{build.stderr[-4000:]}"
        )
    return _SIDECAR_TAG


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


def _provider() -> SidecarProxyProvider:
    """A provider on a fresh network-ops backend. The allowlist is irrelevant here — the benign
    skill makes no egress — but is default-deny, as a live run's is. The broker is empty: the
    sandbox is handed no credential (§3.3 invariant 1)."""
    return SidecarProxyProvider(
        backend=DockerBackend(),
        image=_SIDECAR_TAG,
        allowlist=EgressAllowlist(
            provider_endpoints=frozenset(), infrastructure_endpoints=frozenset()
        ),
        max_requests=10,
        max_request_bytes=100_000,
        broker=CredentialBroker({}),
    )


def _no_leaked_bridges() -> bool:
    listed = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True
    ).stdout
    return "bw-int-" not in listed and "bw-egr-" not in listed


def test_the_executor_stands_the_proxy_up_and_egress_reads_observed(
    sidecar_image: str, skill_dir: Path, fixture_source: Path, tmp_path: Path
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
        eval_id="proxy",
        run_root=tmp_path / "runs",
        proxy=_provider(),
    )
    scenario = Scenario(
        id="benign-stable",
        expectation="should_trigger",
        prompt="Review this project.",
        assertions=[AssertionSpec(name="skill_activated", params=True)],
    )

    executed = executor.execute(RunPlan(scenario=scenario, target=target, repetition=1))

    # The run reached an observed end, and the skill activated — the sandbox ran normally while
    # routed through the proxy on an internal bridge.
    assert executed.trace.is_complete
    assert executed.trace.exit_reason == "completed"
    assert len(executed.trace.actions_of_kind("skill_activated")) == 1

    # Egress now reads observed, not unavailable: the sidecar came up, wrote its CA to the shared
    # volume (else ca_cert_path would have raised), and its flow log appeared.
    coverage = executed.trace.header.coverage
    assert coverage.egress is not None
    assert coverage.egress.fidelity == "full", coverage.egress.reason
    assert "egress" not in coverage.unavailable()

    # Observed-*clean*: a benign skill made no egress, so the plane recorded nothing. This is the
    # state that lets a benign live run reach `ready` (§16.2).
    assert executed.trace.actions_on_plane("egress") == ()

    # Teardown left no bridge behind — a leaked internal network would block the next run's create.
    assert _no_leaked_bridges(), "a bw-int-/bw-egr- bridge leaked; teardown did not complete"
