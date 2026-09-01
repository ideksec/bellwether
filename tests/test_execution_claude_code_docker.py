"""WP-17's container half: the real Claude Code CLI inside the sandbox, behind the proxy (§9.4).

**CI-only.** Building the sandbox image (an ``npm install`` of the CLI) and the proxy sidecar
image needs the public registries the restricted build environment blocks, so this is gated on
``CI`` and skips locally with a stated reason — the same honesty the ``docker``-mark skips carry.

This is the executor-level done-when for the ``claude-code`` adapter, with every piece real
except the model: a scripted Messages API on the host stands in for the provider, reachable only
through the recording proxy's egress bridge. `SandboxRunExecutor`, handed a claude-code target,
stands the sink FIFO and the proxy up, starts the CLI in the container with the sandbox-scoped
token, streams its structured output, drains the hook stream from the sink, and assembles the
trace. The assertions are the things that could silently go wrong:

- the run completes with the skill **activated by the harness itself** — the trigger surface
  is the CLI's, so ``trigger_metrics_portable`` is true (the reason WP-17 is in v0.1);
- the tool calls the CLI reports are corroborated by its hook stream on the host sink, so
  Plane A reads ``full`` and there is no ``trace_inconsistency``;
- the CLI's model calls are **observed at the proxy** as ``model_api`` flows carrying the
  scoped token swapped for the real key — and nothing skill-attributed leaves;
- the write lands in the workspace overlay (Plane B), so the two planes agree.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from bellwether.capture import CredentialBroker, EgressAllowlist, provider_hosts
from bellwether.cli.execution import SandboxRunExecutor
from bellwether.cli.orchestrator import RunPlan, TargetInfo
from bellwether.cli.proxy_run import SidecarProxyProvider
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.determinism import SeededRng
from bellwether.harness import CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS, ScriptedClient
from bellwether.sandbox import DockerBackend, overlay_available
from bellwether.skill import load_skill

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not os.environ.get("CI"),
        reason="the sandbox and sidecar image builds need open egress; CI only",
    ),
]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SANDBOX_TAG = "bw-sandbox-claude-code:test"
_SIDECAR_TAG = "bw-proxy-sidecar:test"
_FAKE_API = Path(__file__).parent / "fake_messages_api.py"
#: The workspace root the executor derives with identifier randomisation off — the fake
#: API scripts absolute paths under it, as the CLI's tools expect.
_WORKSPACE_ROOT = "/work/workspace"
_FAKE_KEY_ENV = "BW_TEST_FAKE_PROVIDER_KEY"


def _daemon_available() -> bool:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True
    )
    return probe.returncode == 0


def _build(tag: str, dockerfile: Path) -> str:
    build = subprocess.run(
        ["docker", "build", "-f", str(dockerfile), "-t", tag, str(_REPO_ROOT)],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.fail(
            f"image build failed for {dockerfile}:\n"
            f"--- stdout ---\n{build.stdout[-4000:]}\n--- stderr ---\n{build.stderr[-4000:]}"
        )
    return tag


@pytest.fixture(scope="module")
def images() -> tuple[str, str]:
    """Build the claude-code sandbox image and the proxy sidecar once; a build failure fails
    loudly — it is the point of the job."""
    if not _daemon_available():
        pytest.skip("no Docker daemon")
    usable, reason = overlay_available()
    if not usable:
        pytest.skip(f"no host-side overlay: {reason}")
    return (
        _build(_SANDBOX_TAG, _REPO_ROOT / "sandbox" / "claude-code" / "Dockerfile"),
        _build(_SIDECAR_TAG, _REPO_ROOT / "sidecar" / "proxy" / "Dockerfile"),
    )


def _host_ip_for_containers() -> str:
    """The host as the sidecar reaches it from its egress bridge: the default bridge gateway."""
    probe = subprocess.run(
        ["docker", "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return probe.stdout.strip()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("0.0.0.0", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    root = tmp_path / "demo-skill"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Demo skill that reads the README and writes notes.\n"
        "---\nRead README.md then write notes.md.\n",
        encoding="utf-8",
    )
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n  - id: take-notes\n    expectation: should_trigger\n"
        '    prompt: "Use the demo-skill to take notes."\n    assert:\n'
        "      - skill_activated: true\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def fixture_source(tmp_path: Path) -> Path:
    source = tmp_path / "fixture"
    source.mkdir()
    (source / "README.md").write_text("# project\nhello world\n", encoding="utf-8")
    return source


def test_the_real_cli_runs_in_the_sandbox_behind_the_proxy(
    images: tuple[str, str], skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    sandbox_image, sidecar_image = images
    host_ip = _host_ip_for_containers()
    port = _free_port()
    base_url = f"http://{host_ip}:{port}"
    server = subprocess.Popen(
        [sys.executable, str(_FAKE_API), str(port), "0.0.0.0"],
        env={**os.environ, "FAKE_WS": _WORKSPACE_ROOT},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    # The "real" key the sidecar injects, forwarded into the sidecar by env name (§10.5.1).
    os.environ[_FAKE_KEY_ENV] = "sk-real-fake-provider-key"
    try:
        broker = CredentialBroker.for_run(
            {"anthropic": _FAKE_KEY_ENV}, os.environ, rng=SeededRng(1, "claude-code-test")
        )
        proxy = SidecarProxyProvider(
            backend=DockerBackend(image=sandbox_image),
            image=sidecar_image,
            allowlist=EgressAllowlist(
                provider_endpoints=provider_hosts([base_url]),
                infrastructure_endpoints=frozenset(CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS),
            ),
            max_requests=50,
            max_request_bytes=1 << 20,
            broker=broker,
            provider_of_host=dict.fromkeys(provider_hosts([base_url]), "anthropic"),
        )
        package = load_skill(skill_dir)
        target = TargetInfo(harness="claude-code", provider="anthropic", model_alias="frontier")
        executor = SandboxRunExecutor(
            backend=DockerBackend(image=sandbox_image),
            package=package,
            fixture=fixture_source,
            client_factory=lambda _plan: (ScriptedClient([]), "fake-model-v1"),
            eval_id="wp17",
            run_root=tmp_path / "runs",
            proxy=proxy,
            randomize_identifiers=False,
            provider_base_urls={"anthropic": base_url},
        )
        scenario = Scenario(
            id="take-notes",
            expectation="should_trigger",
            prompt="Use the demo-skill to take notes.",
            assertions=[AssertionSpec(name="skill_activated", params=True)],
        )
        executed = executor.execute(RunPlan(scenario=scenario, target=target, repetition=1))
    finally:
        server.kill()
        server.wait()
        os.environ.pop(_FAKE_KEY_ENV, None)

    trace = executed.trace
    assert trace.is_complete
    assert trace.exit_reason == "completed", trace.footer
    assert trace.header.target.harness == "claude-code"
    assert trace.header.target.harness_version == "2.1.257"
    capabilities = trace.header.target.harness_capabilities or {}
    assert capabilities["trigger_metrics_portable"] is True
    assert capabilities["hooks_corroborated"] is True

    # The harness itself activated the skill and drove the tools; the hook stream agreed.
    assert len(trace.actions_of_kind("skill_activated")) == 1
    tools = [a.action["tool"] for a in trace.actions_of_kind("tool_call")]
    assert tools == ["Skill", "Read", "Write"]
    assert not trace.actions_of_kind("trace_inconsistency")
    assert trace.header.coverage.harness_events.fidelity == "full"

    # The model channel was observed at the proxy — and nothing else left.
    egress = trace.actions_on_plane("egress")
    assert egress, "the CLI's model calls must be visible as egress"
    classes = {a.action["egress_class"] for a in egress}
    assert classes == {"model_api"}, classes
    assert not trace.actions_of_kind("egress_blocked")
    assert trace.header.coverage.egress.fidelity == "full"

    # Plane B saw the write the CLI reported.
    writes = {a.action["path"]: a.action["zone"] for a in trace.actions_on_plane("filesystem")}
    assert (
        f"{_WORKSPACE_ROOT}/notes.md" in writes
        and writes[f"{_WORKSPACE_ROOT}/notes.md"] == "workspace"
    )

    # The real key never reached an artifact: neither the trace nor the run directory.
    assert "sk-real-fake-provider-key" not in executed.trace_jsonl
    for path in (tmp_path / "runs").rglob("*"):
        if path.is_file() and path.suffix in (".jsonl", ".json", ".log"):
            assert "sk-real-fake-provider-key" not in path.read_text(
                encoding="utf-8", errors="replace"
            )
