"""The first-light checkpoint: benign-stable end to end in a real sandbox (§25).

This is the skeleton walking. The sandbox execution driver runs a ``benign-stable``-shaped
skill through a real container six times, the analysis orchestrator turns those six traces
into a verdict, and the artifact tree lands on disk — proxy and resolver bypassed, egress
reported ``not_evaluable`` with a reason. The model side is scripted (no live provider until
WP-13); everything below it is real: overlay mount, container exec, two-plane capture.

Needs Docker and root, like every capture test — mounting the host-side overlay upper
directory is the privilege the host has and the container does not (§10.0).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bellwether.cli.execution import SandboxRunExecutor
from bellwether.cli.orchestrator import RunPlan, TargetInfo, aggregate, analyse_run, orchestrate
from bellwether.config import template_path
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.config.policy_loader import parse_policy
from bellwether.harness import ModelTurn, ScriptedClient, ToolCallRequest, TurnUsage
from bellwether.sandbox import DockerBackend, overlay_available
from bellwether.skill import load_skill

pytestmark = pytest.mark.docker

TEST_IMAGE = os.environ.get("BELLWETHER_TEST_IMAGE", "mcr.microsoft.com/cbl-mariner/base/core:2.0")

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
    (source / "src").mkdir(parents=True)
    (source / "src" / "auth.py").write_text("def login(): ...\n", encoding="utf-8")
    (source / "README.md").write_text("# project\n", encoding="utf-8")
    return source


def _firstlight_profile() -> object:
    import yaml

    data = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    profile = data.profile("low")
    security = profile.gates.security_runtime.model_copy(
        update={"egress_outside_allowlist": "warn", "dns_outside_allowlist": "warn"}
    )
    gates = profile.gates.model_copy(update={"security_runtime": security})
    return profile.model_copy(update={"gates": gates})


def _scenario() -> Scenario:
    return Scenario(
        id="benign-stable",
        expectation="should_trigger",
        prompt="Review this project.",
        assertions=[AssertionSpec(name="skill_activated", params=True)],
    )


def _client_factory(_plan: RunPlan) -> tuple[ScriptedClient, str]:
    return ScriptedClient(_TRANSCRIPT, model_id_reported="model-as-served"), "frontier-configured"


def test_benign_stable_walks_end_to_end_in_a_real_sandbox(
    backend: DockerBackend, skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    package = load_skill(skill_dir)
    target = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")
    executor = SandboxRunExecutor(
        backend=backend,
        package=package,
        fixture=fixture_source,
        client_factory=_client_factory,
        eval_id="firstlight",
        run_root=tmp_path / "runs",
    )
    scenario = _scenario()
    profile = _firstlight_profile()

    analysed = []
    for repetition in range(1, 7):
        plan = RunPlan(scenario=scenario, target=target, repetition=repetition)
        executed = executor.execute(plan)
        # Each run is a real two-plane trace: the skill activated, and the write landed in
        # the workspace zone (Plane B, which only a mounted overlay can see).
        assert executed.trace.is_complete
        assert executed.trace.exit_reason == "completed"
        assert len(executed.trace.actions_of_kind("skill_activated")) == 1
        fs = {
            a.action["path"]: a.action["zone"]
            for a in executed.trace.actions_on_plane("filesystem")
        }
        assert any(path.endswith("report.md") and zone == "workspace" for path, zone in fs.items())
        analysed.append(analyse_run(plan, executed, scope=None))

    reading = aggregate("benign-stable", target, analysed, profile=profile)  # type: ignore[arg-type]
    result = orchestrate(
        skill_name="security-review",
        package_digest=package.package_digest,
        payload_digest=package.payload_digest,
        criticality="high",
        profile_name="low",
        profile=profile,  # type: ignore[arg-type]
        policy_digest="sha256:" + "c" * 64,
        readings=[reading],
        eval_id="firstlight",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
        out_dir=tmp_path / "out",
    )

    # The skeleton walked: a verdict was produced from real runs, and it is conditional —
    # every evaluable gate passed, but egress cannot be evaluated until the proxy lands.
    assert result.verdict.verdict == "conditional"
    assert result.exit_code == 0
    egress = [g for g in result.verdict.gates if "egress" in g.name]
    assert egress and egress[0].status == "not_evaluable"

    # The artifact tree is on disk, with six real traces filed under the scenario/target.
    assert result.artifacts.summary_json.exists()
    assert len(result.artifacts.traces) == 6
    assert result.summary.consistency.bci >= 90
