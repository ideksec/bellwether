"""`run_evaluation` — the whole `bellwether run` pipeline, offline (§20, §16).

The executor is injected, so resolution → matrix → drive → orchestrate → verdict → artifact tree all
run without a container: a scripted `api-loop` executor stands in for the sandbox half, exactly as the
first-light checkpoint does. This is `benign-stable` reaching a verdict from the top-level entry point,
one seam short of a real container.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from pathlib import Path

import pytest

from bellwether.cli.orchestrator import ExecutedRun, RunPlan
from bellwether.cli.run import policy_digest, run_evaluation
from bellwether.config.models.common import Target
from bellwether.config.models.config import Config, SandboxConfig
from bellwether.config.models.policy import Policy, Selection
from bellwether.config.models.provider import ProviderConfig
from bellwether.errors import BellwetherError
from bellwether.harness import (
    ApiLoopAdapter,
    ExecResult,
    ModelClient,
    ModelTurn,
    OfferedSkill,
    RunLimits,
    SandboxToolset,
    ScriptedClient,
    ToolCallRequest,
    TurnUsage,
)
from bellwether.skill import SkillPackage, load_skill
from bellwether.trace import (
    Coverage,
    NormalizationContext,
    PlaneCoverage,
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
    exit_reason_from_events,
    harness_actions,
    read_trace,
    token_totals_from_events,
    write_trace,
)

_API = {"apiVersion": "bellwether/v1"}
_KEY_ENV = "ANTHROPIC_API_KEY"
_ENVIRON = {_KEY_ENV: "sk-real-value"}
_TRANSCRIPT = [
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=120, output=40),
        tool_calls=(ToolCallRequest(id="t1", name="skill", input={"name": "security-review"}),),
    ),
    ModelTurn(text="done", usage=TurnUsage(input=90, output=10)),
]


# ---------------------------------------------------------------------------
# fixtures: a real on-disk skill, and config/policy objects
# ---------------------------------------------------------------------------


@pytest.fixture
def package(tmp_path: Path) -> SkillPackage:
    root = tmp_path / "security-review"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: security-review\ndescription: Reviews code.\n---\nbody\n", encoding="utf-8"
    )
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n  - id: benign-stable\n    expectation: should_trigger\n"
        '    prompt: "Review this project."\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    (root / "evals" / "manifest.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: SkillManifest\n"
        "metadata:\n  owner: team\n  criticality: low\n",
        encoding="utf-8",
    )
    return load_skill(root)


def _config() -> Config:
    return Config(
        **_API,
        kind="Config",
        providers={
            "anthropic": ProviderConfig(
                type="anthropic", api_key_env=_KEY_ENV, models={"frontier": "a-real-model-id"}
            )
        },
        sandbox=SandboxConfig(image="img@sha256:" + "d" * 64),
    )


def _policy() -> Policy:
    """The shipped 'low' profile — real, calibrated thresholds — with a target injected into its
    matrix and egress/DNS demoted to warn (the first-light configuration where those planes don't
    exist yet). Building a ProfileSpec by hand uses model defaults that are not a sensible profile."""
    import yaml

    from bellwether.config import template_path
    from bellwether.config.policy_loader import parse_policy

    shipped = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    low = shipped.profile("low")
    matrix = low.matrix.model_copy(
        update={
            "required_targets": [
                Target(harness="api-loop", provider="anthropic", model_alias="frontier")
            ]
        }
    )
    security = low.gates.security_runtime.model_copy(
        update={
            "egress_outside_allowlist": "warn",
            "dns_outside_allowlist": "warn",
            "canary_leak": "warn",
        }
    )
    gates = low.gates.model_copy(update={"security_runtime": security})
    profile = low.model_copy(update={"matrix": matrix, "gates": gates})
    return shipped.model_copy(update={"profiles": {**shipped.profiles, "low": profile}})


# ---------------------------------------------------------------------------
# a scripted executor factory that stamps each plan into its trace
# ---------------------------------------------------------------------------


def _fixed_clock():  # type: ignore[no-untyped-def]
    start = dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.UTC)
    state = {"tick": 0}

    def read() -> dt.datetime:
        instant = start + dt.timedelta(seconds=state["tick"])
        state["tick"] += 1
        return instant

    return read


class _NoopExec:
    def __call__(self, argv: list[str], *, stdin: str | None = None, timeout: float) -> ExecResult:
        return ExecResult(exit_code=0, stdout="", stderr="")


class _ScriptedExecutor:
    """Stands in for `SandboxRunExecutor`: runs the scripted `api-loop` and stamps the plan into the
    trace header, so `analyse_run`'s trace-to-plan binding is satisfied. It *calls the injected client
    factory* per plan, so the real credential path (build_model_client) is exercised for the run."""

    def __init__(
        self,
        package: SkillPackage,
        tmp_path: Path,
        client_factory: Callable[[RunPlan], tuple[ModelClient, str]],
    ) -> None:
        self.package = package
        self.tmp_path = tmp_path
        self.client_factory = client_factory
        self.calls = 0

    def execute(self, plan: RunPlan) -> ExecutedRun:
        self.calls += 1
        _client, model_id = self.client_factory(plan)  # exercises build_model_client + key lookup
        adapter = ApiLoopAdapter(
            ScriptedClient(_TRANSCRIPT, model_id_reported="model-as-served"),
            SandboxToolset(_NoopExec()),
            skills=(OfferedSkill(name="security-review", description="d", body="b"),),
            clock=_fixed_clock(),
        )
        events = list(adapter.run("Review this project.", model_id=model_id, limits=RunLimits()))
        header = RunHeader(
            run_id=f"{plan.scenario.id}-{plan.target.slug}-{plan.repetition:03d}",
            eval_id="e",
            scenario_id=plan.scenario.id,
            repetition=plan.repetition,
            skill=SkillRef(
                name=self.package.name,
                package_digest=self.package.package_digest,
                payload_digest=self.package.payload_digest,
                source="t",
            ),
            target=TargetRef(
                harness=plan.target.harness,
                harness_version=adapter.version(),
                provider=plan.target.provider,
                model_alias=plan.target.model_alias,
                model_id_requested=model_id,
                model_id_reported="model-as-served",
                harness_capabilities=adapter.capabilities().as_record(),
            ),
            sandbox=SandboxRef(image="scripted@sha256:" + "2" * 64, isolation="none"),
            coverage=Coverage(
                harness_events=PlaneCoverage(fidelity="full"),
                filesystem_writes=PlaneCoverage(fidelity="unavailable", reason="scripted"),
            ),
            started_at=dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.UTC),
        )
        footer = RunFooter(
            ended_at=dt.datetime(2026, 8, 5, 12, 5, 0, tzinfo=dt.UTC),
            wall_clock_ms=300_000,
            exit_reason=exit_reason_from_events(events),
            tokens=token_totals_from_events(events),
        )
        path = write_trace(
            self.tmp_path / f"run-{self.calls}.jsonl", header, harness_actions(events), footer
        )
        return ExecutedRun(
            trace=read_trace(path),
            context=NormalizationContext(workspace_root="/home/agent/workspace"),
            trace_jsonl=path.read_text(encoding="utf-8"),
        )


def _evaluate(package: SkillPackage, tmp_path: Path, *, environ=_ENVIRON):  # type: ignore[no-untyped-def]
    holder: dict[str, _ScriptedExecutor] = {}

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        holder["exec"] = _ScriptedExecutor(pkg, tmp_path, client_factory)
        return holder["exec"]

    result = run_evaluation(
        config=_config(),
        policy=_policy(),
        package=package,
        fixture=tmp_path / "fixture",
        environ=environ,
        make_executor=make_executor,
        out_dir=tmp_path / "out",
        eval_id="firstlight",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
    )
    return result, holder["exec"]


# ---------------------------------------------------------------------------
# the pipeline, end to end
# ---------------------------------------------------------------------------


def _weakened_config() -> Config:
    """`_config()` with a §21-enforced setting turned off (model-API body scanning)."""
    cfg = _config()
    return cfg.model_copy(
        update={"egress": cfg.egress.model_copy(update={"scan_model_api_bodies": False})}
    )


def _policy_with_target_in(profile_name: str) -> Policy:
    """The shipped policy with the run target injected into ``profile_name`` (which `_policy`
    only wires into 'low'), so a non-low profile can actually resolve a target."""
    pol = _policy()
    with_target = pol.profile("low")  # already carries the injected target + warn dispositions
    return pol.model_copy(update={"profiles": {**pol.profiles, profile_name: with_target}})


def test_run_refuses_a_disabled_enforced_setting_above_low(
    package: SkillPackage, tmp_path: Path
) -> None:
    # BW-02 / §21: with model-API body scanning off, a run above the 'low' profile must be
    # refused before it spends — the guarantee the threat model advertises but `run` lacked.
    from bellwether.errors import BellwetherError

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        return _ScriptedExecutor(pkg, tmp_path, client_factory)

    with pytest.raises(BellwetherError, match="enforced setting"):
        run_evaluation(
            config=_weakened_config(),
            policy=_policy_with_target_in("medium"),
            package=package,
            fixture=tmp_path / "fixture",
            environ=_ENVIRON,
            make_executor=make_executor,
            out_dir=tmp_path / "out",
            eval_id="firstlight",
            created_at="2026-08-05T12:00:00Z",
            bellwether_version="0.1.0",
            profile_override="medium",
        )


def test_run_allows_a_disabled_enforced_setting_at_low(
    package: SkillPackage, tmp_path: Path
) -> None:
    # §21 emits a finding at 'low' but does NOT refuse — the low profile is the escape hatch.
    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        return _ScriptedExecutor(pkg, tmp_path, client_factory)

    result = run_evaluation(
        config=_weakened_config(),
        policy=_policy(),
        package=package,
        fixture=tmp_path / "fixture",
        environ=_ENVIRON,
        make_executor=make_executor,
        out_dir=tmp_path / "out",
        eval_id="firstlight",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
        profile_override="low",
    )
    assert result.verdict.verdict in {"ready", "conditional", "not_ready"}


def _policy_keeping_block_dispositions() -> Policy:
    """The shipped 'low' profile with the run target injected but the egress/DNS `block`
    dispositions LEFT AS SHIPPED — the scaffold-default configuration a new user runs with."""
    import yaml

    from bellwether.config import template_path
    from bellwether.config.policy_loader import parse_policy

    shipped = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    low = shipped.profile("low")
    matrix = low.matrix.model_copy(
        update={
            "required_targets": [
                Target(harness="api-loop", provider="anthropic", model_alias="frontier")
            ]
        }
    )
    profile = low.model_copy(update={"matrix": matrix})
    return shipped.model_copy(update={"profiles": {**shipped.profiles, "low": profile}})


def test_run_refuses_a_blocking_egress_gate_with_no_proxy_wired(
    package: SkillPackage, tmp_path: Path
) -> None:
    """§16.4 / BW-51: the scaffold default blocks on egress, and a config with no
    `egress.image` wires no proxy — that matrix would run to completion and then block on an
    unobserved plane, spending the whole budget to learn the policy could never pass. The
    preflight must refuse it before the executor is even built."""
    built: list[str] = []

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        built.append("built")
        return _ScriptedExecutor(pkg, tmp_path, client_factory)

    with pytest.raises(BellwetherError, match=r"egress\.image") as excinfo:
        run_evaluation(
            config=_config(),
            policy=_policy_keeping_block_dispositions(),
            package=package,
            fixture=tmp_path / "fixture",
            environ=_ENVIRON,
            make_executor=make_executor,
            out_dir=tmp_path / "out",
            eval_id="firstlight",
            created_at="2026-08-05T12:00:00Z",
            bellwether_version="0.1.0",
        )
    assert "Cannot start" in str(excinfo.value)
    # Both unobservable blocking channels are named in one refusal, not one per attempt.
    assert "dns.image" in str(excinfo.value)
    assert built == []  # refused before anything was constructed, let alone paid for


def test_run_refuses_a_profile_requiring_planes_the_runner_lacks(
    package: SkillPackage, tmp_path: Path
) -> None:
    """§16.4 combo 2 on the real path: the high profile requires the process and read planes,
    which are not built in this version — refuse up front, naming each missing plane."""
    import yaml

    from bellwether.config import template_path
    from bellwether.config.policy_loader import parse_policy

    shipped = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    high = shipped.profile("high")
    matrix = high.matrix.model_copy(
        update={
            "required_targets": [
                Target(harness="api-loop", provider="anthropic", model_alias="frontier")
            ]
        }
    )
    security = high.gates.security_runtime.model_copy(
        update={
            "egress_outside_allowlist": "warn",
            "dns_outside_allowlist": "warn",
            "canary_leak": "warn",
        }
    )
    gates = high.gates.model_copy(update={"security_runtime": security})
    profile = high.model_copy(update={"matrix": matrix, "gates": gates})
    policy = shipped.model_copy(update={"profiles": {**shipped.profiles, "high": profile}})

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        raise AssertionError("the executor must never be built for an unsatisfiable profile")

    with pytest.raises(BellwetherError, match=r"capture_planes\[process\]"):
        run_evaluation(
            config=_config(),
            policy=policy,
            package=package,
            fixture=tmp_path / "fixture",
            environ=_ENVIRON,
            make_executor=make_executor,
            out_dir=tmp_path / "out",
            eval_id="firstlight",
            created_at="2026-08-05T12:00:00Z",
            bellwether_version="0.1.0",
            profile_override="high",
        )


def test_run_refuses_a_target_with_no_shipped_adapter(
    package: SkillPackage, tmp_path: Path
) -> None:
    """A `claude-code` target has no adapter in this build. Pre-preflight it ran the whole
    sandbox under the api-loop adapter and then died on the trace-to-plan binding ("does not
    match the run plan") — money spent, wrong error. Now it refuses up front, naming WP-17."""
    pol = _policy()
    low = pol.profile("low")
    matrix = low.matrix.model_copy(
        update={
            "required_targets": [
                Target(harness="claude-code", provider="anthropic", model_alias="frontier")
            ]
        }
    )
    profile = low.model_copy(update={"matrix": matrix})
    policy = pol.model_copy(update={"profiles": {**pol.profiles, "low": profile}})

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        raise AssertionError("the executor must never be built for a target with no adapter")

    with pytest.raises(BellwetherError, match="no adapter for harness 'claude-code'"):
        run_evaluation(
            config=_config(),
            policy=policy,
            package=package,
            fixture=tmp_path / "fixture",
            environ=_ENVIRON,
            make_executor=make_executor,
            out_dir=tmp_path / "out",
            eval_id="firstlight",
            created_at="2026-08-05T12:00:00Z",
            bellwether_version="0.1.0",
        )


def test_run_evaluation_produces_a_verdict_and_an_artifact_tree(
    package: SkillPackage, tmp_path: Path
) -> None:
    result, executor = _evaluate(package, tmp_path)

    # benign-stable: every evaluable gate passes; egress not_evaluable (no proxy in this path) →
    # conditional, exit 0. The full n_max was run.
    assert result.verdict.verdict == "conditional"
    assert result.exit_code == 0
    assert executor.calls == _policy().profile("low").matrix.n_max
    assert result.artifacts.summary_json.exists()


def test_run_evaluation_refuses_a_missing_api_key(package: SkillPackage, tmp_path: Path) -> None:
    with pytest.raises(BellwetherError, match=_KEY_ENV):
        _evaluate(package, tmp_path, environ={})


def test_run_evaluation_refuses_a_skill_without_scenarios(tmp_path: Path) -> None:
    root = tmp_path / "no-scenarios"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: no-scenarios\ndescription: d\n---\nb\n", encoding="utf-8"
    )
    (root / "evals" / "manifest.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: SkillManifest\nmetadata:\n  owner: t\n  criticality: low\n",
        encoding="utf-8",
    )
    with pytest.raises(BellwetherError, match="no scenarios"):
        _evaluate(load_skill(root), tmp_path)


def test_the_policy_digest_changes_with_the_policy(package: SkillPackage) -> None:
    a = _policy()
    b = a.model_copy(update={"selection": Selection(by_criticality={"low": "low"})})
    assert policy_digest(a) != policy_digest(b)
    assert policy_digest(a).startswith("sha256:")
