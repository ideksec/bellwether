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
            "canary_without_read": "warn",
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
            "canary_without_read": "warn",
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


def test_run_refuses_a_claude_code_target_with_no_proxy_wired(
    package: SkillPackage, tmp_path: Path
) -> None:
    """A `claude-code` target needs the recording proxy: the CLI's model calls originate inside
    the sandbox and have no route out but the proxy (§3.3 invariant 1). With no `egress.image`
    the run would spend a container to watch the CLI fail to reach any model, so the §16.4
    preflight refuses up front, naming the setting."""
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

    with pytest.raises(BellwetherError, match="reaches the model only through the recording proxy"):
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


def test_run_refuses_a_manifest_denied_tool_weighted_zero(tmp_path: Path) -> None:
    """§16.1 on the real path: weight 0 on a class the manifest denies erases it from the
    risk-weighted Jaccard, so a skill could use a tool its own manifest denies and still post a
    clean consistency score. The cross-document check (policy weights × manifest deny) refuses
    before the executor is built, alongside the §16.4 preflight."""
    root = tmp_path / "denier"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: denier\ndescription: d.\n---\nbody\n", encoding="utf-8"
    )
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n  - id: s\n    expectation: should_trigger\n"
        '    prompt: "go"\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    (root / "evals" / "manifest.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: SkillManifest\n"
        "metadata:\n  owner: team\n  criticality: low\n"
        "declared_scope:\n  tools:\n    deny: [curl]\n",
        encoding="utf-8",
    )
    package = load_skill(root)

    base = _policy()
    low = base.profile("low")
    metrics = low.metrics.model_copy(
        update={"capability_risk_weights": {**low.metrics.capability_risk_weights, "curl": 0.0}}
    )
    profile = low.model_copy(update={"metrics": metrics})
    policy = base.model_copy(update={"profiles": {**base.profiles, "low": profile}})

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        raise AssertionError("the executor must never be built for an invalid weight set")

    with pytest.raises(BellwetherError, match="denies"):
        run_evaluation(
            config=_config(),
            policy=policy,
            package=package,
            fixture=tmp_path / "fixture",
            environ=_ENVIRON,
            make_executor=make_executor,
            out_dir=tmp_path / "out",
            eval_id="e",
            created_at="2026-08-05T12:00:00Z",
            bellwether_version="0.1.0",
        )


def test_run_evaluation_stamps_each_scenarios_fixture_on_its_plans(tmp_path: Path) -> None:
    """§7.2 on the real path: with a resolver, every plan carries its scenario's own fixture and
    name, which the executor reads (and records as `sandbox.fixture`) — so a skill whose
    scenarios need different starting trees is expressible end to end."""
    from bellwether.cli.fixtures import fixture_resolver

    root = tmp_path / "two-fixtures"
    (root / "evals" / "fixtures" / "alpha").mkdir(parents=True)
    (root / "evals" / "fixtures" / "beta").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: two-fixtures\ndescription: d.\n---\nb\n", encoding="utf-8"
    )
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n"
        "  - id: a\n    expectation: should_trigger\n    fixture: alpha\n"
        '    prompt: "go"\n    assert:\n      - skill_activated: true\n'
        "  - id: b\n    expectation: should_trigger\n    fixture: beta\n"
        '    prompt: "go"\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    (root / "evals" / "manifest.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: SkillManifest\nmetadata:\n  owner: t\n  criticality: low\n",
        encoding="utf-8",
    )
    package = load_skill(root)
    seen: list[tuple[str, str | None, Path | None]] = []

    class _Recording(_ScriptedExecutor):
        def execute(self, plan: RunPlan) -> ExecutedRun:
            seen.append((plan.scenario.id, plan.fixture_name, plan.fixture))
            return super().execute(plan)

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        return _Recording(pkg, tmp_path, client_factory)

    run_evaluation(
        config=_config(),
        policy=_policy(),
        package=package,
        fixture=tmp_path / "default-fixture",
        environ=_ENVIRON,
        make_executor=make_executor,
        out_dir=tmp_path / "out",
        eval_id="e",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
        fixture_for=fixture_resolver(root, package.scenarios),  # type: ignore[arg-type]
    )
    assert {(s, n, p) for s, n, p in seen} == {
        ("a", "alpha", root / "evals" / "fixtures" / "alpha"),
        ("b", "beta", root / "evals" / "fixtures" / "beta"),
    }


def test_run_evaluation_honours_a_scenarios_own_look_schedule(tmp_path: Path) -> None:
    """§7.2 end to end: a scenario with `looks: [2, 4]` / `n_max: 4` runs four times (not the
    profile's twenty) and its set is aggregated under its own schedule, which the reading records
    so the summary counts "stopped at look k" against the schedule that actually ran."""
    root = tmp_path / "short"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: short\ndescription: d.\n---\nb\n", encoding="utf-8")
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n"
        "  - id: quick\n    expectation: should_trigger\n    looks: [2, 4]\n    n_max: 4\n"
        '    prompt: "go"\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    (root / "evals" / "manifest.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: SkillManifest\nmetadata:\n  owner: t\n  criticality: low\n",
        encoding="utf-8",
    )
    package = load_skill(root)
    holder: dict[str, _ScriptedExecutor] = {}

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        holder["exec"] = _ScriptedExecutor(pkg, tmp_path, client_factory)
        return holder["exec"]

    result = run_evaluation(
        config=_config(),
        policy=_policy(),
        package=package,
        fixture=tmp_path / "fixture",
        environ=_ENVIRON,
        make_executor=make_executor,
        out_dir=tmp_path / "out",
        eval_id="e",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
    )
    assert holder["exec"].calls == 4  # the scenario's n_max, not the profile's 20
    # The summary counts "stopped at look k" against the schedule the set actually ran: under
    # [2, 4] the one set is keyed "1" or "2". Before per-set schedules a stop at N = 4 — not a
    # profile look — was mis-keyed as the profile's last look, "3".
    stopped = result.summary.matrix.sets_stopped_at_look
    assert sum(stopped.values()) == 1
    assert set(stopped) <= {"1", "2"}


def test_run_refuses_a_multi_turn_scenario_on_a_claude_code_target(tmp_path: Path) -> None:
    """§7.3 × §16.4: the claude-code harness runs one prompt per session in this build, so a
    turn-list scenario on it is refused before any container — never flattened into one turn."""
    from bellwether.cli.orchestrator import TargetInfo
    from bellwether.cli.preflight import preflight_failures

    failures = preflight_failures(
        _config(),
        _policy().profile("low"),
        [TargetInfo("api-loop", "anthropic", "frontier")],
        multi_turn_scenario_ids=["chat"],
    )
    assert not any("chat" in f.gate for f in failures)  # api-loop runs multi-turn fine

    failures = preflight_failures(
        _config(),
        _policy().profile("low"),
        [TargetInfo("claude-code", "anthropic", "frontier")],
        multi_turn_scenario_ids=["chat"],
    )
    turn_failures = [f for f in failures if f.gate == "scenario[chat].prompt"]
    assert turn_failures
    assert "multi-turn" in turn_failures[0].remedy
    assert "api-loop" in turn_failures[0].remedy


def test_run_refuses_companion_skills_on_a_claude_code_target() -> None:
    """§7.4 × §16.4: the claude-code harness stages only the skill under test in this build, so
    companions would be undiscoverable and "which activated" a foregone conclusion — refused
    before any container rather than run with competitors the harness cannot see."""
    from bellwether.cli.orchestrator import TargetInfo
    from bellwether.cli.preflight import preflight_failures

    ok = preflight_failures(
        _config(),
        _policy().profile("low"),
        [TargetInfo("api-loop", "anthropic", "frontier")],
        companion_scenario_ids=["collide"],
    )
    assert not any("collide" in f.gate for f in ok)

    refused = preflight_failures(
        _config(),
        _policy().profile("low"),
        [TargetInfo("claude-code", "anthropic", "frontier")],
        companion_scenario_ids=["collide"],
    )
    companion_failures = [f for f in refused if f.gate == "scenario[collide].also_load_skills"]
    assert companion_failures
    assert "api-loop" in companion_failures[0].remedy


# ---------------------------------------------------------------------------
# --scenario / --tag filtering (§7.2, §20)
# ---------------------------------------------------------------------------


def _tagged_suite():  # type: ignore[no-untyped-def]
    from bellwether.config.models.scenarios import ScenarioSuite

    return ScenarioSuite.model_validate(
        {
            "apiVersion": "bellwether/v1",
            "kind": "ScenarioSuite",
            "scenarios": [
                {
                    "id": "auth",
                    "expectation": "should_trigger",
                    "prompt": "p",
                    "tags": ["security", "fast"],
                    "assert": [{"skill_activated": True}],
                },
                {
                    "id": "docs",
                    "expectation": "should_trigger",
                    "prompt": "p",
                    "tags": ["docs"],
                    "assert": [{"skill_activated": True}],
                },
                {
                    "id": "leak",
                    "expectation": "should_trigger",
                    "prompt": "p",
                    "tags": ["security"],
                    "assert": [{"skill_activated": True}],
                },
            ],
        }
    )


def test_select_scenarios_by_id_tag_and_both() -> None:
    from bellwether.cli.run import select_scenarios

    suite = _tagged_suite()
    ids = lambda picked: [s.id for s in picked]  # noqa: E731
    assert ids(select_scenarios(suite.scenarios)) == ["auth", "docs", "leak"]  # no filter
    assert ids(select_scenarios(suite.scenarios, scenario_ids=["leak"])) == ["leak"]
    # A tag selects every scenario carrying it, in suite order.
    assert ids(select_scenarios(suite.scenarios, tags=["security"])) == ["auth", "leak"]
    # Any-of across tags; both filters intersect.
    assert ids(select_scenarios(suite.scenarios, tags=["docs", "fast"])) == ["auth", "docs"]
    assert ids(
        select_scenarios(suite.scenarios, scenario_ids=["auth", "docs"], tags=["security"])
    ) == ["auth"]


def test_a_filter_that_selects_nothing_refuses_naming_what_exists() -> None:
    """An empty selection run to completion would be a clean-looking verdict about no evidence."""
    from bellwether.cli.run import select_scenarios

    suite = _tagged_suite()
    with pytest.raises(BellwetherError, match="selects no scenarios") as excinfo:
        select_scenarios(suite.scenarios, tags=["nonexistent"])
    assert "security" in str(excinfo.value)  # names the tags that do exist
    with pytest.raises(BellwetherError, match="does not define"):
        select_scenarios(suite.scenarios, scenario_ids=["ghost"])


def test_run_evaluation_runs_only_the_selected_scenario(tmp_path: Path) -> None:
    root = tmp_path / "two"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: two\ndescription: d.\n---\nb\n", encoding="utf-8")
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n"
        "  - id: a\n    expectation: should_trigger\n    tags: [keep]\n"
        '    prompt: "go"\n    assert:\n      - skill_activated: true\n'
        "  - id: b\n    expectation: should_trigger\n"
        '    prompt: "go"\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    (root / "evals" / "manifest.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: SkillManifest\nmetadata:\n  owner: t\n  criticality: low\n",
        encoding="utf-8",
    )
    package = load_skill(root)
    seen: set[str] = set()

    class _Recording(_ScriptedExecutor):
        def execute(self, plan: RunPlan) -> ExecutedRun:
            seen.add(plan.scenario.id)
            return super().execute(plan)

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        return _Recording(pkg, tmp_path, client_factory)

    run_evaluation(
        config=_config(),
        policy=_policy(),
        package=package,
        fixture=tmp_path / "fixture",
        environ=_ENVIRON,
        make_executor=make_executor,
        out_dir=tmp_path / "out",
        eval_id="e",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
        tags=["keep"],
    )
    assert seen == {"a"}


# ---------------------------------------------------------------------------
# §20 matrix options: --targets, --n-max/--looks, --repetitions (fixed mode)
# ---------------------------------------------------------------------------


def _resolved():  # type: ignore[no-untyped-def]
    from bellwether.cli.run_plan import resolve_run

    return resolve_run(_config(), _policy(), None, environ=_ENVIRON, profile_override="low")


def test_targets_filters_by_alias_and_refuses_when_nothing_matches() -> None:
    from bellwether.cli.run import apply_matrix_options

    resolved = _resolved()
    kept = apply_matrix_options(resolved, target_aliases=["frontier"])
    assert [rt.target.model_alias for rt in kept.targets] == ["frontier"]
    with pytest.raises(BellwetherError, match="frontier"):
        apply_matrix_options(resolved, target_aliases=["nope"])


def test_n_max_and_looks_override_the_matrix_under_the_schedule_rule() -> None:
    from bellwether.cli.run import apply_matrix_options

    resolved = _resolved()  # low profile: looks [6, 12, 20], n_max 20
    assert apply_matrix_options(resolved, n_max_override=12).looks == (6, 12)
    both = apply_matrix_options(resolved, looks_override=[2, 4], n_max_override=4)
    assert (both.looks, both.n_max) == ((2, 4), 4)
    only_looks = apply_matrix_options(resolved, looks_override=[3, 9])
    assert (only_looks.looks, only_looks.n_max) == ((3, 9), 9)  # n_max defaults to the last look
    with pytest.raises(BellwetherError, match="n_max"):
        apply_matrix_options(resolved, n_max_override=10)  # not a pre-registered look


def test_repetitions_forces_a_single_look_and_excludes_the_other_overrides() -> None:
    from bellwether.cli.run import apply_matrix_options

    resolved = _resolved()
    fixed = apply_matrix_options(resolved, repetitions=3)
    assert (fixed.looks, fixed.n_max) == ((3,), 3)
    with pytest.raises(BellwetherError, match="cannot be combined"):
        apply_matrix_options(resolved, repetitions=3, n_max_override=3)
    with pytest.raises(BellwetherError, match="at least two"):
        apply_matrix_options(resolved, repetitions=1)


def test_fixed_mode_runs_exactly_n_times_and_is_descriptive_only(
    package: SkillPackage, tmp_path: Path
) -> None:
    """§13.1 / §16.2 rule 6 end to end: `--repetitions 3` runs three times (not the profile's 20)
    and the verdict is descriptive_only — it can never be `ready`, because a fixed-N run makes no
    sequential decision and licenses no gate-eligible interval."""
    holder: dict[str, _ScriptedExecutor] = {}

    def make_executor(pkg, fixture, client_factory):  # type: ignore[no-untyped-def]
        holder["exec"] = _ScriptedExecutor(pkg, tmp_path, client_factory)
        return holder["exec"]

    result = run_evaluation(
        config=_config(),
        policy=_policy(),
        package=package,
        fixture=tmp_path / "fixture",
        environ=_ENVIRON,
        make_executor=make_executor,
        out_dir=tmp_path / "out",
        eval_id="e",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
        repetitions=3,
    )
    assert holder["exec"].calls == 3
    assert result.verdict.descriptive_only is True
    assert result.verdict.verdict != "ready"
