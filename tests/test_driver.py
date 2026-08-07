"""The evaluation driver: matrix planning and the execute→analyse→aggregate loop (§4, §13).

`plan_matrix` and `drive_evaluation` are the bridge the CLI `run` sits on. Both are tested offline
with a replay executor — one real scripted `ExecutedRun` stands in for the sandbox half, the same way
the orchestrator test does — so the matrix ordering, the per-set grouping, and the determinism are
pinned without a container.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from bellwether.cli.orchestrator import (
    ExecutedRun,
    RunPlan,
    TargetInfo,
    drive_evaluation,
    plan_matrix,
)
from bellwether.config import template_path
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.config.policy_loader import parse_policy
from bellwether.errors import BellwetherError
from bellwether.harness import (
    ApiLoopAdapter,
    ExecResult,
    ModelTurn,
    OfferedSkill,
    RunLimits,
    SandboxToolset,
    ScriptedClient,
    ToolCallRequest,
    TurnUsage,
)
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

_WORKSPACE = "/home/agent/workspace"
_SKILL = OfferedSkill(name="security-review", description="Reviews code.", body="# body\n")
_TRANSCRIPT = [
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=120, output=40),
        tool_calls=(ToolCallRequest(id="t1", name="skill", input={"name": "security-review"}),),
    ),
    ModelTurn(text="done", usage=TurnUsage(input=90, output=10)),
]


class _InProcessExec:
    def __call__(self, argv: list[str], *, stdin: str | None = None, timeout: float) -> ExecResult:
        return ExecResult(exit_code=0, stdout="", stderr="")


def _fixed_clock():  # type: ignore[no-untyped-def]
    start = dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.UTC)
    state = {"tick": 0}

    def read() -> dt.datetime:
        instant = start + dt.timedelta(seconds=state["tick"])
        state["tick"] += 1
        return instant

    return read


def _executed_run(tmp_path: Path) -> ExecutedRun:
    """One deterministic scripted run assembled into an `ExecutedRun` — a single trace can back
    every plan, because `analyse_run` keys each run by its plan, not by the trace header."""
    adapter = ApiLoopAdapter(
        ScriptedClient(_TRANSCRIPT, model_id_reported="model-as-served"),
        SandboxToolset(_InProcessExec()),
        skills=(_SKILL,),
        clock=_fixed_clock(),
    )
    events = list(adapter.run("Review.", model_id="frontier-configured", limits=RunLimits()))
    exit_reason = exit_reason_from_events(events)
    header = RunHeader(
        run_id="r",
        eval_id="e",
        scenario_id="s",
        repetition=1,
        skill=SkillRef(
            name="security-review",
            package_digest="sha256:" + "a" * 64,
            payload_digest="sha256:" + "b" * 64,
            source="t",
        ),
        target=TargetRef(
            harness=adapter.name,
            harness_version=adapter.version(),
            provider="scripted",
            model_alias="frontier",
            model_id_requested="frontier-configured",
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
        exit_reason=exit_reason,
        tokens=token_totals_from_events(events),
    )
    path = write_trace(tmp_path / "run.jsonl", header, harness_actions(events), footer)
    return ExecutedRun(
        trace=read_trace(path),
        context=NormalizationContext(workspace_root=_WORKSPACE),
        trace_jsonl=path.read_text(encoding="utf-8"),
    )


def _firstlight_profile():  # type: ignore[no-untyped-def]
    import yaml

    data = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    profile = data.profile("low")
    security = profile.gates.security_runtime.model_copy(
        update={"egress_outside_allowlist": "warn", "dns_outside_allowlist": "warn"}
    )
    gates = profile.gates.model_copy(update={"security_runtime": security})
    return profile.model_copy(update={"gates": gates})


def _scenario(scenario_id: str) -> Scenario:
    return Scenario(
        id=scenario_id,
        expectation="should_trigger",
        prompt="Review.",
        assertions=[AssertionSpec(name="skill_activated", params=True)],
    )


class _ReplayExecutor:
    """Returns one canned `ExecutedRun` for every plan, counting the calls."""

    def __init__(self, executed: ExecutedRun) -> None:
        self.executed = executed
        self.plans: list[RunPlan] = []

    def execute(self, plan: RunPlan) -> ExecutedRun:
        self.plans.append(plan)
        return self.executed


# ---------------------------------------------------------------------------
# plan_matrix
# ---------------------------------------------------------------------------


def test_plan_matrix_expands_scenarios_targets_and_repetitions_in_order() -> None:
    scenarios = [_scenario("alpha"), _scenario("beta")]
    targets = [
        TargetInfo(harness="api-loop", provider="p", model_alias="frontier"),
        TargetInfo(harness="api-loop", provider="p", model_alias="small"),
    ]
    plans = plan_matrix(scenarios, targets, repetitions=3)

    assert len(plans) == 2 * 2 * 3
    # Fixed order: scenario, then target, then repetition.
    head = [(p.scenario.id, p.target.model_alias, p.repetition) for p in plans[:4]]
    assert head == [
        ("alpha", "frontier", 1),
        ("alpha", "frontier", 2),
        ("alpha", "frontier", 3),
        ("alpha", "small", 1),
    ]


def test_plan_matrix_refuses_a_zero_length_set() -> None:
    with pytest.raises(BellwetherError, match="at least one run"):
        plan_matrix([_scenario("a")], [TargetInfo("api-loop", "p", "frontier")], repetitions=0)


# ---------------------------------------------------------------------------
# drive_evaluation
# ---------------------------------------------------------------------------


def test_drive_evaluation_groups_runs_into_one_reading_per_set(tmp_path: Path) -> None:
    executor = _ReplayExecutor(_executed_run(tmp_path))
    scenarios = [_scenario("alpha"), _scenario("beta")]
    targets = [TargetInfo("api-loop", "p", "frontier"), TargetInfo("api-loop", "p", "small")]
    plans = plan_matrix(scenarios, targets, repetitions=4)

    readings = drive_evaluation(plans, executor, profile=_firstlight_profile())

    # One reading per (scenario, target) set — 2 × 2 — each aggregating its 4 runs.
    assert len(readings) == 4
    assert len(executor.plans) == 16  # every plan executed exactly once
    assert all(len(reading.runs) == 4 for reading in readings)


def test_drive_evaluation_preserves_first_seen_set_order(tmp_path: Path) -> None:
    """Readings must come back in plan_matrix order, so the verdict and artifact tree are
    deterministic regardless of how plans interleave."""
    executor = _ReplayExecutor(_executed_run(tmp_path))
    scenarios = [_scenario("alpha"), _scenario("beta")]
    targets = [TargetInfo("api-loop", "p", "frontier")]
    plans = plan_matrix(scenarios, targets, repetitions=6)

    readings = drive_evaluation(plans, executor, profile=_firstlight_profile())

    assert [reading.scenario_id for reading in readings] == ["alpha", "beta"]


def test_a_driven_set_carries_the_passing_outcome_through(tmp_path: Path) -> None:
    """The scripted run activates the skill and completes, so the aggregated set is consistent —
    the driver faithfully carries per-run analysis into the reading, not just the count."""
    executor = _ReplayExecutor(_executed_run(tmp_path))
    plans = plan_matrix(
        [_scenario("alpha")], [TargetInfo("api-loop", "p", "frontier")], repetitions=6
    )

    (reading,) = drive_evaluation(plans, executor, profile=_firstlight_profile())

    assert reading.pass_rate == 1.0
