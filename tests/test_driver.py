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
from bellwether.config.models.manifest import DeclaredScope, ToolScope
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
# Activates the skill, then reads a file with the `read` tool. A manifest that declares only the
# `skill` tool leaves `read` undeclared, so §12.5 scope evaluation marks it exceeded — the material
# the BW-47 regression test drives through the live path.
_SCOPE_VIOLATION_TRANSCRIPT = [
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=120, output=40),
        tool_calls=(ToolCallRequest(id="t1", name="skill", input={"name": "security-review"}),),
    ),
    ModelTurn(
        stop_reason="tool_use",
        usage=TurnUsage(input=100, output=30),
        tool_calls=(ToolCallRequest(id="t2", name="read", input={"path": "/etc/hostname"}),),
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


def _executed_run(
    plan: RunPlan, tmp_path: Path, index: int, transcript: list[ModelTurn] | None = None
) -> ExecutedRun:
    """A scripted run whose trace header is stamped from the plan — as the real executor builds it,
    so `analyse_run`'s trace-to-plan binding is satisfied. Each plan gets its own trace file."""
    adapter = ApiLoopAdapter(
        ScriptedClient(transcript or _TRANSCRIPT, model_id_reported="model-as-served"),
        SandboxToolset(_InProcessExec()),
        skills=(_SKILL,),
        clock=_fixed_clock(),
    )
    events = list(adapter.run("Review.", model_id="frontier-configured", limits=RunLimits()))
    exit_reason = exit_reason_from_events(events)
    header = RunHeader(
        run_id=f"{plan.scenario.id}-{plan.target.slug}-{plan.repetition:03d}",
        eval_id="e",
        scenario_id=plan.scenario.id,
        repetition=plan.repetition,
        skill=SkillRef(
            name="security-review",
            package_digest="sha256:" + "a" * 64,
            payload_digest="sha256:" + "b" * 64,
            source="t",
        ),
        target=TargetRef(
            harness=plan.target.harness,
            harness_version=adapter.version(),
            provider=plan.target.provider,
            model_alias=plan.target.model_alias,
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
    path = write_trace(tmp_path / f"run-{index}.jsonl", header, harness_actions(events), footer)
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
    """Builds a per-plan trace whose header matches the plan (as the real executor does), counting
    the calls. ``stamp`` lets a test deliberately return a *mismatched* trace to exercise the bind."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        stamp: RunPlan | None = None,
        transcript: list[ModelTurn] | None = None,
    ) -> None:
        self.tmp_path = tmp_path
        self.stamp = stamp
        self.transcript = transcript
        self.plans: list[RunPlan] = []

    def execute(self, plan: RunPlan) -> ExecutedRun:
        self.plans.append(plan)
        return _executed_run(
            self.stamp or plan, self.tmp_path, len(self.plans), transcript=self.transcript
        )


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


def test_plan_matrix_refuses_a_single_run_set() -> None:
    """Repetition is mandatory — one run is an anecdote (§13.2), zero is not a set at all."""
    for repetitions in (0, 1):
        with pytest.raises(BellwetherError, match="at least two runs"):
            plan_matrix(
                [_scenario("a")], [TargetInfo("api-loop", "p", "frontier")], repetitions=repetitions
            )


# ---------------------------------------------------------------------------
# drive_evaluation
# ---------------------------------------------------------------------------


def test_drive_evaluation_groups_runs_into_one_reading_per_set(tmp_path: Path) -> None:
    executor = _ReplayExecutor(tmp_path)
    scenarios = [_scenario("alpha"), _scenario("beta")]
    targets = [TargetInfo("api-loop", "p", "frontier"), TargetInfo("api-loop", "p", "small")]
    plans = plan_matrix(scenarios, targets, repetitions=6)

    readings = drive_evaluation(plans, executor, profile=_firstlight_profile())

    # One reading per (scenario, target) set — 2 × 2 — each aggregating its 6 runs.
    assert len(readings) == 4
    assert len(executor.plans) == 24  # every plan executed exactly once
    assert all(len(reading.runs) == 6 for reading in readings)


def test_drive_evaluation_preserves_first_seen_set_order(tmp_path: Path) -> None:
    """Readings must come back in plan_matrix order, so the verdict and artifact tree are
    deterministic regardless of how plans interleave."""
    executor = _ReplayExecutor(tmp_path)
    scenarios = [_scenario("alpha"), _scenario("beta")]
    targets = [TargetInfo("api-loop", "p", "frontier")]
    plans = plan_matrix(scenarios, targets, repetitions=6)

    readings = drive_evaluation(plans, executor, profile=_firstlight_profile())

    assert [reading.scenario_id for reading in readings] == ["alpha", "beta"]


def test_a_driven_set_carries_the_passing_outcome_through(tmp_path: Path) -> None:
    """The scripted run activates the skill and completes, so the aggregated set is consistent —
    the driver faithfully carries per-run analysis into the reading, not just the count."""
    executor = _ReplayExecutor(tmp_path)
    plans = plan_matrix(
        [_scenario("alpha")], [TargetInfo("api-loop", "p", "frontier")], repetitions=6
    )

    (reading,) = drive_evaluation(plans, executor, profile=_firstlight_profile())

    assert reading.pass_rate == 1.0


def test_drive_evaluation_refuses_a_set_below_the_first_look(tmp_path: Path) -> None:
    """A set with fewer runs than the profile's first look (6) has no boundary to stop at and must
    not be aggregated into a figure the design does not license (§13.1). plan_matrix requires ≥2,
    so a 5-run set is what slips past it — the driver is the second gate."""
    plans = plan_matrix(
        [_scenario("alpha")], [TargetInfo("api-loop", "p", "frontier")], repetitions=5
    )
    with pytest.raises(BellwetherError, match="first look"):
        drive_evaluation(plans, _ReplayExecutor(tmp_path), profile=_firstlight_profile())


def test_a_misrouted_trace_is_rejected(tmp_path: Path) -> None:
    """§ trace-to-plan binding: if the executor returns a trace whose header names a different
    target, it must not be scored under this one — a stale or misrouted trace is refused."""
    wrong = RunPlan(_scenario("other"), TargetInfo("api-loop", "elsewhere", "small"), 1)
    executor = _ReplayExecutor(tmp_path, stamp=wrong)
    plans = plan_matrix(
        [_scenario("alpha")], [TargetInfo("api-loop", "p", "frontier")], repetitions=6
    )
    with pytest.raises(BellwetherError, match="does not match the run plan"):
        drive_evaluation(plans, executor, profile=_firstlight_profile())


def test_drive_evaluation_enforces_declared_scope_on_the_live_path(tmp_path: Path) -> None:
    """§12.5 / BW-47: a skill that uses a tool outside its declared scope must reach the ``scope``
    gate as a violation on the *live* run path — not only in the demo.

    The manifest here declares the ``skill`` tool only; the transcript also calls ``read``, which is
    therefore undeclared. Threading the manifest's declared scope into ``drive_evaluation`` makes
    every run's ``scope_exceeded`` name the undeclared tool. Omitting it — the old first-light
    shortcut that passed ``scope=None`` and nothing else — leaves the field empty, which is exactly
    the false ``within scope`` the fix closes: without the ``declared_scope`` argument this test
    would see an empty tuple where a violation occurred.
    """
    declared = DeclaredScope(tools=ToolScope(allow=["skill"]))
    plans = plan_matrix(
        [_scenario("alpha")], [TargetInfo("api-loop", "p", "frontier")], repetitions=6
    )

    enforced = _ReplayExecutor(tmp_path / "enforced", transcript=_SCOPE_VIOLATION_TRANSCRIPT)
    (reading,) = drive_evaluation(
        plans, enforced, profile=_firstlight_profile(), declared_scope=declared
    )
    assert reading.scope_exceeded == ("read",)
    assert all("read" in run.scope_exceeded for run in reading.runs)

    # Without the declared scope the live path is blind to the same violation — the pre-fix behaviour
    # this regression pins against, so a future revert of the driver change fails here.
    blind = _ReplayExecutor(tmp_path / "blind", transcript=_SCOPE_VIOLATION_TRANSCRIPT)
    (unenforced,) = drive_evaluation(plans, blind, profile=_firstlight_profile())
    assert unenforced.scope_exceeded == ()
