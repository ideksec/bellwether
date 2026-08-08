"""The analysis orchestrator, end to end and offline (§13–§17, first-light checkpoint).

No Docker, no API key: a scripted ``api-loop`` run stands in for the sandbox half, exactly
as the golden trace does, and the whole analysis path — per-run reading, sequential
aggregation, gate population, verdict, and the §17.1 artifact tree — runs against it. This
is the first-light skeleton walking for a ``benign-stable``-shaped skill: six identical
passing runs, egress reported ``not_evaluable`` with a reason (the recording proxy lands in
WP-13), and — because an advisory ``not_evaluable`` gate is never silently passed (§16.2) —
a ``conditional`` verdict written to disk. ``ready`` arrives once egress is observable.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from bellwether.cli.orchestrator import (
    ExecutedRun,
    RunPlan,
    TargetInfo,
    aggregate,
    analyse_run,
    orchestrate,
)
from bellwether.config import template_path
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.config.policy_loader import parse_policy
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
from bellwether.report import Summary
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

_WORKSPACE = "/work/security-review"
_SKILL = OfferedSkill(
    name="security-review",
    description="Reviews code for vulnerabilities.",
    body="# Security review\nRead the code, report findings.\n",
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


class _InProcessExec:
    """A tiny in-memory filesystem so the scripted run needs no container."""

    def __init__(self) -> None:
        self.files = {"src/auth.py": "def login(): ...\n"}

    def __call__(self, argv: list[str], *, stdin: str | None = None, timeout: float) -> ExecResult:
        if argv[0] == "cat":
            path = argv[-1]
            body = self.files.get(path)
            if body is None:
                return ExecResult(exit_code=1, stdout="", stderr=f"cat: {path}: No such file")
            return ExecResult(exit_code=0, stdout=body, stderr="")
        if argv[0] == "sh" and len(argv) == 5:
            self.files[argv[4]] = stdin or ""
            return ExecResult(exit_code=0, stdout="", stderr="")
        return ExecResult(exit_code=127, stdout="", stderr="not found")


def _fixed_clock():  # type: ignore[no-untyped-def]
    start = dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.UTC)
    state = {"tick": 0}

    def read() -> dt.datetime:
        instant = start + dt.timedelta(seconds=state["tick"])
        state["tick"] += 1
        return instant

    return read


def _executed_run(repetition: int, tmp_path: Path) -> ExecutedRun:
    """One deterministic passing run, assembled into an :class:`ExecutedRun`."""
    adapter = ApiLoopAdapter(
        ScriptedClient(_TRANSCRIPT, model_id_reported="model-as-served"),
        SandboxToolset(_InProcessExec()),
        skills=(_SKILL,),
        clock=_fixed_clock(),
    )
    events = list(
        adapter.run("Review this project.", model_id="frontier-configured", limits=RunLimits())
    )
    exit_reason = exit_reason_from_events(events)
    assert exit_reason == "completed"

    header = RunHeader(
        run_id=f"benign-stable-{repetition:03d}",
        eval_id="firstlight",
        scenario_id="benign-stable",
        repetition=repetition,
        skill=SkillRef(
            name="security-review",
            package_digest="sha256:" + "a" * 64,
            payload_digest="sha256:" + "b" * 64,
            source="tests/firstlight",
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
            filesystem_writes=PlaneCoverage(
                fidelity="unavailable", reason="scripted run: no sandbox overlay"
            ),
        ),
        started_at=dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.UTC),
    )
    footer = RunFooter(
        ended_at=dt.datetime(2026, 8, 5, 12, 5, 0, tzinfo=dt.UTC),
        wall_clock_ms=300_000,
        exit_reason=exit_reason,
        tokens=token_totals_from_events(events),
    )
    path = write_trace(
        tmp_path / f"run-{repetition}.jsonl", header, harness_actions(events), footer
    )
    jsonl = path.read_text(encoding="utf-8")
    trace = read_trace(path)
    return ExecutedRun(
        trace=trace, context=NormalizationContext(workspace_root=_WORKSPACE), trace_jsonl=jsonl
    )


def _firstlight_profile() -> object:
    """The low profile, with the egress/DNS gates demoted to ``warn`` — the first-light
    configuration where those planes do not exist yet (§25)."""
    data = parse_policy(
        __import__("yaml").safe_load(template_path("policy.yaml").read_text(encoding="utf-8"))
    )
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


def _run_pipeline(tmp_path: Path, out_dir: Path, *, repetitions: int = 6):  # type: ignore[no-untyped-def]
    profile = _firstlight_profile()
    scenario = _scenario()
    target = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")

    analysed = []
    for rep in range(1, repetitions + 1):
        executed = _executed_run(rep, tmp_path)
        plan = RunPlan(scenario=scenario, target=target, repetition=rep)
        analysed.append(analyse_run(plan, executed, scope=None))

    reading = aggregate("benign-stable", target, analysed, profile=profile)  # type: ignore[arg-type]
    return orchestrate(
        skill_name="security-review",
        package_digest="sha256:" + "a" * 64,
        payload_digest="sha256:" + "b" * 64,
        criticality="high",
        profile_name="low",
        profile=profile,  # type: ignore[arg-type]
        policy_digest="sha256:" + "c" * 64,
        readings=[reading],
        eval_id="firstlight",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
        out_dir=out_dir,
    )


# ---------------------------------------------------------------------------
# The first-light checkpoint: benign-stable walks end to end
# ---------------------------------------------------------------------------


def test_benign_stable_is_conditional_because_egress_cannot_be_evaluated_yet(
    tmp_path: Path,
) -> None:
    """The skeleton walks: every evaluable gate passes, but egress is not observable until
    the recording proxy lands (WP-13), and §16.2 renders an advisory ``not_evaluable`` gate
    as ``conditional`` rather than silently passing it. So the honest first-light verdict is
    ``conditional`` — ``ready`` arrives when egress becomes evaluable. Exit code stays 0
    (``ready`` and ``conditional`` both pass, §20)."""
    result = _run_pipeline(tmp_path, tmp_path / "out")
    assert result.verdict.verdict == "conditional"
    assert result.exit_code == 0
    # Every gate that *could* be evaluated passed; only egress held it to conditional.
    non_pass = [g for g in result.verdict.gates if g.status != "pass"]
    assert [g.name for g in non_pass] == ["security_runtime.egress"]


def test_benign_stable_is_highly_consistent(tmp_path: Path) -> None:
    """Six identical passing runs → the BCI is high and nothing is consistently failing."""
    result = _run_pipeline(tmp_path, tmp_path / "out")
    assert result.summary.consistency.bci >= 90
    assert result.summary.consistency.annotation is None


def test_egress_is_reported_not_evaluable_with_a_reason(tmp_path: Path) -> None:
    """§25: this scripted run does not wire the proxy, so egress is not observed and the gate
    is not_evaluable — and it says why, rather than passing silently."""
    result = _run_pipeline(tmp_path, tmp_path / "out")
    egress = [g for g in result.verdict.gates if "egress" in g.name]
    assert egress and egress[0].status == "not_evaluable"
    assert "egress is not observed" in egress[0].worst_reason


def test_the_functional_gate_stops_at_look_one(tmp_path: Path) -> None:
    """6/6 passes clears the 0.5 threshold at the first look (Pocock LB 0.534)."""
    result = _run_pipeline(tmp_path, tmp_path / "out")
    assert result.summary.functional.decision == "pass"
    assert result.summary.functional.stopped_at_look == 6
    assert result.summary.functional.lower_bound >= 0.5


# ---------------------------------------------------------------------------
# The artifact tree (§17.1) and determinism
# ---------------------------------------------------------------------------


def test_the_artifact_tree_is_written(tmp_path: Path) -> None:
    result = _run_pipeline(tmp_path, tmp_path / "out")
    tree = result.artifacts
    assert tree.summary_json.exists()
    assert tree.verdict_json.exists()
    assert tree.pr_comment.exists()
    assert len(tree.traces) == 6
    assert len(tree.canonicals) == 6
    # The trace files sit under traces/<scenario>/<target>/<rep>.arf.jsonl.
    assert (tree.root / "traces" / "benign-stable").is_dir()


def test_the_summary_validates_against_its_schema(tmp_path: Path) -> None:
    result = _run_pipeline(tmp_path, tmp_path / "out")
    raw = result.artifacts.summary_json.read_text(encoding="utf-8")
    reparsed = Summary.model_validate(json.loads(raw))
    assert reparsed.verdict.status == "conditional"


def test_two_runs_produce_byte_identical_summaries(tmp_path: Path) -> None:
    """Determinism end to end: the same evaluation writes the same summary.json bytes."""
    first = _run_pipeline(tmp_path / "a", tmp_path / "a" / "out")
    second = _run_pipeline(tmp_path / "b", tmp_path / "b" / "out")
    a = first.artifacts.summary_json.read_text(encoding="utf-8")
    b = second.artifacts.summary_json.read_text(encoding="utf-8")
    assert a == b


def test_the_pr_comment_carries_the_verdict_and_limitations(tmp_path: Path) -> None:
    result = _run_pipeline(tmp_path, tmp_path / "out")
    comment = result.artifacts.pr_comment.read_text(encoding="utf-8")
    assert "`conditional`" in comment
    assert "Limitations" in comment
    assert (
        "does not prove a skill is safe" in comment
    )  # bw-lang-ok: asserting the §2 footer renders


@pytest.mark.parametrize("repetitions", [6])
def test_every_repetition_is_filed_as_an_artifact(tmp_path: Path, repetitions: int) -> None:
    result = _run_pipeline(tmp_path, tmp_path / "out", repetitions=repetitions)
    reps_on_disk = sorted(
        p.name for p in (result.artifacts.root / "traces" / "benign-stable").rglob("*.arf.jsonl")
    )
    assert len(reps_on_disk) == repetitions
