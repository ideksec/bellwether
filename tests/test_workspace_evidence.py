"""R7/R11: content assertions read a retained host-side snapshot, or nothing at all.

Two defects an independent review reproduced, closed together because the fix for one is the
precondition of the other.

The analysis path built its evidence index from ``context.workspace_root`` — the path *inside
the container*, ``/work/<slug>``. Content-inspecting assertions then did host filesystem reads
against it. On the host that path does not exist, so ``artifact_valid`` failed on every live run
for a file the skill had genuinely written; and where a host directory of that name did exist,
they would have read it and reported on unrelated content.

The workspace they should read is the overlay's merged view, which the kernel assembles and the
teardown unmounts — so it has to be copied while it is still there, and copied *after* the
container is gone or a detached process can edit the evidence mid-read.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from bellwether.assertions import EvidenceIndex, evaluate
from bellwether.cli.execution import (
    _WORKSPACE_SNAPSHOT_MAX_BYTES,
    SandboxRunExecutor,
)
from bellwether.cli.orchestrator import ExecutedRun
from bellwether.config.models.scenarios import AssertionSpec
from bellwether.trace import (
    Coverage,
    NormalizationContext,
    PlaneCoverage,
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
    TokenTotals,
    parse_trace,
    serialize_record,
)

_WORKSPACE = "/work/t1"
_START = dt.datetime(2026, 9, 19, 12, 0, 0, tzinfo=dt.UTC)


def _header() -> RunHeader:
    return RunHeader(
        run_id="r1",
        eval_id="e1",
        scenario_id="s1",
        repetition=1,
        skill=SkillRef(
            name="writer",
            package_digest="sha256:" + "a" * 64,
            payload_digest="sha256:" + "a" * 64,
            source="test",
        ),
        target=TargetRef(harness="api-loop", provider="scripted", model_alias="frontier"),
        sandbox=SandboxRef(image="img"),
        coverage=Coverage(
            harness_events=PlaneCoverage(fidelity="full"),
            filesystem_writes=PlaneCoverage(fidelity="overlay_diff"),
        ),
        started_at=_START,
    )


def _footer() -> RunFooter:
    return RunFooter(
        ended_at=_START + dt.timedelta(seconds=1),
        wall_clock_ms=1_000,
        exit_reason="completed",
        tokens=TokenTotals(input=1, output=1),
    )


def _jsonl() -> str:
    return f"{serialize_record(_header())}\n{serialize_record(_footer())}\n"


def _index(workspace: Path | None) -> EvidenceIndex:
    return EvidenceIndex.from_trace(
        parse_trace(_jsonl()),
        NormalizationContext(workspace_root=_WORKSPACE),
        workspace=workspace,
    )


def _executed(workspace: Path | None) -> ExecutedRun:
    jsonl = _jsonl()
    return ExecutedRun(
        trace=parse_trace(jsonl),
        context=NormalizationContext(workspace_root=_WORKSPACE),
        trace_jsonl=jsonl,
        workspace=workspace,
    )


def test_artifact_valid_reads_the_retained_snapshot(tmp_path: Path) -> None:
    """Given the workspace the executor actually retained, the assertion passes — which it
    could not do at all while it was handed the container's path."""
    (tmp_path / "out.json").write_text('{"ok": true}', encoding="utf-8")

    result = evaluate(AssertionSpec(name="artifact_valid", params="out.json"), _index(tmp_path))

    assert result.status == "pass"


def test_no_retained_workspace_is_not_evaluable_rather_than_a_failure(tmp_path: Path) -> None:
    """R11's user-visible half. With no workspace retained — a run replayed from the cache, a
    backend with no host-side merged view — the assertion has no bytes to judge. That is a
    coverage statement, not a verdict about the skill: reporting ``fail`` blames the skill for
    the evaluator's blindness, which is the inversion of §10.0's rule."""
    result = evaluate(AssertionSpec(name="artifact_valid", params="out.json"), _index(None))

    assert result.status == "not_evaluable"
    assert "not retained" in result.reason


def test_a_container_path_would_have_failed_a_file_that_exists(tmp_path: Path) -> None:
    """The defect itself, pinned. Reading the container's path on the host finds nothing, and
    the old code reported that as the skill failing to produce the artifact."""
    (tmp_path / "out.json").write_text('{"ok": true}', encoding="utf-8")

    as_container_path = evaluate(
        AssertionSpec(name="artifact_valid", params="out.json"), _index(Path(_WORKSPACE))
    )

    assert as_container_path.status == "fail"
    assert evaluate(AssertionSpec(name="artifact_valid", params="out.json"), _index(tmp_path)) != (
        as_container_path
    )


# ---------------------------------------------------------------------------
# The snapshot itself
# ---------------------------------------------------------------------------


def _retain(merged: Path | None, run_dir: Path) -> Path | None:
    return SandboxRunExecutor._retain_workspace(None, merged, run_dir)  # type: ignore[arg-type]


def test_the_snapshot_copies_regular_files(tmp_path: Path) -> None:
    merged = tmp_path / "merged"
    (merged / "nested").mkdir(parents=True)
    (merged / "nested" / "report.md").write_text("# findings", encoding="utf-8")

    retained = _retain(merged, tmp_path / "run")

    assert retained is not None
    assert (retained / "nested" / "report.md").read_text(encoding="utf-8") == "# findings"


def test_a_symlink_is_recreated_not_followed(tmp_path: Path) -> None:
    """Containment. A skill that plants ``report.md -> /etc/passwd`` in its workspace must not
    get the evaluator's own file copied into the evidence and read back by an assertion as
    though the skill had written it."""
    outside = tmp_path / "host-secret.txt"
    outside.write_text("SYNTHETIC-HOST-SECRET", encoding="utf-8")
    merged = tmp_path / "merged"
    merged.mkdir()
    (merged / "report.md").symlink_to(outside)

    retained = _retain(merged, tmp_path / "run")

    assert retained is not None
    link = retained / "report.md"
    # Copied as a link, so the tree's shape is faithful and no host bytes entered the evidence.
    assert link.is_symlink()
    assert not (link.parent / "report.md").is_file() or link.is_symlink()

    # And the assertion refuses to read through it, which is the half that matters: a snapshot
    # that faithfully records a link still hands an assertion a route out of the workspace if
    # the read follows it.
    result = evaluate(AssertionSpec(name="artifact_valid", params="report.md"), _index(retained))
    assert result.status == "fail"
    assert "does not exist in the final workspace" in result.reason


def test_an_oversized_workspace_retains_nothing(tmp_path: Path) -> None:
    """Bounded, and all-or-nothing. The copy runs on the host, outside the container's own
    resource limits. A *partial* snapshot would be worse than none: a content assertion would
    then fail for a file that existed, which reads as a defect in the skill."""
    merged = tmp_path / "merged"
    merged.mkdir()
    (merged / "huge.bin").write_bytes(b"\0" * 1024)

    original = _WORKSPACE_SNAPSHOT_MAX_BYTES
    try:
        import bellwether.cli.execution as execution

        execution._WORKSPACE_SNAPSHOT_MAX_BYTES = 16
        retained = _retain(merged, tmp_path / "run")
    finally:
        execution._WORKSPACE_SNAPSHOT_MAX_BYTES = original

    assert retained is None
    assert not (tmp_path / "run" / "workspace-final").exists()


def test_an_unmounted_overlay_retains_nothing(tmp_path: Path) -> None:
    """The ``--paranoid`` fallback and any backend with no host-side merged view land here."""
    assert _retain(None, tmp_path / "run") is None


def test_an_assertion_path_cannot_traverse_out_of_the_workspace(tmp_path: Path) -> None:
    """The other route out, needing no symlink: the assertion's own path. Containment is
    decided by resolving both sides, so the traversal and the symlink are one check."""
    (tmp_path / "outside.json").write_text('{"ok": true}', encoding="utf-8")
    workspace = tmp_path / "ws"
    workspace.mkdir()

    result = evaluate(
        AssertionSpec(name="artifact_valid", params="../outside.json"), _index(workspace)
    )

    assert result.status in {"fail", "not_evaluable"}
    assert result.status != "pass"


def test_analyse_run_judges_content_against_the_retained_workspace(tmp_path: Path) -> None:
    """The wiring, not just the helper. ``analyse_run`` is where the container path was passed,
    so the proof has to run through it: an ``artifact_valid`` assertion over a file the run
    really produced passes only when the *retained host* workspace reaches the evidence index.

    Reverting the one line to ``Path(context.workspace_root)`` turns this run's outcome from a
    pass into a failure, which is what every live run with a content assertion was getting.
    """
    from bellwether.cli.orchestrator import RunPlan, TargetInfo, analyse_run
    from bellwether.config.models.scenarios import Scenario

    workspace = tmp_path / "workspace-final"
    workspace.mkdir()
    (workspace / "out.json").write_text('{"ok": true}', encoding="utf-8")

    target = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")
    scenario = Scenario(
        id="s1",
        expectation="should_trigger",
        prompt="Write out.json.",
        assertions=[AssertionSpec(name="artifact_valid", params="out.json")],
    )
    plan = RunPlan(scenario=scenario, target=target, repetition=1)
    executed = _executed(workspace)

    analysed = analyse_run(plan, executed, scope=None)

    assert analysed.outcome == "pass"

    without = analyse_run(plan, _executed(None), scope=None)
    assert without.outcome == "not_evaluable"
