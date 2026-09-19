"""The platform baseline on the analysis path (§12.6).

`.bellwether/platform-baseline.yaml` was a shipped document nothing read: `apply_path_baseline`
had no callers, so every harness/toolchain path a run touched counted against the skill.
Now `analyse_run` applies the baseline's path entries — glob-aware, near-miss-flagging — to
each run before the capability sets are produced, records what it absorbed as an audit
trail, and never absorbs a traversal that names an entry but escapes it.
"""

from __future__ import annotations

from pathlib import Path

from bellwether.cli.orchestrator import (
    ExecutedRun,
    RunPlan,
    TargetInfo,
    analyse_run,
    baseline_absorption,
    observed_paths,
)
from bellwether.config.models.baseline import BaselinePaths, PlatformBaseline
from bellwether.config.models.scenarios import Scenario
from bellwether.trace import NormalizationContext, Trace
from tests.factories import make_action, make_footer, make_header

_IMAGE = "ghcr.io/example/bellwether-sandbox@sha256:" + "5" * 64
_CONTEXT = NormalizationContext(workspace_root="/work/a7f3c1", home="/home/agent", tmp="/tmp")
_TARGET = TargetInfo(harness="api-loop", provider="anthropic", model_alias="frontier")


def _read(seq: int, path: str) -> object:
    return make_action(seq, action={"tool": "read", "input": {"path": path}}, capability=None)


def _write(seq: int, path: str) -> object:
    return make_action(
        seq,
        action={"tool": "write", "input": {"path": path, "content": "x"}},
        capability=None,
    )


def _baseline(image: str | None = _IMAGE) -> PlatformBaseline:
    return PlatformBaseline(
        api_version="bellwether/v1",
        kind="PlatformBaseline",
        version="2026.09.1",
        applies_to_image=image,
        paths=BaselinePaths(
            read=("/etc/{passwd,group}", "${HOME}/.cache/**"), write=("${HOME}/.cache/**",)
        ),
    )


def _actions() -> tuple[object, ...]:
    return (
        _read(0, "/etc/passwd"),  # absorbed
        _read(1, "/home/agent/.cache/pip/x"),  # absorbed
        _read(2, "/home/agent/.cache/../.aws/credentials"),  # traversal: near miss, never absorbed
        _read(3, "notes/a.md"),  # workspace: not an entry
        _write(4, "/home/agent/.cache/build.log"),  # absorbed (write)
        _write(5, "out.md"),  # workspace write: not an entry
    )


def test_observed_paths_keep_the_named_form_beside_the_resolved_one() -> None:
    reads, writes = observed_paths(_actions(), _CONTEXT)  # type: ignore[arg-type]
    by_resolved = {path.resolved: path for path in reads}
    assert by_resolved["/etc/passwd"].raw == "/etc/passwd"
    assert by_resolved["${HOME}/.cache/pip/x"].raw == "${HOME}/.cache/pip/x"
    traversal = by_resolved["${HOME}/.aws/credentials"]
    assert traversal.raw == "${HOME}/.cache/../.aws/credentials"
    assert traversal.used_traversal
    assert by_resolved["${WORKSPACE}/notes/a.md"].raw == "${WORKSPACE}/notes/a.md"
    assert [path.resolved for path in writes] == [
        "${HOME}/.cache/build.log",
        "${WORKSPACE}/out.md",
    ]


def test_absorption_subtracts_entries_and_flags_the_traversal() -> None:
    absorbed, _tools, near = baseline_absorption(
        _actions(),  # type: ignore[arg-type]
        _CONTEXT,
        _baseline(),
        sandbox_image=_IMAGE,
    )
    assert absorbed == {"/etc/passwd", "${HOME}/.cache/pip/x", "${HOME}/.cache/build.log"}
    assert len(near) == 1
    assert ".cache/../.aws/credentials" in near[0]
    assert "traversal never resolves into a baseline match" in near[0]


def test_a_baseline_for_another_image_absorbs_nothing() -> None:
    absorbed, _tools, near = baseline_absorption(
        _actions(),  # type: ignore[arg-type]
        _CONTEXT,
        _baseline(image="other@sha256:" + "0" * 64),
        sandbox_image=_IMAGE,
    )
    assert absorbed == frozenset()
    assert near == ()


def _executed() -> ExecutedRun:
    trace = Trace(header=make_header(), actions=tuple(_actions()), footer=make_footer())  # type: ignore[arg-type]
    return ExecutedRun(trace=trace, context=_CONTEXT, trace_jsonl="")


def _plan() -> RunPlan:
    scenario = Scenario.model_validate(
        {
            "id": "triggers-on-direct-request",
            "expectation": "should_trigger",
            "prompt": "go",
            "assert": [{"skill_activated": True}],
        }
    )
    return RunPlan(scenario=scenario, target=_TARGET, repetition=1)


def test_analyse_run_subtracts_the_baseline_before_the_capability_sets_are_produced() -> None:
    without = analyse_run(_plan(), _executed(), scope=None)
    assert "/etc/passwd" in without.caps_t3
    assert "${HOME}/.cache/pip/x" in without.caps_t3
    assert without.baseline_absorbed == ()

    with_baseline = analyse_run(_plan(), _executed(), scope=None, platform_baseline=_baseline())
    assert "/etc/passwd" not in with_baseline.caps_t3
    assert "${HOME}/.cache/pip/x" not in with_baseline.caps_t3
    assert "${HOME}/.cache/build.log" not in with_baseline.caps_t3
    # The escape is never absorbed, and the workspace accesses stay the skill's.
    assert "${HOME}/.aws/credentials" in with_baseline.caps_t3
    assert "${WORKSPACE}/notes/a.md" in with_baseline.caps_t3
    assert with_baseline.baseline_absorbed == (
        "${HOME}/.cache/build.log",
        "${HOME}/.cache/pip/x",
        "/etc/passwd",
    )
    assert len(with_baseline.baseline_near_misses) == 1
    # Tier 1 follows: outside_workspace_read survives only for the credential read.
    assert "outside_workspace_read" in with_baseline.caps_t1


def test_analyse_run_with_a_mismatched_image_changes_nothing_and_records_nothing() -> None:
    result = analyse_run(
        _plan(), _executed(), scope=None, platform_baseline=_baseline(image="x@sha256:" + "1" * 64)
    )
    assert "/etc/passwd" in result.caps_t3
    assert result.baseline_absorbed == ()
    assert result.baseline_near_misses == ()


def test_the_literal_set_and_the_baseline_compose(tmp_path: Path) -> None:
    """A caller-supplied literal set (the WP-8 seam) is unioned with what the matcher absorbs."""
    result = analyse_run(
        _plan(),
        _executed(),
        scope=None,
        platform_baseline_t3=frozenset({"${WORKSPACE}/notes/a.md"}),
        platform_baseline=_baseline(),
    )
    assert "${WORKSPACE}/notes/a.md" not in result.caps_t3
    assert "/etc/passwd" not in result.caps_t3


# ---------------------------------------------------------------------------
# §12.6: computing the audit trail is not the same as publishing it
# ---------------------------------------------------------------------------


def test_what_the_baseline_absorbed_and_nearly_absorbed_reaches_the_summary() -> None:
    """The regression this closes: both were computed and then dropped on the floor.

    `analyse_run` produced `baseline_absorbed` and `baseline_near_misses`, the aggregation
    carried them onto the set reading, and nothing downstream ever read either — no summary,
    no verdict, no renderer. So the subtraction that makes declared-vs-observed readable was
    itself unobservable, and a near-miss §12.6 asks be *raised* was computed and discarded.
    """
    from bellwether.cli.orchestrator import _platform_baseline_summary

    analysed = analyse_run(_plan(), _executed(), scope=None, platform_baseline=_baseline())

    class _Reading:
        baseline_absorbed = analysed.baseline_absorbed
        baseline_near_misses = analysed.baseline_near_misses

    block = _platform_baseline_summary(
        _baseline(), [_Reading()], applied_version=_baseline().version
    )
    assert block is not None
    assert block.applied is True
    # The audit trail: what came out of this evaluation.
    assert "/etc/passwd" in block.absorbed
    assert "${HOME}/.cache/pip/x" in block.absorbed
    # And the near-miss, said out loud rather than absorbed.
    assert block.near_misses == analysed.baseline_near_misses
    assert block.near_misses, "a near-miss was computed and then lost again"
    # The allowlist itself, which is what makes the subtraction checkable.
    assert block.paths_read == _baseline().paths.read
    assert block.paths_write == _baseline().paths.write


def test_a_baseline_that_did_not_apply_is_reported_as_such_not_as_empty() -> None:
    """`applied` is carried separately from an empty `absorbed`: a baseline not keyed to this
    run's image absorbed nothing for a different reason than one that matched nothing."""
    from bellwether.cli.orchestrator import _platform_baseline_summary

    class _Reading:
        baseline_absorbed: tuple[str, ...] = ()
        baseline_near_misses: tuple[str, ...] = ()

    block = _platform_baseline_summary(_baseline(), [_Reading()], applied_version="")
    assert block is not None
    assert block.applied is False
    assert block.absorbed == ()
    # The contents still travel, so a reader can see what *would* have been subtracted.
    assert block.paths_read


def test_no_baseline_yields_no_block_at_all() -> None:
    """Absent is not empty."""
    from bellwether.cli.orchestrator import _platform_baseline_summary

    assert _platform_baseline_summary(None, [], applied_version="") is None


# ---------------------------------------------------------------------------
# §12.6 `tools`: the third area, and the last one no capture plane blocks
# ---------------------------------------------------------------------------


def _baseline_with_tools(*tools: str) -> PlatformBaseline:
    return PlatformBaseline(
        apiVersion="bellwether/v1",
        kind="PlatformBaseline",
        version="2026.08.1",
        applies_to_image=_IMAGE,
        tools=tools,
    )


def test_a_tool_the_platform_accounts_for_is_absorbed() -> None:
    """§12.6 has three areas and `tools` was parsed and inert.

    `paths` has absorbed since the baseline landed; `processes` waits on the §10.3 process
    plane, because `helpers_of` is written in terms of tree attribution and there are no
    trees to attribute against. `tools` needs no new plane — a tool call is Plane A evidence
    every run already has — so it was the one area left unapplied for no reason but reach.
    """
    from bellwether.assertions import apply_tool_baseline

    observed = ["tool:bash", "tool:read", "tool:fetch"]
    absorbed = apply_tool_baseline(observed, _baseline_with_tools("bash"), sandbox_image=_IMAGE)
    assert absorbed == frozenset({"tool:bash"})


def test_tool_names_match_exactly_never_as_globs() -> None:
    """A path baseline is written in globs because paths are hierarchical and unbounded. A
    tool name is a fixed identifier from the harness's own vocabulary, and a glob there would
    let a single `*` absorb the entire tool surface — the failure an allowlist exists to
    prevent."""
    from bellwether.assertions import apply_tool_baseline

    observed = ["tool:bash", "tool:read"]
    assert apply_tool_baseline(observed, _baseline_with_tools("*"), sandbox_image=_IMAGE) == (
        frozenset()
    )
    assert apply_tool_baseline(observed, _baseline_with_tools("ba*"), sandbox_image=_IMAGE) == (
        frozenset()
    )


def test_a_tool_baseline_for_another_image_absorbs_nothing() -> None:
    """The same refusal the path half makes, and for the same reason: an unkeyed allowlist
    absorbs findings it has no standing to absorb."""
    from bellwether.assertions import apply_tool_baseline

    absorbed = apply_tool_baseline(
        ["tool:bash"], _baseline_with_tools("bash"), sandbox_image="other@sha256:" + "9" * 64
    )
    assert absorbed == frozenset()


def test_an_absorbed_tool_leaves_the_capability_set_but_stays_in_the_sequence() -> None:
    """§11.4's rule, applied to the new area: baseline subtraction removes *what* was touched
    from the capability sets while the step sequence keeps every step, because how the skill
    worked includes its infrastructure moves.

    The first version of this test used the filesystem tools from `_actions()`, whose tier-1 is
    `workspace_read:…` and never `tool:…` — so `caps_t1` was byte-identical with and without
    the absorption and the test passed with the feature deleted. It needs a tool whose
    capability really is a `tool:` class.
    """
    import datetime as dt

    from bellwether.trace import Action, canonicalize

    call = Action(
        seq=1,
        ts=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        plane="harness",
        kind="tool_call",
        action={"tool": "bash", "input": {"command": "ls"}},
    )

    unabsorbed = canonicalize([call], _CONTEXT)
    assert "tool:bash" in unabsorbed.caps_t1, "the fixture must produce the class under test"

    absorbed = canonicalize([call], _CONTEXT, platform_baseline_t1=frozenset({"tool:bash"}))
    assert "tool:bash" not in absorbed.caps_t1
    # Removed from *what* was touched, kept in *how* the run went — the same treatment a
    # baseline-absorbed path gets.
    assert absorbed.step_sequence == unabsorbed.step_sequence
    assert any(step[0] == "tool_call" for step in absorbed.step_sequence)
