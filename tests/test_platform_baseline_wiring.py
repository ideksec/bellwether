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
    absorbed, near = baseline_absorption(
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
    absorbed, near = baseline_absorption(
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
