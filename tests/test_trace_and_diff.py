"""`bellwether trace` and `bellwether diff` — reading stored artifacts (§20, §17.1, §17.5).

Both commands work on the demo trees. `diff` reads the committed ``examples/reports/``
summaries, which the demo byte-compare test already pins. `trace` needs the per-run traces,
which the committed tree deliberately omits (``.gitignore``: only the rendered outputs are
kept), so the trace tests regenerate the demo into a temporary tree once per module — the
same `generate_demo` the byte-compare test drives. The diff's §17.5 discipline is the point:
what is not comparable is named at the top, a schema-version mismatch is refused, and tier-1
expansion is surfaced as the regression signal rather than buried in a table.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bellwether.cli import ExitCode, app
from bellwether.cli.diff import (
    diff_summaries,
    load_summary,
    render_diff_markdown,
    resolve_summary,
)
from bellwether.cli.trace_view import (
    TraceFilter,
    load_trace,
    locate_trace,
    render_trace_lines,
    summarise_action,
    trace_record,
)
from bellwether.errors import BellwetherError

_ROOT = Path(__file__).resolve().parent.parent
_REPORTS = _ROOT / "examples" / "reports"
_BENIGN = "demo-benign-note-taker"
_SNEAKY = "demo-sneaky-exfiltrator"
_FLAKY = "demo-flaky-formatter"
_SNEAKY_RUN = "demo-sneaky-exfiltrator-001"

runner = CliRunner()


@pytest.fixture(scope="module")
def tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A full demo artifact tree — traces included — generated once for this module."""
    from bellwether.cli.demo import generate_demo

    base = tmp_path_factory.mktemp("demo")
    generate_demo(
        skills_root=_ROOT / "examples" / "skills", out_dir=base / "out", tmp_dir=base / "traces"
    )
    return base / "out"


# ---------------------------------------------------------------------------
# trace
# ---------------------------------------------------------------------------


def test_locate_finds_a_trace_by_its_header_run_id(tree: Path) -> None:
    path = locate_trace(_SNEAKY_RUN, out_dir=tree)
    assert path.name == "1.arf.jsonl"
    assert path.parent.parent.parent.parent.name == _SNEAKY


def test_locate_narrows_to_one_evaluation(tree: Path) -> None:
    assert locate_trace(_SNEAKY_RUN, out_dir=tree, eval_id=_SNEAKY).is_file()
    with pytest.raises(BellwetherError, match="no trace with run_id"):
        locate_trace(_SNEAKY_RUN, out_dir=tree, eval_id=_BENIGN)


def test_locate_takes_a_path_directly(tree: Path) -> None:
    path = next((tree / _BENIGN / "traces").glob("**/2.arf.jsonl"))
    assert locate_trace(str(path), out_dir=Path("/nonexistent")) == path


def test_locate_refuses_a_missing_id_naming_what_it_searched(tree: Path) -> None:
    with pytest.raises(
        BellwetherError, match=r"no trace with run_id 'nope'.*trace file\(s\) searched"
    ):
        locate_trace("nope", out_dir=tree)


def test_locate_refuses_an_absent_artifact_directory(tmp_path: Path) -> None:
    with pytest.raises(BellwetherError, match="does not exist"):
        locate_trace("anything", out_dir=tmp_path / "missing")


def test_locate_refuses_an_ambiguous_id_naming_every_candidate(tree: Path, tmp_path: Path) -> None:
    """The same run_id under two evaluations: picking one silently would show the wrong run."""
    source = locate_trace(_SNEAKY_RUN, out_dir=tree)
    for eval_name in ("a", "b"):
        target = tmp_path / eval_name / "traces" / "s" / "t" / "1.arf.jsonl"
        target.parent.mkdir(parents=True)
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(BellwetherError, match="matches 2 traces") as caught:
        locate_trace(_SNEAKY_RUN, out_dir=tmp_path)
    assert str(tmp_path / "a") in str(caught.value)
    assert str(tmp_path / "b") in str(caught.value)


def test_render_lists_every_action_with_its_summary(tree: Path) -> None:
    trace = load_trace(locate_trace(_SNEAKY_RUN, out_dir=tree))
    lines = render_trace_lines(trace)
    assert lines[0] == f"run      {_SNEAKY_RUN}"
    assert any("coverage" in line and "harness_events=full" in line for line in lines)
    # The credential read the exfiltrator makes is legible on its line.
    assert any("tool_call" in line and "/home/agent/.aws/credentials" in line for line in lines)
    assert lines[-1].startswith("ended") and "exit completed" in lines[-1]


def test_filters_keep_only_the_named_kinds_and_say_how_many_were_hidden(tree: Path) -> None:
    trace = load_trace(locate_trace(_SNEAKY_RUN, out_dir=tree))
    lines = render_trace_lines(trace, TraceFilter(kinds=frozenset({"tool_call"})))
    body = [line for line in lines if "  harness  " in line]
    assert body and all("tool_call" in line for line in body)
    assert any("actions shown" in line and "filtered out" in line for line in lines)
    record = trace_record(trace, TraceFilter(planes=frozenset({"filesystem"})))
    assert record["actions"] == []  # the scripted demo has no Plane B
    assert record["actions_total"] == len(trace.actions)


def test_summarise_action_covers_the_common_kinds(tree: Path) -> None:
    trace = load_trace(locate_trace(_SNEAKY_RUN, out_dir=tree))
    by_kind = {action.kind: summarise_action(action) for action in trace.actions}
    assert by_kind["skill_offered"] == "sneaky-exfiltrator"
    assert by_kind["model_turn"].startswith("stop=")
    assert by_kind["tool_result"].endswith("(1000 ms)")
    assert by_kind["final_output"] == "Wrote summary.md."


def test_trace_record_is_json_serialisable_and_complete(tree: Path) -> None:
    trace = load_trace(locate_trace(_SNEAKY_RUN, out_dir=tree))
    record = trace_record(trace)
    json.dumps(record)
    assert record["complete"] is True
    assert record["footer"]["exit_reason"] == "completed"
    assert record["target"]["model_alias"] == "frontier"


def test_render_marks_an_incomplete_trace(tree: Path, tmp_path: Path) -> None:
    source = locate_trace(_SNEAKY_RUN, out_dir=tree)
    lines = source.read_text(encoding="utf-8").splitlines()
    truncated = tmp_path / "cut.arf.jsonl"
    truncated.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")  # drop the footer
    rendered = render_trace_lines(load_trace(truncated))
    assert rendered[-1].startswith("INCOMPLETE:")


def test_trace_command_end_to_end(tree: Path) -> None:
    result = runner.invoke(
        app, ["trace", _SNEAKY_RUN, "--out", str(tree), "--kind", "tool_call", "--json"]
    )
    assert result.exit_code == ExitCode.OK, result.output
    payload = json.loads(result.output)
    assert payload["run_id"] == _SNEAKY_RUN
    assert {action["kind"] for action in payload["actions"]} == {"tool_call"}
    missing = runner.invoke(app, ["trace", "nope", "--out", str(tree)])
    assert missing.exit_code == ExitCode.INFRASTRUCTURE
    assert "no trace with run_id" in missing.output


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def test_resolve_accepts_an_id_a_directory_or_a_file() -> None:
    expected = _REPORTS / _BENIGN / "summary.json"
    assert resolve_summary(_BENIGN, out_dir=_REPORTS) == expected
    assert resolve_summary(str(_REPORTS / _BENIGN), out_dir=Path("/nonexistent")) == expected
    assert resolve_summary(str(expected), out_dir=Path("/nonexistent")) == expected
    with pytest.raises(BellwetherError, match=r"not a summary\.json"):
        resolve_summary("nope", out_dir=_REPORTS)


def test_an_evaluation_diffed_with_itself_is_identical() -> None:
    summary = load_summary(_REPORTS / _BENIGN / "summary.json")
    diff = diff_summaries(summary, summary)
    assert diff.identical
    assert not diff.capability_expanded
    assert "No differences" in render_diff_markdown(diff)
    # Tier 3 is always named as not compared (§4.1) — never silently dropped.
    assert any("tier3" in component for component, _ in diff.skipped)


def test_the_exfiltrator_shows_tier1_expansion_and_the_sensitive_hit() -> None:
    """benign → sneaky: the read outside the workspace is a new tier-1 class, and the
    `.aws/` hit is new — the two regression signals §17.5 names — beside the verdict change."""
    diff = diff_summaries(
        load_summary(_REPORTS / _BENIGN / "summary.json"),
        load_summary(_REPORTS / _SNEAKY / "summary.json"),
    )
    assert diff.capability_expanded
    assert diff.capabilities_added == ("outside_workspace_read",)
    assert diff.sensitive_hits_added == ("outside_workspace_read:${HOME}/.aws/",)
    changed = {(d.component, d.name): (d.before, d.after) for d in diff.changes}
    assert changed[("verdict", "status")] == ("conditional", "not_ready")
    assert changed[("gate", "scope")] == ("pass", "block")
    # Different policies are a caveat the reader sees before the table.
    assert any("policies differ" in caveat for caveat in diff.caveats)
    rendered = render_diff_markdown(diff)
    assert rendered.index("Read with care") < rendered.index("| component |")
    assert "**Tier-1 capability expansion**" in rendered


def test_peripheral_classes_count_as_tier1_and_are_read_from_their_records() -> None:
    """The flaky formatter's `workspace_write` is peripheral (6 of 20 runs), recorded as a
    §13.5.2 record rather than a bare name; it is still the same tier-1 class, so moving from
    core to peripheral is neither an expansion nor a removal."""
    diff = diff_summaries(
        load_summary(_REPORTS / _BENIGN / "summary.json"),
        load_summary(_REPORTS / _FLAKY / "summary.json"),
    )
    assert "workspace_write" not in diff.capabilities_added
    assert "workspace_write" not in diff.capabilities_removed


def test_a_different_weights_digest_skips_the_weighted_figures_and_says_so() -> None:
    a = load_summary(_REPORTS / _BENIGN / "summary.json")
    b = a.model_copy(
        update={"consistency": a.consistency.model_copy(update={"weights_digest": "sha256:other"})}
    )
    diff = diff_summaries(a, b)
    skipped = dict(diff.skipped)
    assert any("bci" in component for component in skipped)
    assert not any(d.name in {"bci", "capability_jaccard_weighted"} for d in diff.changes)
    rendered = render_diff_markdown(diff)
    assert rendered.index("Not compared") < rendered.index("No differences")


def test_a_schema_version_mismatch_is_refused() -> None:
    a = load_summary(_REPORTS / _BENIGN / "summary.json")
    b = a.model_copy(update={"schema_version": "0.9"})
    with pytest.raises(BellwetherError, match="different schema versions"):
        diff_summaries(a, b)


def test_an_invalid_summary_is_refused_naming_the_file(tmp_path: Path) -> None:
    bad = tmp_path / "summary.json"
    bad.write_text('{"eval_id": "x"}', encoding="utf-8")
    with pytest.raises(BellwetherError, match=r"not a valid summary\.json"):
        load_summary(bad)


def test_diff_command_end_to_end() -> None:
    result = runner.invoke(app, ["diff", _BENIGN, _SNEAKY, "--out", str(_REPORTS), "--json"])
    assert result.exit_code == ExitCode.OK, result.output
    payload = json.loads(result.output)
    assert payload["capability_expanded"] is True
    assert {
        "component": "verdict",
        "field": "status",
        "before": "conditional",
        "after": "not_ready",
    } in payload["changes"]
    text = runner.invoke(app, ["diff", _BENIGN, _BENIGN, "--out", str(_REPORTS)])
    assert text.exit_code == ExitCode.OK
    assert "No differences" in text.output
    missing = runner.invoke(app, ["diff", _BENIGN, "nope", "--out", str(_REPORTS)])
    assert missing.exit_code == ExitCode.INFRASTRUCTURE
