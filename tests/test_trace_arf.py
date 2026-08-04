"""WP-3: the ARF schema, writer and reader (§11.1–11.3).

Done when: round-trip write→read is lossless; a truncated file is detected as incomplete.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bellwether.errors import TraceError
from bellwether.trace import (
    Coverage,
    PlaneCoverage,
    TraceWriter,
    iter_actions,
    read_trace,
    serialize_record,
    write_trace,
)
from tests.factories import make_action, make_footer, make_header


@pytest.fixture
def trace_path(tmp_path: Path) -> Path:
    return write_trace(
        tmp_path / "run.jsonl",
        make_header(),
        [make_action(1), make_action(2, kind="file_write", plane="filesystem")],
        make_footer(),
    )


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


def test_round_trip_is_lossless(trace_path: Path) -> None:
    trace = read_trace(trace_path)
    assert trace.header.model_dump(mode="json") == make_header().model_dump(mode="json")
    assert trace.footer is not None
    assert trace.footer.model_dump(mode="json") == make_footer().model_dump(mode="json")
    assert [action.model_dump(mode="json") for action in trace.actions] == [
        make_action(1).model_dump(mode="json"),
        make_action(2, kind="file_write", plane="filesystem").model_dump(mode="json"),
    ]


def test_rewriting_a_read_trace_reproduces_the_bytes(trace_path: Path, tmp_path: Path) -> None:
    """§24: given identical input, output is byte-identical."""
    trace = read_trace(trace_path)
    again = write_trace(tmp_path / "again.jsonl", trace.header, list(trace.actions), trace.footer)
    assert again.read_bytes() == trace_path.read_bytes()


def test_unknown_fields_survive_a_round_trip(tmp_path: Path) -> None:
    """ARF is a wire format other tools may emit; a reader that drops what it does not
    recognise cannot round-trip a trace from a newer writer."""
    path = tmp_path / "run.jsonl"
    write_trace(path, make_header(), [make_action(1)], make_footer())

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["future_field"] = {"emitted_by": "some other tool"}
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    action = read_trace(path).actions[0]
    assert action.model_extra == {"future_field": {"emitted_by": "some other tool"}}
    assert "future_field" in serialize_record(action)


def test_records_serialise_to_one_line_each(trace_path: Path) -> None:
    lines = trace_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    assert json.loads(lines[0])["type"] == "run_header"
    assert json.loads(lines[-1])["type"] == "run_footer"


def test_serialisation_sorts_keys(trace_path: Path) -> None:
    line = trace_path.read_text(encoding="utf-8").splitlines()[1]
    keys = list(json.loads(line).keys())
    assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Incomplete traces (§11.1)
# ---------------------------------------------------------------------------


def test_a_trace_without_a_footer_is_incomplete(tmp_path: Path) -> None:
    path = write_trace(tmp_path / "run.jsonl", make_header(), [make_action(1)], footer=None)
    trace = read_trace(path)

    assert not trace.is_complete
    assert trace.evaluability() == "not_evaluable"
    assert trace.exit_reason is None
    assert "no run_footer" in (trace.not_evaluable_reason() or "")


def test_a_truncated_trace_is_incomplete_not_corrupt(trace_path: Path) -> None:
    """A run killed mid-write leaves a partial line. The correct reading is "no verdict",
    not "corrupt file"."""
    text = trace_path.read_text(encoding="utf-8")
    trace_path.write_text(text[: len(text) - 40], encoding="utf-8")

    trace = read_trace(trace_path)
    assert not trace.is_complete
    assert trace.evaluability() == "not_evaluable"
    assert "truncated" in (trace.not_evaluable_reason() or "")
    # Everything observed before the kill is still available.
    assert len(trace.actions) == 2


def test_malformed_json_anywhere_but_the_last_line_is_an_error(trace_path: Path) -> None:
    lines = trace_path.read_text(encoding="utf-8").splitlines()
    lines[1] = "{not json"
    trace_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(TraceError, match="line 2 is not valid JSON"):
        read_trace(trace_path)


def test_a_timeout_produces_a_complete_evaluable_trace(tmp_path: Path) -> None:
    """§12.7: a timeout is a *failure*, which is a thing the skill did — it is not the
    same as a trace that produced no outcome at all."""
    path = write_trace(
        tmp_path / "run.jsonl",
        make_header(),
        [make_action(1)],
        make_footer(exit_reason="timeout"),
    )
    trace = read_trace(path)
    assert trace.is_complete
    assert trace.evaluability() == "evaluable"
    assert trace.exit_reason == "timeout"


# ---------------------------------------------------------------------------
# Envelope rules
# ---------------------------------------------------------------------------


def test_an_empty_file_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    path.write_text("", encoding="utf-8")
    with pytest.raises(TraceError, match="line 0 must be a run_header"):
        read_trace(path)


def test_a_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(TraceError, match="not found"):
        read_trace(tmp_path / "absent.jsonl")


def test_line_one_must_be_a_header(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    path.write_text(serialize_record(make_action(1)) + "\n", encoding="utf-8")
    with pytest.raises(TraceError, match="line 1 must be a run_header"):
        read_trace(path)


def test_a_second_header_is_an_error(tmp_path: Path) -> None:
    """Two runs concatenated into one file is a different document, not a longer trace."""
    path = write_trace(tmp_path / "run.jsonl", make_header(), [make_action(1)], footer=None)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(serialize_record(make_header()) + "\n")
    with pytest.raises(TraceError, match="second run_header"):
        read_trace(path)


def test_nothing_may_follow_the_footer(trace_path: Path) -> None:
    with trace_path.open("a", encoding="utf-8") as handle:
        handle.write(serialize_record(make_action(9)) + "\n")
    with pytest.raises(TraceError, match="follows the run_footer"):
        read_trace(trace_path)


def test_the_writer_requires_a_header_first(tmp_path: Path) -> None:
    with TraceWriter(tmp_path / "run.jsonl") as writer, pytest.raises(TraceError, match="header"):
        writer.write_action(make_action(1))


def test_the_writer_rejects_a_repeated_seq(tmp_path: Path) -> None:
    """seq is the evidence reference findings cite; a repeat makes evidence ambiguous."""
    with TraceWriter(tmp_path / "run.jsonl") as writer:
        writer.write_header(make_header())
        writer.write_action(make_action(5))
        with pytest.raises(TraceError, match="seq must increase"):
            writer.write_action(make_action(5))


def test_the_writer_rejects_a_second_footer(tmp_path: Path) -> None:
    with TraceWriter(tmp_path / "run.jsonl") as writer:
        writer.write_header(make_header())
        writer.write_footer(make_footer())
        with pytest.raises(TraceError, match="at most one run_footer"):
            writer.write_footer(make_footer())


def test_the_writer_does_not_synthesise_a_footer(tmp_path: Path) -> None:
    """Writing one on the way out would turn a crashed run into a trace claiming it
    completed — which is exactly the reading the footer's absence exists to prevent."""
    path = tmp_path / "run.jsonl"
    with TraceWriter(path) as writer:
        writer.write_header(make_header())
        writer.write_action(make_action(1))
        assert not writer.wrote_footer

    assert not read_trace(path).is_complete


def test_a_crash_mid_run_leaves_what_was_observed(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    with pytest.raises(RuntimeError), TraceWriter(path) as writer:
        writer.write_header(make_header())
        writer.write_action(make_action(1))
        raise RuntimeError("the runner went away")

    trace = read_trace(path)
    assert not trace.is_complete
    assert len(trace.actions) == 1


# ---------------------------------------------------------------------------
# Coverage and lookups
# ---------------------------------------------------------------------------


def test_coverage_reports_unavailable_planes_with_their_reason(trace_path: Path) -> None:
    """§10.7: an enum alone gives a user nothing to act on."""
    unavailable = read_trace(trace_path).header.coverage.unavailable()
    assert set(unavailable) == {"filesystem_reads", "process"}
    assert "CAP_BPF" in unavailable["process"]


def test_a_plane_with_no_recorded_reason_still_reports_something() -> None:
    coverage = Coverage(process=PlaneCoverage(fidelity="unavailable"))
    assert "no reason recorded" in coverage.unavailable()["process"]


def test_overlay_diff_fidelity_is_usable() -> None:
    """It cannot refute a Plane A claim, but it is evidence (§10.8)."""
    assert PlaneCoverage(fidelity="overlay_diff").is_usable()
    assert not PlaneCoverage(fidelity="unavailable").is_usable()


def test_actions_can_be_found_by_seq_plane_and_kind(trace_path: Path) -> None:
    trace = read_trace(trace_path)
    assert trace.by_seq(2).kind == "file_write"
    assert len(trace.actions_on_plane("filesystem")) == 1
    assert len(trace.actions_of_kind("tool_call", "file_write")) == 2
    with pytest.raises(KeyError):
        trace.by_seq(99)


def test_actions_can_be_streamed(trace_path: Path) -> None:
    assert [action.seq for action in iter_actions(trace_path)] == [1, 2]


def test_streaming_stops_at_a_truncated_line(trace_path: Path) -> None:
    text = trace_path.read_text(encoding="utf-8")
    trace_path.write_text(text[: len(text) - 40], encoding="utf-8")
    assert [action.seq for action in iter_actions(trace_path)] == [1, 2]


def test_token_totals_keep_cache_reads_separate() -> None:
    """§9.3: a cost estimate built on a naive mean is systematically wrong without this."""
    tokens = make_footer().tokens
    assert tokens.cache_read == 6000
    assert tokens.total == 17_200
