"""Reading ARF traces, and the incomplete-trace rule (§11.1).

**A trace whose last line is not a ``run_footer`` is incomplete.** Readers MUST treat an
incomplete trace as ``not_evaluable`` for every assertion and MUST NOT count it as a pass
or a fail; it contributes to ``n_errored``, never to ``n_evaluable`` (§13.1, §13.2).

That rule is why a truncated file is not a parse error here. A run killed by the runner
mid-write leaves a partial last line, and the correct reading of that file is "this run
produced no verdict", not "this file is corrupt".
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from bellwether.errors import TraceError
from bellwether.trace.models import Action, ExitReason, RunFooter, RunHeader

__all__ = ["Evaluability", "Trace", "iter_actions", "read_trace"]

#: Whether a trace can support an assertion at all (§13.2).
Evaluability = Literal["evaluable", "not_evaluable"]


@dataclass(frozen=True)
class Trace:
    """One run's ordered record of what was observed."""

    header: RunHeader
    actions: tuple[Action, ...]
    footer: RunFooter | None
    #: Why the trace is incomplete, where it is. Carried so the reason reaches the report
    #: rather than being reduced to a boolean somebody has to interpret.
    incomplete_reason: str | None = None
    source: Path | None = None

    @property
    def is_complete(self) -> bool:
        return self.footer is not None

    @property
    def exit_reason(self) -> ExitReason | None:
        return self.footer.exit_reason if self.footer else None

    def evaluability(self) -> Evaluability:
        """Whether assertions may be evaluated against this trace.

        Note that this is narrower than "did the run pass". A `timeout` produces a
        complete trace and a *failing* outcome — it is something the skill did. A trace
        with no footer produces no outcome at all (§12.7).
        """
        return "evaluable" if self.is_complete else "not_evaluable"

    def not_evaluable_reason(self) -> str | None:
        if self.is_complete:
            return None
        return self.incomplete_reason or "trace has no run_footer: the run did not reach an end"

    def actions_of_kind(self, *kinds: str) -> tuple[Action, ...]:
        wanted = set(kinds)
        return tuple(action for action in self.actions if action.kind in wanted)

    def actions_on_plane(self, *planes: str) -> tuple[Action, ...]:
        wanted = set(planes)
        return tuple(action for action in self.actions if action.plane in wanted)

    def by_seq(self, seq: int) -> Action:
        """Look up the evidence a finding points at. Findings cite ``seq``."""
        for action in self.actions:
            if action.seq == seq:
                return action
        raise KeyError(f"no action with seq {seq} in this trace")


def read_trace(path: Path) -> Trace:
    """Read a trace from a JSONL file."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise TraceError(f"{path}: trace file not found") from None
    return parse_trace(text, source=path)


def parse_trace(text: str, *, source: Path | None = None) -> Trace:
    """Parse a trace from JSONL text."""
    where = str(source) if source else "<trace>"
    lines = text.splitlines()
    if not lines:
        raise TraceError(f"{where}: trace is empty; line 0 must be a run_header")

    header = _parse_header(lines[0], where)

    actions: list[Action] = []
    footer: RunFooter | None = None
    incomplete_reason: str | None = None

    for number, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        if footer is not None:
            raise TraceError(f"{where}: line {number} follows the run_footer")

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # A partial final line is a killed run, not a corrupt file. Anywhere else it
            # is genuinely malformed and worth refusing.
            if number == len(lines):
                incomplete_reason = (
                    f"the last line is truncated: the run was killed while writing line {number}"
                )
                break
            raise TraceError(f"{where}: line {number} is not valid JSON") from None

        if not isinstance(record, dict):
            raise TraceError(f"{where}: line {number} is not a JSON object")

        kind = record.get("type")
        if kind == "action":
            actions.append(_validate(Action, record, where, number))
        elif kind == "run_footer":
            footer = _validate(RunFooter, record, where, number)
        elif kind == "run_header":
            raise TraceError(f"{where}: line {number} is a second run_header")
        else:
            raise TraceError(
                f"{where}: line {number} has unknown record type {kind!r}; "
                "expected 'action' or 'run_footer'"
            )

    if footer is None and incomplete_reason is None:
        incomplete_reason = "trace has no run_footer: the run did not reach an end"

    return Trace(
        header=header,
        actions=tuple(actions),
        footer=footer,
        incomplete_reason=incomplete_reason,
        source=source,
    )


def iter_actions(path: Path) -> Iterator[Action]:
    """Stream a trace's actions without holding the whole file in memory."""
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if number == 1 or not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return  # truncated final line: stop, do not raise
            if isinstance(record, dict) and record.get("type") == "action":
                yield _validate(Action, record, str(path), number)


def _parse_header(line: str, where: str) -> RunHeader:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        raise TraceError(f"{where}: line 1 is not valid JSON; it must be the run_header") from None
    if not isinstance(record, dict) or record.get("type") != "run_header":
        raise TraceError(f"{where}: line 1 must be a run_header")
    return _validate(RunHeader, record, where, 1)


def _validate[T](model: type[T], record: dict[str, Any], where: str, line: int) -> T:
    try:
        return model.model_validate(record)  # type: ignore[attr-defined,no-any-return]
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"]) or "<record>"
        raise TraceError(f"{where}: line {line}: {location}: {first['msg']}") from None
