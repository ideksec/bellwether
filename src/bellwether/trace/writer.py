"""Writing ARF traces (§11.1).

Append-only and streamable: each record is serialised and flushed as it happens, so a run
that is killed mid-way leaves everything observed up to that point. What it will not
leave is a footer — and that absence is the signal that the trace is incomplete.
"""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import IO, Self

from bellwether.determinism import canonical_json
from bellwether.errors import TraceError
from bellwether.trace.models import Action, ArfModel, RunFooter, RunHeader

__all__ = ["TraceWriter", "serialize_record", "write_trace"]


def serialize_record(record: ArfModel) -> str:
    """Serialise one ARF record to a single canonical JSON line.

    Keys sorted and floats rounded at this boundary, so two runs that observed the same
    thing produce byte-identical lines (§24).

    ``None`` fields are omitted rather than written as ``null``. Every optional ARF field
    defaults to ``None`` on read, so absence and ``null`` are indistinguishable to a
    reader and omitting them is lossless — while a trivial action carrying four ``:null``
    keys is a third larger than it needs to be, multiplied by the thousands of filesystem
    records a single run produces once Plane B is live. The one thing given up is
    re-emitting an *explicit* ``null`` some other writer chose to put in an unknown
    field, which carries no information a reader could act on.
    """
    payload = record.model_dump(mode="json", by_alias=True, exclude_none=True)
    line = canonical_json(payload)
    if "\n" in line:  # pragma: no cover — canonical_json never emits a newline
        raise TraceError("a serialised ARF record must occupy exactly one line")
    return line


class TraceWriter:
    """Writes one run's trace, enforcing the envelope rules as it goes.

    The ordering rules are enforced rather than documented because a malformed trace is
    discovered by the analysis layer hours later, by which point the run that produced it
    is gone.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: IO[str] | None = None
        self._header_written = False
        self._footer_written = False
        self._last_seq: int | None = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w", encoding="utf-8", newline="\n")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        # Deliberately does not write a footer on the way out, including on a clean exit.
        # A footer means the run reached an end Bellwether observed; synthesising one here
        # would turn a crashed run into a well-formed trace claiming it completed.
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    @property
    def wrote_footer(self) -> bool:
        return self._footer_written

    def write_header(self, header: RunHeader) -> None:
        if self._header_written:
            raise TraceError("a trace has exactly one run_header, and it was already written")
        self._write(header)
        self._header_written = True

    def write_action(self, action: Action) -> None:
        if not self._header_written:
            raise TraceError("the run_header must be written before any action")
        if self._footer_written:
            raise TraceError("no action may follow the run_footer")
        if self._last_seq is not None and action.seq <= self._last_seq:
            raise TraceError(
                f"action seq must increase: got {action.seq} after {self._last_seq}. "
                "seq is the evidence reference used by findings and assertions, so a "
                "repeated or reordered value makes evidence links ambiguous."
            )
        self._write(action)
        self._last_seq = action.seq

    def write_footer(self, footer: RunFooter) -> None:
        if not self._header_written:
            raise TraceError("the run_header must be written before the run_footer")
        if self._footer_written:
            raise TraceError("a trace has at most one run_footer, and it was already written")
        self._write(footer)
        self._footer_written = True

    def _write(self, record: ArfModel) -> None:
        if self._handle is None:
            raise TraceError("TraceWriter is used as a context manager and this one is not open")
        self._handle.write(serialize_record(record) + "\n")
        # Flushed per record: a trace is only useful for diagnosing a crash if it survives
        # one.
        self._handle.flush()


def write_trace(
    path: Path,
    header: RunHeader,
    actions: list[Action],
    footer: RunFooter | None = None,
) -> Path:
    """Write a complete trace in one call. Convenience for tests and golden traces."""
    with TraceWriter(path) as writer:
        writer.write_header(header)
        for action in actions:
            writer.write_action(action)
        if footer is not None:
            writer.write_footer(footer)
    return path
