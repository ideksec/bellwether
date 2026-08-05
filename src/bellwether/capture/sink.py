"""Plane A's host-owned event sink (§10.1).

Where the harness writes hook events, it must write to a sink the container cannot
rewrite. A regular file in a writable mount is not acceptable — a skill can truncate it.
This sink is a FIFO created and owned by the host, bind-mounted into the container as a
single file, with permissions that make it **write-only from the container's side**:

- The host creates the FIFO with owner-only permissions, opens it, and only then chmods
  it to write-only (``0222``). The host's already-open descriptor is unaffected — an open
  file descriptor is not re-checked against the mode — while every *subsequent* open for
  reading is refused. This closes the FIFO's one architectural leak: a FIFO delivers
  data to whichever reader gets it first, so a skill that could open the read end could
  *steal* events out of the evidence stream, which is worse than truncating a log file
  because the theft leaves no trace. Write-only-for-everyone (not ``0622``) because the
  container's uid can coincide with the FIFO owner's uid on an unprivileged host.
- Received bytes live in host memory and are never written back anywhere the container
  can reach. From the container's perspective the sink is append-only by construction.
- The FIFO node is a bind-mounted single file, so ``unlink`` from inside fails with
  ``EBUSY`` — the container cannot even remove the sink, only decline to write to it.

The reader is a host-side thread that polls with a timeout and drains against a
deadline. Nothing here ever blocks indefinitely on the observed process: a FIFO whose
writer never appears, never writes, or dies mid-line must not decide whether the
observer finishes (§10.0 — and the WP-4 review found exactly this hang, in the
collector's handling of a FIFO the *container* had created).

The sink records, it does not judge: a line that is not valid JSON is kept as a
``malformed`` event rather than dropped, because a skill spraying garbage into the
evidence stream is itself evidence. Plane A is the least trustworthy plane under
adversarial conditions either way (§10.1); the ground-truth planes do not consume it.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import select
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from bellwether.capture.filesystem import PlaneStatus
from bellwether.errors import BellwetherError

__all__ = ["HostEventSink", "SinkEvent", "SinkStats"]

_POLL_INTERVAL_MS = 200
_READ_CHUNK = 64 * 1024

#: Everything after this many bytes of one line is dropped and the event marked
#: truncated. Bounds a single event; a tool result embedded in a hook event can be
#: large, but a line this long is not an event any consumer would keep whole.
_DEFAULT_MAX_LINE_BYTES = 1 << 20
#: Beyond this, event *content* stops being stored and only counts are kept. Bounds the
#: host's memory against a skill that floods the sink; the flood itself stays visible.
_DEFAULT_MAX_TOTAL_BYTES = 64 << 20


@dataclass(frozen=True)
class SinkEvent:
    """One line received on the sink."""

    index: int
    received_at: dt.datetime
    #: The raw line as received (truncated at the line cap). Kept even where parsing
    #: failed — garbage in the evidence stream is evidence.
    raw: str
    #: The parsed JSON object, or ``None`` where the line was not one.
    payload: dict[str, Any] | None = None
    #: The line was not a JSON object. Recorded, never dropped.
    malformed: bool = False
    #: The line exceeded the per-line cap, or the writer died mid-line.
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return not self.malformed and not self.truncated


@dataclass
class SinkStats:
    """What the sink saw, including what it declined to store."""

    events: int = 0
    bytes_received: int = 0
    #: Events whose content was dropped after the total-bytes cap. Nonzero means the
    #: harness-events plane is `partial` for this run, and the reason says why.
    dropped_after_cap: int = 0
    malformed: int = 0
    truncated: int = 0


class HostEventSink:
    """A host-owned FIFO sink for Plane A harness events (§10.1).

    Use as a context manager, or call :meth:`start` / :meth:`stop` explicitly::

        with HostEventSink(run_dir / "events") as sink:
            ...  # start the container with sink.path bind-mounted in
        events = sink.events  # populated after exit; stop() drains with a deadline
    """

    def __init__(
        self,
        path: Path,
        *,
        max_line_bytes: int = _DEFAULT_MAX_LINE_BYTES,
        max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
    ) -> None:
        self.path = path
        self.max_line_bytes = max_line_bytes
        self.max_total_bytes = max_total_bytes
        self.stats = SinkStats()
        self._events: list[SinkEvent] = []
        self._fd: int | None = None
        self._thread: threading.Thread | None = None
        self._stop_deadline: float | None = None
        self._stop_requested = threading.Event()
        self._lock = threading.Lock()
        self._buffer = b""

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            raise BellwetherError("the sink is already started")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            raise BellwetherError(
                f"refusing to reuse an existing path as the event sink: {self.path}. "
                "A pre-existing node could be a plant; the sink must be created by the "
                "host, this run."
            )
        os.mkfifo(self.path, 0o600)
        # Open read+write: holding our own write end means the descriptor never signals
        # end-of-file as container-side writers come and go, so the reader is driven by
        # its poll deadline rather than by writer behaviour. Opened *before* the chmod —
        # an already-open descriptor is not re-checked — after which no process at all,
        # owner included, can open the FIFO for reading.
        self._fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK)
        self.path.chmod(0o222)
        self._stop_requested.clear()
        self._thread = threading.Thread(target=self._read_loop, name="bw-event-sink", daemon=True)
        self._thread.start()

    def stop(self, *, drain_seconds: float = 2.0) -> list[SinkEvent]:
        """Stop reading, drain what is already buffered, and return the events.

        The drain runs against a monotonic deadline. The sink never waits on the
        container: whatever has not arrived when the deadline passes was not evidence
        this run produced in time to be collected.
        """
        thread = self._thread
        if thread is None:
            return self.events
        self._stop_deadline = time.monotonic() + drain_seconds
        self._stop_requested.set()
        thread.join(timeout=drain_seconds + 5.0)
        if thread.is_alive():  # pragma: no cover — the loop's own deadline prevents this
            raise BellwetherError("the sink reader did not stop by its deadline")
        self._thread = None
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        return self.events

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()

    @property
    def events(self) -> list[SinkEvent]:
        with self._lock:
            return list(self._events)

    def status(self) -> PlaneStatus:
        """This plane's fidelity for the coverage block (§10.7)."""
        if self.stats.dropped_after_cap:
            return PlaneStatus(
                fidelity="partial",
                reason=(
                    f"the event sink's {self.max_total_bytes}-byte cap was hit; "
                    f"{self.stats.dropped_after_cap} later event(s) were counted but "
                    "not stored"
                ),
            )
        return PlaneStatus(fidelity="full")

    # -- the reader thread --------------------------------------------------

    def _read_loop(self) -> None:
        fd = self._fd
        assert fd is not None
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        while True:
            if self._stop_requested.is_set():
                deadline = self._stop_deadline or 0.0
                if time.monotonic() >= deadline:
                    break
            events = poller.poll(_POLL_INTERVAL_MS)
            if not events:
                if self._stop_requested.is_set():
                    break  # drained: stop was requested and nothing is arriving
                continue
            try:
                chunk = os.read(fd, _READ_CHUNK)
            except BlockingIOError:  # pragma: no cover — poll said readable
                continue
            if chunk:
                self._consume(chunk)
        self._flush_partial()

    def _consume(self, chunk: bytes) -> None:
        self.stats.bytes_received += len(chunk)
        self._buffer += chunk
        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                # An over-cap line with no newline yet must not grow without bound.
                if len(self._buffer) > self.max_line_bytes:
                    self._record_line(self._buffer, truncated=True)
                    self._buffer = b""
                return
            line, self._buffer = self._buffer[:newline], self._buffer[newline + 1 :]
            if line:
                self._record_line(line)

    def _flush_partial(self) -> None:
        """A writer that died mid-line still produced evidence; keep it, marked."""
        if self._buffer:
            self._record_line(self._buffer, truncated=True)
            self._buffer = b""

    def _record_line(self, line: bytes, *, truncated: bool = False) -> None:
        self.stats.events += 1
        if self.stats.bytes_received > self.max_total_bytes:
            self.stats.dropped_after_cap += 1
            return
        if len(line) > self.max_line_bytes:
            line = line[: self.max_line_bytes]
            truncated = True

        raw = line.decode("utf-8", "replace")
        payload: dict[str, Any] | None = None
        malformed = False
        if not truncated:
            try:
                decoded = json.loads(raw)
            except ValueError:
                malformed = True
            else:
                if isinstance(decoded, dict):
                    payload = decoded
                else:
                    malformed = True  # a bare scalar or array is not an event object

        if malformed:
            self.stats.malformed += 1
        if truncated:
            self.stats.truncated += 1

        with self._lock:
            self._events.append(
                SinkEvent(
                    index=self.stats.events - 1,
                    received_at=dt.datetime.now(dt.UTC),
                    raw=raw,
                    payload=payload,
                    malformed=malformed,
                    truncated=truncated,
                )
            )
