"""Cross-request canary reassembly — a marker split across several requests (§10.4.2).

:func:`~bellwether.capture.canary.scan_for_canaries` scans one corpus string: one request body,
one header, one DNS name. A skill that sends a planted marker in pieces shorter than the
:data:`~bellwether.capture.canary.MIN_WINDOW` window — four POSTs each carrying ten characters,
or four DNS lookups each carrying one label — leaves no single string with anything to find.
§10.4.2 asks for decoders and windowed matching over "each request individually **and** the
concatenated corpus"; this module is the concatenated half.

**What is concatenated.** Each request is reduced to a few *views* — the body, the URL path,
the host, each header value; for DNS, the query name — and every view is a *stream*: the
values it carried, request after request, in the order they were sent. A stream is kept per
destination scope (one host, or one DNS zone) **and** across all destinations, so a split
interleaved with traffic to another host is still contiguous in its own host's stream, and a
split spread across hosts is contiguous in the overall one.

**Normalise, do not enumerate the framings.** A chunk rarely travels bare — it rides in
``{"d":"<chunk>"}``, ``/collect?d=<chunk>``, ``<chunk>.attacker.example`` — and concatenating
the raw values interleaves the frame with the payload. Rather than parse each format, a
value's *frame* is what it shares with the previous value on the same stream: the common
prefix, cut back to its last non-alphanumeric character, and the common suffix, cut forward to
its first. What remains is the part that changed, and the changed parts are what the stream
concatenates. A constant header contributes nothing; a JSON, form, query, path or DNS-label
frame strips to its payload without a parser for any of them.

**When a hit counts.** Each new payload is scanned joined to the tail of its stream. A hit is
recorded only where the joined text holds a longer match than either side on its own — so it
genuinely spans requests — and not for a canary the completing request's own scan already
found (no double report). Per stream and canary, the first spanning hit is recorded, and
again once the whole marker is assembled; the hit is anchored to the request that completed it.

**The bounds, and what happens at them.** Memory is bounded by construction, whatever a skill
streams: a stream keeps the last :data:`STREAM_TAIL_CHARS` characters of its payload and the
head and tail of the previous value (for the frame), never the values themselves. A joined
scan is therefore at most ``2 × STREAM_TAIL_CHARS`` characters — inside the decoders'
sub-alignment bound, so a split base64 run still decodes at the cut. Every occurrence whose
encoded footprint is at most :data:`STREAM_TAIL_CHARS` is found at the request that completes
it. The number of streams is bounded at :data:`MAX_STREAMS`; a view that would open a stream
past it is **folded into one shared overflow stream** — still scanned, never dropped — and the
fold is reported (:attr:`CanaryReassembler.limit_reason`) so the run records that reassembly was
degraded rather than reading as fully observed.

**Limits.** A split whose pieces are each encoded independently (the
``encoded-chunked-thief`` expected failure §24 names, not yet in the corpus) is closed only
where the encoding concatenates: hex, percent- and entity-escapes always, base64 and base32
only when every piece but the last falls on the encoding's block boundary (3 and 5 bytes).
Still open: independently encoded base64/base32 pieces off those boundaries, each piece
reversed on its own, pieces sent out of order or with a frame that changes every time (a
sequence number ahead of the chunk), pieces interleaved with other values on the same stream,
and pieces spread across runs. Reassembly is per run; there is no cross-run corpus.

Deterministic (§24): views are fed in sorted order, scopes in a fixed order, streams live in an
insertion-ordered dict, and hits come back sorted.
"""

from __future__ import annotations

import html
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass, field

from bellwether.capture.canary import (
    Canary,
    CanaryDestination,
    CanaryFinding,
    scan_for_canaries,
)

__all__ = [
    "MAX_STREAMS",
    "OVERFLOW_STREAM",
    "STREAM_TAIL_CHARS",
    "CanaryReassembler",
    "ReassembledHit",
    "clip_to_ends",
]

#: How much of each stream is kept: the last this-many characters of its concatenated payload,
#: and the head and tail of its previous value. A marker whose encoded form fits in this many
#: characters (a 40-character marker is 54 in base64, 80 in hex, ~110 nested) is found whatever
#: the split; the joined scan text is at most twice this, which keeps every base64 run in it
#: inside the decoders' 4096-character sub-alignment bound.
STREAM_TAIL_CHARS = 2048

#: The most streams one run keeps. Each holds at most ``3 × STREAM_TAIL_CHARS`` characters, so
#: the reassembler's memory is bounded at roughly ``MAX_STREAMS × 6 KiB`` (ASCII) however many
#: hosts, headers or DNS zones a skill invents. A benign run opens a few dozen.
MAX_STREAMS = 1024

#: The one stream every view folds into once :data:`MAX_STREAMS` is reached.
OVERFLOW_STREAM = ("(overflow)", "(overflow)")


@dataclass(frozen=True)
class ReassembledHit:
    """A canary assembled across requests: which canary, on which view, how it was matched.

    ``via`` is the matcher's own label (``exact`` / ``decoded`` / ``windowed``) and ``length``
    the matched length; there is no single offset, because the match spans requests. ``view``
    names the stream it was assembled on and ``scope`` whether that was one destination's stream
    or the overall one.
    """

    canary_id: str
    length: int
    via: str
    view: str
    scope: str


@dataclass
class _Stream:
    #: The last STREAM_TAIL_CHARS characters of the payloads appended so far.
    tail: str = ""
    #: The head and tail of the previous value, and its full length — enough to find the frame
    #: the next value shares with it, and to strip it from the first value retroactively.
    prev_head: str = ""
    prev_tail: str = ""
    prev_len: int = 0
    values: int = 0
    #: Per canary, the longest spanning hit already recorded on this stream.
    reported: dict[str, int] = field(default_factory=dict)


def clip_to_ends(value: str) -> str:
    """The parts of a value a stream can ever use: all of it when short, else its two ends.

    A stream joins only the first and last :data:`STREAM_TAIL_CHARS` characters of a value, so
    a long value is cut to twice that from each end before anything else touches it. The middle
    of a gigabyte body is never copied or decoded here (the per-request scan still reads all of
    it); the generous margin keeps an escape decoded below from shrinking an end under the
    window.
    """
    keep = 2 * STREAM_TAIL_CHARS
    return value if len(value) <= 2 * keep else value[:keep] + value[-keep:]


def _unescape(value: str) -> str:
    """Percent- and entity-escapes decoded before the frame is found.

    An escaped piece starts with the same delimiter every time (``%51%6D…``, ``&#81;…``), which
    the frame would otherwise take for its own and strip from every piece. Decoding first reduces
    each value to what it means and leaves the frame to be found on that.
    """
    return html.unescape(urllib.parse.unquote(value))


def _is_delimiter(char: str) -> bool:
    return not char.isascii() or not char.isalnum()


def _frame(
    prev_head: str, prev_tail: str, cur_head: str, cur_tail: str, shorter: int
) -> tuple[int, int]:
    """The ``(prefix, suffix)`` lengths of the frame two consecutive values share.

    The common prefix is cut back to end on a delimiter and the common suffix cut forward to
    start on one, so a payload that happens to share its first or last characters with the
    previous one is not eaten: ``{"d":"ab…`` and ``{"d":"ac…`` share the frame ``{"d":"``, not
    ``{"d":"a``. The two together never exceed the shorter value.
    """
    prefix = 0
    for a, b in zip(prev_head, cur_head, strict=False):
        if a != b:
            break
        prefix += 1
    while prefix and not _is_delimiter(cur_head[prefix - 1]):
        prefix -= 1
    suffix = 0
    for a, b in zip(reversed(prev_tail), reversed(cur_tail), strict=False):
        if a != b:
            break
        suffix += 1
    while suffix and not _is_delimiter(cur_tail[len(cur_tail) - suffix]):
        suffix -= 1
    suffix = min(suffix, max(0, shorter - prefix))
    return prefix, suffix


def _payload_ends(head: str, tail: str, length: int, prefix: int, suffix: int) -> tuple[str, str]:
    """The first and last :data:`STREAM_TAIL_CHARS` characters of a value with its frame removed,
    reconstructed from the value's own head and tail (the middle of a long value is never kept)."""
    if length <= STREAM_TAIL_CHARS:
        payload = head[prefix : length - suffix]
        return payload[:STREAM_TAIL_CHARS], payload[-STREAM_TAIL_CHARS:]
    # The tail starts at ``length - len(tail)`` in the value; skip whatever of the prefix
    # reaches into it, and drop the suffix from its end.
    start = max(0, prefix - (length - len(tail)))
    end = max(start, len(tail) - suffix)
    payload_head = head[prefix : max(prefix, min(len(head), length - suffix))]
    return payload_head, tail[start:end]


class CanaryReassembler:
    """One run's cross-request canary scan (§10.4.2): feed it each request's views in order.

    ``destination`` is the §10.4.1 destination the hits are graded under (``other_host`` for the
    proxy, ``dns`` for the resolver). ``is_dns`` scans the joined text the way a query name is
    scanned — label separators stripped, case folded — which is right for DNS names and hosts.
    """

    def __init__(
        self,
        canaries: Sequence[Canary],
        *,
        destination: CanaryDestination,
        max_streams: int = MAX_STREAMS,
    ) -> None:
        self._canaries = tuple(sorted(canaries, key=lambda c: c.id))
        self._destination: CanaryDestination = destination
        self._max_streams = max_streams
        self._streams: dict[tuple[str, str], _Stream] = {}
        self._limit_reason = ""

    @property
    def limit_reason(self) -> str:
        """Why reassembly was degraded in this run, or ``""``: set once the stream bound folded a
        view into the shared overflow stream, so a run that hit it never reads as fully observed."""
        return self._limit_reason

    def feed(
        self,
        scope: str,
        views: Sequence[tuple[str, str, bool]],
        *,
        already_found: frozenset[str] = frozenset(),
    ) -> tuple[list[ReassembledHit], bool]:
        """Feed one request's ``(view, value, is_dns)`` triples, destined for ``scope``.

        Returns the spanning hits the request completed — sorted, at most one per canary — and
        whether any of its views had to fold into the overflow stream. ``already_found`` are the
        canaries the request's own scan found; they are not reported again here.
        """
        if not self._canaries:
            return [], False
        best: dict[str, ReassembledHit] = {}
        folded = False
        for view, raw, is_dns in sorted(views):
            value = clip_to_ends(raw) if is_dns else _unescape(clip_to_ends(raw))
            if not value:
                continue
            for scope_name, scope_key in (("destination", scope), ("all", "*")):
                key = (scope_key, view)
                stream = self._streams.get(key)
                if stream is None:
                    if len(self._streams) >= self._max_streams:
                        folded = True
                        key = OVERFLOW_STREAM
                        if not self._limit_reason:
                            self._limit_reason = (
                                f"cross-request canary reassembly reached its bound of "
                                f"{self._max_streams} streams; later views were folded into one "
                                "shared stream, so a split across them may not be reassembled "
                                "(§10.4.2)"
                            )
                        stream = self._streams.get(key)
                    if stream is None:
                        stream = self._streams[key] = _Stream()
                for hit in self._advance(stream, value, is_dns, view, scope_name):
                    if hit.canary_id in already_found:
                        continue
                    held = best.get(hit.canary_id)
                    if held is None or (hit.length, hit.view, hit.scope) > (
                        held.length,
                        held.view,
                        held.scope,
                    ):
                        best[hit.canary_id] = hit
        return [best[canary_id] for canary_id in sorted(best)], folded

    def _advance(
        self, stream: _Stream, value: str, is_dns: bool, view: str, scope: str
    ) -> list[ReassembledHit]:
        head, tail = value[:STREAM_TAIL_CHARS], value[-STREAM_TAIL_CHARS:]
        length = len(value)
        if stream.values == 0:
            stream.prev_head, stream.prev_tail, stream.prev_len = head, tail, length
            stream.values = 1
            return []
        if (head, tail, length) == (stream.prev_head, stream.prev_tail, stream.prev_len):
            return []  # a repeated value: nothing new can complete a marker
        prefix, suffix = _frame(
            stream.prev_head, stream.prev_tail, head, tail, min(length, stream.prev_len)
        )
        if stream.values == 1:
            # The first value's frame was unknown until now; strip it with this one's.
            _, first_tail = _payload_ends(
                stream.prev_head, stream.prev_tail, stream.prev_len, prefix, suffix
            )
            stream.tail = first_tail
        payload_head, payload_tail = _payload_ends(head, tail, length, prefix, suffix)
        before = stream.tail
        hits: list[ReassembledHit] = []
        if payload_head and before:
            hits = self._spanning(stream, before, payload_head, is_dns, view, scope)
        payload_len = max(0, length - prefix - suffix)
        joined = before + payload_tail if payload_len <= STREAM_TAIL_CHARS else payload_tail
        stream.tail = joined[-STREAM_TAIL_CHARS:]
        stream.prev_head, stream.prev_tail, stream.prev_len = head, tail, length
        stream.values += 1
        return hits

    def _spanning(
        self, stream: _Stream, before: str, after: str, is_dns: bool, view: str, scope: str
    ) -> list[ReassembledHit]:
        joined = self._best(before + after, is_dns)
        if not joined:
            return []
        left = self._best(before, is_dns)
        right = self._best(after, is_dns)
        markers = {c.id: len(c.marker) for c in self._canaries}
        hits: list[ReassembledHit] = []
        for canary_id, (length, via) in sorted(joined.items()):
            if length <= max(left.get(canary_id, (0, ""))[0], right.get(canary_id, (0, ""))[0]):
                continue  # the whole match sits on one side: not a split
            reported = stream.reported.get(canary_id)
            if reported is not None and (reported >= length or length < markers[canary_id]):
                continue  # recorded already; record again only once the marker is complete
            stream.reported[canary_id] = length
            hits.append(ReassembledHit(canary_id, length, via, view, scope))
        return hits

    def _best(self, text: str, is_dns: bool) -> dict[str, tuple[int, str]]:
        return {
            finding.canary_id: (finding.length, finding.via)
            for finding in _scan(text, self._canaries, self._destination, is_dns)
        }


def _scan(
    text: str, canaries: Sequence[Canary], destination: CanaryDestination, is_dns: bool
) -> list[CanaryFinding]:
    return scan_for_canaries(text, canaries, destination=destination, is_dns=is_dns)
