"""WebSocket frames are egress: decided, recorded, scanned and capped (§10.5.0, §10.5.1, §10.5.2).

Reproduced against the pinned mitmproxy 12.2.3 with the real ``sidecar/proxy/proxy_entry.py``
(spec-notes): after a permitted upgrade, mitmproxy relays frames through ``websocket_message``,
which the addon did not implement. A frame carrying a planted canary reached an allowlisted
server with only the ``GET`` upgrade on record, and 21 frames went through a proxy capped at
``max_requests=5``. Every client-to-server frame is now decided like a request body.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from bellwether.capture.proxy_addon import BLOCK_STATUS_BUDGET, read_flow_records
from bellwether.capture.sidecar_entry import _RecordingAddon, build_addon
from tests.test_sidecar_entry import _HOST_ENVIRON, _TS, _config, _FakeRequest, _host_broker

_MARKER = "BWCANARYzq8X4rT2mN7pL5vK"


@dataclass
class _Frame:
    """The subset of a mitmproxy ``WebSocketMessage`` the hook touches."""

    from_client: bool
    content: bytes
    dropped: bool = False

    def drop(self) -> None:
        self.dropped = True


@dataclass
class _WebSocketData:
    messages: list[_Frame] = field(default_factory=list)


@dataclass
class _WsFlow:
    """An ``HTTPFlow`` after a 101: the upgrade request and the frames so far."""

    request: _FakeRequest
    websocket: _WebSocketData = field(default_factory=_WebSocketData)
    killed: bool = False
    killable: bool = True

    def kill(self) -> None:
        self.killed = True


def _recording(tmp_path: Path, **overrides: object) -> tuple[_RecordingAddon, Path]:
    flow_log = tmp_path / "flows.jsonl"
    config = replace(
        _config(_host_broker(), str(flow_log)),
        allowlist_extra=("ws.example",),
        canary_markers=(("c-aws", _MARKER),),
        **overrides,  # type: ignore[arg-type]
    )
    addon = build_addon(config, _HOST_ENVIRON, clock=lambda: _TS)
    return _RecordingAddon(addon, str(flow_log), render=lambda block: block), flow_log


def _upgrade() -> _FakeRequest:
    return _FakeRequest(method="GET", scheme="https", host="ws.example", port=443, path="/stream")


def _send(recording: _RecordingAddon, flow: _WsFlow, frame: _Frame) -> _Frame:
    flow.websocket.messages.append(frame)
    recording.websocket_message(flow)
    return frame


def test_a_frame_carrying_a_canary_is_recorded_with_the_hit(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path)
    flow = _WsFlow(request=_upgrade())
    frame = _send(recording, flow, _Frame(True, f"exfil {_MARKER}".encode()))

    assert not frame.dropped  # recorded and forwarded, as a request body with a canary is
    [record] = read_flow_records(flow_log)
    assert (record.method, record.scheme, record.host, record.path) == (
        "WEBSOCKET",
        "wss",
        "ws.example",
        "/stream",
    )
    assert [hit.canary_id for hit in record.canary_hits] == ["c-aws"]
    assert _MARKER not in flow_log.read_text(encoding="utf-8")  # recorded by reference


def test_frames_are_charged_to_the_per_run_caps(tmp_path: Path) -> None:
    """The cap bypass: each frame now counts, and the one that crosses a cap is dropped."""
    recording, flow_log = _recording(tmp_path, max_requests=3)
    flow = _WsFlow(request=_upgrade())
    frames = [_send(recording, flow, _Frame(True, f"frame {i}".encode())) for i in range(5)]

    assert [frame.dropped for frame in frames] == [False, False, False, True, True]
    assert len(read_flow_records(flow_log)) == 5  # every frame is on record, refused or not


def test_a_server_frame_is_not_the_sandboxs_egress(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path)
    frame = _send(recording, _WsFlow(request=_upgrade()), _Frame(False, _MARKER.encode()))

    assert not frame.dropped
    assert read_flow_records(flow_log) == []


def test_a_frame_that_cannot_be_decided_is_dropped_and_recorded(tmp_path: Path) -> None:
    """Fail closed: anything that raises drops the frame rather than relaying it undecided."""
    recording, flow_log = _recording(tmp_path)

    class _Unreadable(_Frame):
        @property  # type: ignore[override]
        def content(self) -> bytes:
            raise ValueError("frame payload must not be recorded")

        @content.setter
        def content(self, _value: bytes) -> None:
            pass

    frame = _send(recording, _WsFlow(request=_upgrade()), _Unreadable(True, b""))

    assert frame.dropped
    [record] = read_flow_records(flow_log)
    assert record.blocked and "websocket_message hook failed (ValueError)" in record.block_reason
    assert "must not be recorded" not in flow_log.read_text(encoding="utf-8")


def test_a_frame_the_log_cannot_record_is_dropped(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path)
    flow_log.unlink()
    flow_log.mkdir()  # writing the log now fails
    frame = _send(recording, _WsFlow(request=_upgrade()), _Frame(True, b"hello"))
    assert frame.dropped


def test_a_cap_refusal_is_a_budget_refusal(tmp_path: Path) -> None:
    recording, _ = _recording(tmp_path, max_requests=1)
    addon = recording._addon  # the decision the hook applied
    first = addon.on_websocket_message("ws.example", 443, scheme="https", path="/s", content=b"a")
    second = addon.on_websocket_message("ws.example", 443, scheme="https", path="/s", content=b"b")
    assert first is None
    assert second is not None and second.status == BLOCK_STATUS_BUDGET
    assert second.cap_exceeded == "max_requests"
