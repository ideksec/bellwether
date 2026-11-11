"""§10.4.2 at the proxy — the decode-and-window scan continues past a body's first slice under
the sidecar's own per-run budget, and a spent budget is recorded on the flow.

Host-side scans gained a :class:`DecodeBudget` in the previous brick; the recording proxy still
scanned a request body to its first 256 KiB only, so a marker inside an encoded body past that
was found nowhere. These tests sit at the wiring, as ``test_canary_reassembly.py`` does: the
sidecar's mitmproxy-facing ``_RecordingAddon`` built by ``build_addon`` from a ``SidecarConfig``
(the path a live request takes), the flow log the host reads back, and the Plane C action.

Every positive case first asserts that the scan *without* a budget finds nothing in the body —
otherwise the test would pass on the old code and prove nothing.
"""

from __future__ import annotations

import base64
import json
from dataclasses import fields
from pathlib import Path

from bellwether.capture import mint_canaries
from bellwether.capture.canary import (
    MAX_SCAN_CHARS,
    SIDECAR_DECODE_BUDGET_CHARS,
    DecodeBudget,
    scan_for_canaries,
)
from bellwether.capture.egress import EgressAllowlist, EgressFlow, make_flow
from bellwether.capture.proxy_addon import (
    _flow_to_dict,
    flow_record_line,
    parse_flow_record,
    read_flow_records,
)
from bellwether.trace import egress_actions, egress_body_actions
from tests.test_canary_reassembly import _post, _recording, _send
from tests.test_sidecar_entry import _MODEL_BODY, _FakeRequest

_CANARIES = mint_canaries(7)
_MARKER = _CANARIES[0].marker


def _deep_body(padding: int = 300_000, marker: str = _MARKER) -> str:
    """One base64 run with the marker after ``padding`` bytes of filler, behind a short prefix
    so the run starts off the slice alignment. No whole-value encoding of the marker is in it."""
    return "k=" + base64.b64encode(("x" * padding + marker + "y" * 64).encode()).decode()


def _alone_is_clean_without_a_budget(body: str) -> None:
    assert len(body) > MAX_SCAN_CHARS
    assert scan_for_canaries(body, _CANARIES, destination="other_host") == []


def _hits(flow: EgressFlow) -> list[tuple[str, str, str]]:
    return [(hit.canary_id, hit.via, hit.channel) for hit in flow.canary_hits]


# ---------------------------------------------------------------------------
# The sidecar: a marker deep in a body
# ---------------------------------------------------------------------------


def test_a_marker_encoded_deep_in_a_request_body_is_found_at_the_proxy(tmp_path: Path) -> None:
    body = _deep_body()
    _alone_is_clean_without_a_budget(body)
    recording, flow_log = _recording(tmp_path, _CANARIES)
    _send(recording, _post(body))

    [flow] = read_flow_records(flow_log)  # through the wire the host reads
    assert _hits(flow) == [(_CANARIES[0].id, "decoded", "body")]
    assert flow.canary_decode_limit == ""
    # The last hops: Plane D → Plane C, a critical leak anchored to the request that carried it.
    plane_d = egress_actions([flow])
    plane_c = egress_body_actions([(plane_d[0], flow.canary_hits)], start_seq=1)
    assert [(a.kind, a.action["severity"], a.correlation.anchor_seq) for a in plane_c] == [  # type: ignore[union-attr]
        ("canary_leak", "critical", 0)
    ]
    assert "canary_decode_limit" not in plane_d[0].action


def test_a_marker_deep_in_a_websocket_frame_is_found(tmp_path: Path) -> None:
    """Frames go through the same per-frame decision as a request body, under the same budget."""
    from tests.test_websocket_egress import _Frame, _WsFlow

    body = _deep_body()
    _alone_is_clean_without_a_budget(body)
    recording, flow_log = _recording(tmp_path, _CANARIES)
    flow = _WsFlow(
        request=_FakeRequest(method="GET", host="collector.example", path="/stream", content=b"")
    )
    flow.websocket.messages.append(_Frame(from_client=True, content=body.encode()))
    recording.websocket_message(flow)
    [recorded] = read_flow_records(flow_log)
    assert recorded.method == "WEBSOCKET"
    assert _hits(recorded) == [(_CANARIES[0].id, "decoded", "body")]


def test_a_blocked_request_is_scanned_under_the_budget_too(tmp_path: Path) -> None:
    """The body is scanned before the allowlist decides, so the attempt to a refused host is
    evidence as well — and it draws on the same allowance."""
    recording, flow_log = _recording(tmp_path, _CANARIES)
    _send(recording, _post(_deep_body(), host="attacker.example"))
    [flow] = read_flow_records(flow_log)
    assert flow.blocked
    assert _hits(flow) == [(_CANARIES[0].id, "decoded", "body")]
    assert recording._addon._decode_budget.spent > 0


# ---------------------------------------------------------------------------
# The budget: per run, spent, and said
# ---------------------------------------------------------------------------


def test_the_sidecar_holds_one_budget_per_run_at_its_own_limit(tmp_path: Path) -> None:
    recording, _ = _recording(tmp_path, _CANARIES)
    budget = recording._addon._decode_budget
    assert isinstance(budget, DecodeBudget)
    assert budget.limit == SIDECAR_DECODE_BUDGET_CHARS < DecodeBudget().limit
    assert (budget.spent, budget.exhausted) == (0, "")


def test_a_second_large_body_draws_on_what_the_first_left(tmp_path: Path) -> None:
    """Two bodies, each needing one slice past the first, under a budget of one slice: the first
    is found, the second is cut short — clean, with the reason on its flow. A fresh allowance
    per request would find both, which is the hole a per-string bound leaves."""
    recording, flow_log = _recording(tmp_path, _CANARIES)
    recording._addon._decode_budget.limit = MAX_SCAN_CHARS
    first, second = _deep_body(), _deep_body(marker=_CANARIES[1].marker)
    _send(recording, _post(first))
    _send(recording, _post(second))
    _send(recording, _post('{"status": "ok"}'))

    flows = read_flow_records(flow_log)
    assert _hits(flows[0]) == [(_CANARIES[0].id, "decoded", "body")]
    assert flows[0].canary_decode_limit == ""
    assert flows[1].canary_hits == ()
    assert "reached its budget of" in flows[1].canary_decode_limit
    assert "whole-value" in flows[1].canary_decode_limit
    # A small request after the budget is spent was not cut short, so it carries no limit.
    assert flows[2].canary_decode_limit == ""


def test_a_spent_budget_survives_the_wire_and_reaches_plane_d(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path, _CANARIES)
    recording._addon._decode_budget.limit = 0
    _send(recording, _post(_deep_body()))
    [flow] = read_flow_records(flow_log)
    assert flow.canary_decode_limit
    assert parse_flow_record(flow_record_line(flow)) == flow
    assert egress_actions([flow])[0].action["canary_decode_limit"] == flow.canary_decode_limit


def test_a_plain_marker_past_a_spent_budget_is_still_found(tmp_path: Path) -> None:
    """A spent budget degrades the scan to the whole-value pass; it does not blind it."""
    recording, flow_log = _recording(tmp_path, _CANARIES)
    recording._addon._decode_budget.limit = 0
    _send(recording, _post("p" * (MAX_SCAN_CHARS + 5000) + _MARKER))
    [flow] = read_flow_records(flow_log)
    assert _hits(flow) == [(_CANARIES[0].id, "exact", "body")]
    assert flow.canary_decode_limit  # and the flow still says the decode pass was cut short


def test_model_api_bodies_spend_nothing(tmp_path: Path) -> None:
    """Model-API requests are graded host-side by read state and are not scanned here, so the
    harness's own (large) model calls never eat the allowance the skill's traffic is held to."""
    recording, flow_log = _recording(tmp_path, _CANARIES)
    body = json.dumps({**json.loads(_MODEL_BODY), "system": "s" * (2 * MAX_SCAN_CHARS)}).encode()
    _send(recording, _FakeRequest(path="/v1/messages", content=body))
    [flow] = read_flow_records(flow_log)
    assert flow.egress_class == "model_api" and not flow.blocked
    assert recording._addon._decode_budget.spent == 0
    assert flow.canary_decode_limit == ""


def test_the_flow_log_is_byte_identical_across_two_runs(tmp_path: Path) -> None:
    logs = []
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        recording, flow_log = _recording(tmp_path / name, _CANARIES)
        recording._addon._decode_budget.limit = MAX_SCAN_CHARS
        for body in (_deep_body(), _deep_body(), "small"):
            _send(recording, _post(body))
        logs.append(flow_log.read_bytes())
    assert logs[0] == logs[1]


# ---------------------------------------------------------------------------
# The record contract
# ---------------------------------------------------------------------------


def _flow(**overrides: object) -> EgressFlow:
    return make_flow(
        ts="2026-11-11T00:00:00+00:00",
        method="POST",
        scheme="https",
        host="collector.example",
        port=443,
        path="/ingest",
        provider_endpoints=(),
        infrastructure_endpoints=(),
        allowlist=EgressAllowlist(
            provider_endpoints=frozenset(),
            infrastructure_endpoints=frozenset(),
            extra=frozenset({"collector.example"}),
        ),
        **overrides,  # type: ignore[arg-type]
    )


def test_make_flow_without_a_budget_scans_as_it_always_did() -> None:
    flow = _flow(request_body=_deep_body().encode(), canaries=_CANARIES)
    assert flow.canary_hits == () and flow.canary_decode_limit == ""


def test_the_flow_record_carries_every_flow_field() -> None:
    """The record is written field by field so a new one cannot silently drop from the wire —
    which only holds if something compares the two. A field on ``EgressFlow`` that the record
    does not carry never reaches the host: the sidecar would know the scan was cut short and the
    trace would read as a full one."""
    record = _flow_to_dict(_flow())
    assert set(record) == {field.name for field in fields(EgressFlow)}


def test_a_record_from_a_sidecar_without_the_field_still_parses() -> None:
    """An older sidecar image writes no ``canary_decode_limit``; its record reads as not cut
    short rather than failing the run."""
    flow = _flow()
    payload = json.loads(flow_record_line(flow))
    del payload["canary_decode_limit"]
    assert parse_flow_record(json.dumps(payload)) == flow


def test_the_executor_folds_the_sidecar_limit_into_the_credentials_coverage() -> None:
    """Pinned on the source, as the other executor wiring is: the executor needs a Docker daemon.
    The flows' limit is read before the header (and its coverage block) is built and joins the
    reason the credentials plane degrades with."""
    source = (
        Path(__file__).resolve().parents[1] / "src" / "bellwether" / "cli" / "execution.py"
    ).read_text(encoding="utf-8")
    read = source.index("flow.canary_decode_limit for flow in egress_flows")
    fold = source.index(
        "credentials_limit = reassembly_limit or decode_budget.exhausted or sidecar_decode_limit"
    )
    header = source.index("header = RunHeader(")
    assert read < fold < header
    assert 'PlaneStatus(fidelity="partial", reason=credentials_limit)' in source[header:]
