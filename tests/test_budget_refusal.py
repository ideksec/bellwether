"""A per-run cap refusal ends the run as ``budget_exceeded`` (§10.5.1, §12.7).

The proxy refused a request that would cross ``max_requests``/``max_request_bytes`` with a 429,
and then recorded it as the *permitted* request it would have been — ``blocked=False`` for a
request that never left. Nothing downstream could see a cap had been hit: the `CapLedger`
docstring promised `exit_reason: budget_exceeded` and no code produced it. On claude-code the CLI
reported the proxy's 429 as `api_error_status: 429`, which the provider-rejection check (#94)
reads as a provider rate limit — so the run was *retried* against a fresh proxy that hit the same
cap, and the evaluation ended as "infrastructure". The refusal is now recorded as one, and the
executor settles the run as `budget_exceeded` before it asks whether a 429 was the provider's.
"""

from __future__ import annotations

from pathlib import Path

from bellwether.capture import CapLedger
from bellwether.capture.egress import budget_refusal
from bellwether.capture.proxy_addon import (
    BLOCK_STATUS_BUDGET,
    flow_record_line,
    parse_flow_record,
)
from bellwether.trace import egress_actions
from tests.test_proxy_addon import _addon, _FakeRequest


def _over_cap():  # type: ignore[no-untyped-def]
    addon = _addon(caps=CapLedger(max_requests=1, max_request_bytes=1_000_000))
    assert addon.on_request(_FakeRequest()) is None
    block = addon.on_request(_FakeRequest())
    return addon, block


def test_a_cap_refusal_is_recorded_as_a_refusal() -> None:
    addon, block = _over_cap()
    assert block is not None and block.status == BLOCK_STATUS_BUDGET
    forwarded, refused = addon.flows()
    assert not forwarded.blocked and not forwarded.cap_exceeded
    assert refused.blocked, "a request that never left must not read as sent"
    assert refused.cap_exceeded == "max_requests"
    assert "egress budget exceeded" in refused.block_reason


def test_a_websocket_frame_over_a_cap_is_recorded_the_same_way() -> None:
    addon = _addon(caps=CapLedger(max_requests=1, max_request_bytes=1_000_000))
    host = "api.anthropic.com"
    assert addon.on_websocket_message(host, 443, scheme="https", path="/", content=b"a") is None
    assert addon.on_websocket_message(host, 443, scheme="https", path="/", content=b"b")
    assert [flow.cap_exceeded for flow in addon.flows()] == ["", "max_requests"]


def test_the_cap_survives_the_sidecar_to_host_wire() -> None:
    addon, _ = _over_cap()
    refused = addon.flows()[-1]
    assert parse_flow_record(flow_record_line(refused)).cap_exceeded == "max_requests"


def test_the_host_finds_the_cap_and_the_trace_carries_it() -> None:
    addon, _ = _over_cap()
    flows = addon.flows()
    assert budget_refusal(flows) == "max_requests"
    assert budget_refusal(flows[:1]) == ""
    actions = egress_actions(flows, start_seq=0)
    assert actions[-1].action["cap_exceeded"] == "max_requests"


def test_the_executor_settles_a_cap_as_budget_exceeded() -> None:
    """Pinned on the source because the executor needs a Docker daemon; the CI container test
    ``test_a_proxy_cap_ends_a_claude_code_run_as_budget_exceeded`` drives it with the real CLI."""
    source = (
        Path(__file__).resolve().parents[1] / "src" / "bellwether" / "cli" / "execution.py"
    ).read_text(encoding="utf-8")
    cap = source.index("budget_cap = budget_refusal(egress_flows)")
    settle = source.index('exit_reason = "budget_exceeded"')
    assert cap < settle
    assert "if budget_cap:" in source[settle - 400 : settle]
