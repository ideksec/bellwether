"""WP-13 (increment 2b-ii): the recording-proxy addon and its flow-record contract (§10.5).

The mitmproxy-shaped glue over ``decide_request``, tested with a plain fake request — no
mitmproxy, no container. What is exercised here is exactly the edges the decision core does not
own: that a forwarded request's headers are *mutated in place* with the real key, that a block
becomes the right synthetic status without touching headers, that the flow log the sidecar writes
round-trips into the objects the host feeds to the trace, and that a missing log is a loud failure
rather than a silent clean run. The live sidecar that runs this addon in a container is the next
slice, validated on CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from bellwether.capture import (
    BlockResponse,
    CapLedger,
    CredentialBroker,
    EgressAllowlist,
    EgressFlow,
    ProxyAddon,
    flow_record_line,
    parse_flow_record,
    read_flow_records,
    write_flow_records,
)
from bellwether.determinism import SeededRng, canonical_json

_REAL_KEY = "sk-real-ANTHROPIC-secret-value"
_ENVIRON = {"ANTHROPIC_API_KEY": _REAL_KEY}
_PROVIDERS = frozenset({"api.anthropic.com"})
_INFRA = frozenset({"telemetry.example-harness.com"})
_PROVIDER_OF_HOST = {"api.anthropic.com": "anthropic"}
_TS = "2026-08-06T00:00:00+00:00"


@dataclass
class _FakeRequest:
    """A structural stand-in for ``mitmproxy.http.Request`` — only the fields the addon reads
    and the mutable ``headers`` it writes to."""

    method: str = "POST"
    scheme: str = "https"
    pretty_host: str = "api.anthropic.com"
    port: int = 443
    path: str = "/v1/messages"
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | None = b""


def _broker() -> CredentialBroker:
    return CredentialBroker.for_run(
        {"anthropic": "ANTHROPIC_API_KEY"}, _ENVIRON, rng=SeededRng(1, "cred")
    )


def _addon(broker: CredentialBroker | None = None, caps: CapLedger | None = None) -> ProxyAddon:
    return ProxyAddon(
        allowlist=EgressAllowlist(provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA),
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        broker=broker or _broker(),
        provider_of_host=_PROVIDER_OF_HOST,
        caps=caps or CapLedger(max_requests=100, max_request_bytes=1_000_000),
        clock=lambda: _TS,
    )


# ---------------------------------------------------------------------------
# Applying a decision to a real request object
# ---------------------------------------------------------------------------


def test_a_forwarded_model_request_has_the_real_key_written_onto_it() -> None:
    """The injection is not just decided — it must land on the outgoing request. The addon
    mutates ``request.headers`` so the container's scoped token becomes the real key on the wire."""
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    addon = _addon(broker=broker)
    request = _FakeRequest(
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    )

    block = addon.on_request(request)

    assert block is None  # forwarded
    assert request.headers["Authorization"] == f"Bearer {_REAL_KEY}"


def test_a_denied_host_becomes_a_403_and_leaves_headers_untouched() -> None:
    addon = _addon()
    request = _FakeRequest(pretty_host="evil.example.com", headers={"X-Thing": "v"})

    block = addon.on_request(request)

    assert isinstance(block, BlockResponse)
    assert block.status == 403
    assert block.cap_exceeded is None
    assert "allowlist" in block.reason
    # A blocked request is never forwarded, so its headers must not be rewritten.
    assert request.headers == {"X-Thing": "v"}


def test_a_cap_refusal_becomes_a_429_naming_the_cap() -> None:
    caps = CapLedger(max_requests=1, max_request_bytes=1_000_000)
    addon = _addon(caps=caps)
    assert addon.on_request(_FakeRequest()) is None  # first forwards
    block = addon.on_request(_FakeRequest())

    assert block is not None
    assert block.status == 429
    assert block.cap_exceeded == "max_requests"


def test_permitted_infrastructure_forwards_without_injection() -> None:
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    addon = _addon(broker=broker)
    # Even if a scoped token rides on an infra request, it is not a model host, so no swap.
    request = _FakeRequest(
        pretty_host="telemetry.example-harness.com", headers={"Authorization": f"Bearer {token}"}
    )

    block = addon.on_request(request)

    assert block is None
    assert request.headers["Authorization"] == f"Bearer {token}"  # unchanged


def test_a_none_body_is_treated_as_empty() -> None:
    """mitmproxy hands ``content=None`` for a bodyless request; the addon must not choke."""
    addon = _addon()
    block = addon.on_request(_FakeRequest(content=None))
    assert block is None


# ---------------------------------------------------------------------------
# The recorded flows the host reads
# ---------------------------------------------------------------------------


def test_flows_are_recorded_in_order_including_blocks() -> None:
    addon = _addon()
    addon.on_request(_FakeRequest())  # forwarded
    addon.on_request(_FakeRequest(pretty_host="evil.example.com"))  # blocked

    flows = addon.flows()
    assert len(flows) == 2
    assert not flows[0].blocked
    assert flows[1].blocked


def test_a_recorded_flow_never_holds_a_credential_after_injection() -> None:
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    addon = _addon(broker=broker)
    request = _FakeRequest(headers={"Authorization": f"Bearer {token}"})
    addon.on_request(request)

    record = canonical_json(flow_record_line(addon.flows()[0]))
    assert _REAL_KEY not in record
    assert token not in record
    assert not broker.leaks_a_real_key(record)


# ---------------------------------------------------------------------------
# The sidecar ↔ host flow-record file contract
# ---------------------------------------------------------------------------


def _sample_flow(**overrides: object) -> EgressFlow:
    base: dict[str, object] = {
        "ts": _TS,
        "method": "POST",
        "scheme": "https",
        "host": "api.anthropic.com",
        "port": 443,
        "path": "/v1/messages",
        "egress_class": "model_api",
        "blocked": False,
        "request_headers": {"content-type": "application/json"},
        "request_body_bytes": 42,
        "request_body_sha256": "abc123",
        "response_status": 200,
        "response_size": 1024,
        "sni": "api.anthropic.com",
        "block_reason": "",
    }
    base.update(overrides)
    return EgressFlow(**base)  # type: ignore[arg-type]


def test_a_flow_round_trips_through_its_record_line() -> None:
    flow = _sample_flow()
    assert parse_flow_record(flow_record_line(flow)) == flow


def test_a_blocked_flow_with_null_response_fields_round_trips() -> None:
    """The dangerous serialization case: a blocked flow has no response, so the optional ints
    are ``None`` — they must survive as ``None``, not vanish or become 0."""
    flow = _sample_flow(
        blocked=True,
        egress_class="skill_attributed",
        response_status=None,
        response_size=None,
        block_reason="evil.example.com is not in the egress allowlist (default-deny, §10.5.0)",
    )
    restored = parse_flow_record(flow_record_line(flow))
    assert restored == flow
    assert restored.response_status is None
    assert restored.response_size is None


def test_the_record_line_is_canonical_and_stable() -> None:
    flow = _sample_flow()
    assert flow_record_line(flow) == flow_record_line(flow)
    assert "\n" not in flow_record_line(flow)


def test_the_flow_log_round_trips_through_the_shared_file(tmp_path: Path) -> None:
    flows = [_sample_flow(), _sample_flow(blocked=True, response_status=None, response_size=None)]
    path = tmp_path / "flows.jsonl"
    write_flow_records(path, flows)
    assert read_flow_records(path) == flows


def test_a_missing_flow_log_raises_rather_than_reading_as_a_clean_run(tmp_path: Path) -> None:
    """§10.5/§14: the sidecar always writes the log, so its absence means the proxy never ran.
    Returning ``[]`` would read as a skill that made no network calls — the exact clean-looking
    failure this plane exists to distrust. Absence must be loud."""
    with pytest.raises(FileNotFoundError):
        read_flow_records(tmp_path / "never-written.jsonl")


def test_an_empty_flow_log_is_a_real_zero_egress_run(tmp_path: Path) -> None:
    """A *written* but empty log is legitimate: the proxy ran and saw nothing. That is distinct
    from the missing-file case above — observed-empty, not unobserved."""
    path = tmp_path / "flows.jsonl"
    write_flow_records(path, [])
    assert read_flow_records(path) == []
