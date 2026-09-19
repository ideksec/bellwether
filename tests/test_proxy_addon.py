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

from dataclasses import dataclass, field, fields
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
    mint_canaries,
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
    and the mutable ``headers`` it writes to.

    ``host`` and ``host_header`` are separate here because they are separate on the real object,
    and collapsing them is what let R1 through: a fake that could only express "the destination"
    could not express a client that addresses one host and names another, so no test could fail
    on it. ``host_header`` defaults to agreeing with ``host`` — the ordinary case — and a test
    that wants the spoof sets it.
    """

    method: str = "POST"
    scheme: str = "https"
    host: str = "api.anthropic.com"
    host_header: str | None = None
    port: int = 443
    path: str = "/v1/messages"
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | None = b""

    def __post_init__(self) -> None:
        if self.host_header is None:
            self.host_header = self.host


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


def test_on_request_records_a_canary_hit_from_a_non_model_body() -> None:
    """The addon threads the run's canaries into ``decide_request``, so a marker in a POST body to a
    skill-attributed host is recorded on the flow by reference — the wiring that lets the sidecar
    catch POST-body exfil the URL scan misses (§10.5.2)."""
    canaries = mint_canaries(7)
    addon = ProxyAddon(
        allowlist=EgressAllowlist(
            provider_endpoints=_PROVIDERS,
            infrastructure_endpoints=_INFRA,
            extra=frozenset({"attacker.example"}),
        ),
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        broker=_broker(),
        provider_of_host=_PROVIDER_OF_HOST,
        caps=CapLedger(max_requests=100, max_request_bytes=1_000_000),
        clock=lambda: _TS,
        canaries=tuple(canaries),
    )
    addon.on_request(
        _FakeRequest(
            host="attacker.example",
            path="/collect",
            content=f"exfil={canaries[0].marker}".encode(),
        )
    )
    hits = addon.flows()[0].canary_hits
    assert [h.canary_id for h in hits] == [canaries[0].id]
    assert hits[0].destination == "other_host"


def test_a_denied_host_becomes_a_403_and_leaves_headers_untouched() -> None:
    addon = _addon()
    request = _FakeRequest(host="evil.example.com", headers={"X-Thing": "v"})

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
        host="telemetry.example-harness.com", headers={"Authorization": f"Bearer {token}"}
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
    addon.on_request(_FakeRequest(host="evil.example.com"))  # blocked

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


# ---------------------------------------------------------------------------
# R1 / R6 — the asserted identity is not the destination, and a header is a channel
# ---------------------------------------------------------------------------


def test_a_spoofed_host_header_cannot_borrow_the_provider_identity() -> None:
    """R1 (critical): a request addressed to a non-allowlisted host while *claiming* to be the
    provider must be blocked, and must never receive the brokered key.

    The addon used to hand ``request.pretty_host`` to the decision, and mitmproxy's own docstring
    for that property says it "may not reflect the actual destination as the Host header could be
    spoofed". Inside this sandbox the Host header is written by the evaluated code, so the
    allowlist authorised ``api.anthropic.com`` while the connection went to the attacker, and the
    broker swapped in the real provider key on the way. Decided on ``host`` now, and a claimed
    authority that disagrees is refused before the allowlist is even consulted.
    """
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    addon = _addon(broker=broker)
    request = _FakeRequest(
        host="attacker.example",
        host_header="api.anthropic.com",
        headers={"Authorization": f"Bearer {token}"},
    )

    block = addon.on_request(request)

    assert isinstance(block, BlockResponse)
    assert block.status == 403
    assert "connection goes to attacker.example" in block.reason
    # The real key never reached the wire: the request is untouched, still carrying the token.
    assert request.headers["Authorization"] == f"Bearer {token}"
    flow = addon.flows()[0]
    assert flow.blocked and flow.host == "attacker.example"
    # The record names the discrepancy, so the attempt is legible rather than an ordinary denial.
    assert flow.claimed_host == "api.anthropic.com"


def test_a_spoofed_host_header_cannot_launder_an_allowlisted_destination() -> None:
    """The mirror image: a request that really does go to the provider but claims to be some
    other host is equally inconsistent, and equally refused. The rule is "the two agree", not
    "the destination is allowlisted" — a proxy that resolved the disagreement in either direction
    would be choosing which of two attacker-supplied identities to believe."""
    addon = _addon()

    block = addon.on_request(_FakeRequest(host_header="attacker.example"))

    assert isinstance(block, BlockResponse)
    assert "Host header names attacker.example" in block.reason


def test_a_spoofed_sni_is_refused_like_a_spoofed_host_header() -> None:
    """The third asserted identity: the name offered in the TLS handshake. Same rule."""
    addon = _addon()

    block = addon.on_request(_FakeRequest(), sni="attacker.example")

    assert isinstance(block, BlockResponse)
    assert "TLS SNI names attacker.example" in block.reason


def test_the_brokered_key_is_never_written_onto_a_plaintext_request() -> None:
    """A key on an ``http://`` request is readable by anything on the path. The provider host is
    allowlisted and classified ``model_api`` either way, so without the scheme check the only
    thing standing between the real key and a plaintext hop was the client's choice of scheme."""
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    addon = _addon(broker=broker)
    request = _FakeRequest(scheme="http", port=80, headers={"Authorization": f"Bearer {token}"})

    assert addon.on_request(request) is None  # forwarded: the host is allowlisted
    assert request.headers["Authorization"] == f"Bearer {token}"  # but un-upgraded


def test_a_canary_in_a_request_header_is_found_before_redaction() -> None:
    """R6: ``make_flow`` redacts header values, and the canary scan used to run on the body only —
    so ``X-Export: <marker>`` to an allowlisted host produced no finding at all and survived into
    the record as ``<redacted>``. Headers are scanned first now, and the hit names its channel."""
    canaries = mint_canaries(7)
    addon = ProxyAddon(
        allowlist=EgressAllowlist(
            provider_endpoints=_PROVIDERS,
            infrastructure_endpoints=_INFRA,
            extra=frozenset({"paste.example"}),
        ),
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        broker=_broker(),
        provider_of_host=_PROVIDER_OF_HOST,
        caps=CapLedger(max_requests=100, max_request_bytes=1_000_000),
        clock=lambda: _TS,
        canaries=tuple(canaries),
    )

    addon.on_request(
        _FakeRequest(
            method="GET", host="paste.example", path="/", headers={"X-Export": canaries[0].marker}
        )
    )

    flow = addon.flows()[0]
    assert [hit.canary_id for hit in flow.canary_hits] == [canaries[0].id]
    assert flow.canary_hits[0].channel == "header:x-export"
    assert flow.canary_hits[0].destination == "other_host"
    # And the value itself still never reaches the record.
    assert canaries[0].marker not in flow_record_line(flow)


def test_the_fake_request_models_every_field_the_protocol_declares() -> None:
    """The structural reason R1 survived: the fake had one ``pretty_host`` field where the real
    object has two, so no test could express a client that addresses one host and names another.
    The attack was not representable, which is a stronger kind of untested than "we forgot".

    A ``Protocol`` gives no runtime enforcement — a fake satisfies it by having *enough* fields,
    never all of them — so a field added to :class:`RequestLike` for a new decision would not
    fail anything here. This checks the fake is complete, so the next field the addon starts
    reading has to be modelled before its behaviour can be tested at all.
    """
    from bellwether.capture.proxy_addon import RequestLike

    declared = set(RequestLike.__annotations__)
    modelled = {field.name for field in fields(_FakeRequest)}

    missing = sorted(declared - modelled)
    assert not missing, (
        f"_FakeRequest does not model {missing}, so no test here can vary them. A fake that "
        "cannot express an input cannot fail on it."
    )
