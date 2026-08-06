"""WP-13 (increment 2b-i): the recording proxy's per-request decision (§10.5).

The security brain the mitmproxy sidecar runs, tested pure. The order of operations is
itself a security property — allowlist before cap before inject, record either way — so
each step is exercised on its own and the whole sequence end to end. The sidecar container
that applies these decisions in a live container is the next slice; it needs an environment
that can pull mitmproxy and route traffic, which this build environment cannot.
"""

from __future__ import annotations

from bellwether.capture import (
    CapLedger,
    CredentialBroker,
    EgressAllowlist,
    ProxyDecision,
    decide_request,
)
from bellwether.determinism import SeededRng, canonical_json

_REAL_KEY = "sk-real-ANTHROPIC-secret-value"
_ENVIRON = {"ANTHROPIC_API_KEY": _REAL_KEY}
_PROVIDERS = frozenset({"api.anthropic.com"})
_INFRA = frozenset({"telemetry.example-harness.com"})
_PROVIDER_OF_HOST = {"api.anthropic.com": "anthropic"}


def _broker() -> CredentialBroker:
    return CredentialBroker.for_run(
        {"anthropic": "ANTHROPIC_API_KEY"}, _ENVIRON, rng=SeededRng(1, "cred")
    )


def _decide(
    host: str,
    *,
    body: bytes = b"",
    caps: CapLedger | None = None,
    broker: CredentialBroker | None = None,
    extra: frozenset[str] = frozenset(),
    auth: str | None = None,
) -> ProxyDecision:
    broker = broker or _broker()
    headers = {"Content-Type": "application/json"}
    if auth is not None:
        headers["Authorization"] = f"Bearer {auth}"
    return decide_request(
        ts="2026-08-06T00:00:00+00:00",
        method="POST",
        scheme="https",
        host=host,
        port=443,
        path="/v1/messages",
        headers=headers,
        body=body,
        allowlist=EgressAllowlist(
            provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA, extra=extra
        ),
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        broker=broker,
        provider_of_host=_PROVIDER_OF_HOST,
        caps=caps or CapLedger(max_requests=100, max_request_bytes=1_000_000),
    )


# ---------------------------------------------------------------------------
# (1) allowlist
# ---------------------------------------------------------------------------


def test_a_denied_host_is_blocked_and_still_recorded() -> None:
    decision = _decide("evil.example.com")
    assert decision.action == "block"
    assert decision.flow.blocked and decision.flow.egress_class == "skill_attributed"
    assert not decision.injected


def test_a_permitted_provider_is_forwarded() -> None:
    decision = _decide("api.anthropic.com", auth="bw-placeholder")
    assert decision.action == "forward"
    assert not decision.flow.blocked


def test_permitted_infrastructure_forwards_its_own_headers_uninjected() -> None:
    decision = _decide("telemetry.example-harness.com")
    assert decision.action == "forward"
    assert decision.flow.egress_class == "harness_infrastructure"
    assert not decision.injected  # no credential swap for non-model traffic


# ---------------------------------------------------------------------------
# (2) caps — enforced before forwarding, only counted when forwarded
# ---------------------------------------------------------------------------


def test_a_request_cap_blocks_before_the_request_leaves() -> None:
    caps = CapLedger(max_requests=1, max_request_bytes=1_000_000)
    first = _decide("api.anthropic.com", caps=caps)
    assert first.action == "forward"
    second = _decide("api.anthropic.com", caps=caps)
    assert second.action == "block"
    assert second.cap_exceeded == "max_requests"


def test_a_byte_cap_blocks_an_oversized_body() -> None:
    caps = CapLedger(max_requests=100, max_request_bytes=10)
    decision = _decide("api.anthropic.com", body=b"x" * 11, caps=caps)
    assert decision.action == "block"
    assert decision.cap_exceeded == "max_request_bytes"


def test_a_blocked_request_does_not_consume_the_cap() -> None:
    """A denied host must not spend the sandbox-scoped token's budget — otherwise a skill
    could exhaust the cap with blocked attempts and deny the run its real calls."""
    caps = CapLedger(max_requests=2, max_request_bytes=1_000_000)
    _decide("evil.example.com", caps=caps)  # blocked at the allowlist
    _decide("evil.example.com", caps=caps)
    assert caps.requests == 0  # nothing counted
    assert _decide("api.anthropic.com", caps=caps).action == "forward"


# ---------------------------------------------------------------------------
# (3) credential injection — only for a permitted model-API request
# ---------------------------------------------------------------------------


def test_a_model_api_request_gets_the_real_key_injected() -> None:
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    decision = _decide("api.anthropic.com", broker=broker, auth=token)
    assert decision.injected
    assert decision.upstream_headers["Authorization"] == f"Bearer {_REAL_KEY}"


def test_injection_never_happens_for_a_blocked_host() -> None:
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    decision = _decide("evil.example.com", broker=broker, auth=token)
    assert decision.action == "block"
    assert not decision.injected


# ---------------------------------------------------------------------------
# (4) recording — the flow is written either way, and never holds a credential
# ---------------------------------------------------------------------------


def test_the_recorded_flow_never_holds_the_real_key_even_after_injection() -> None:
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    decision = _decide("api.anthropic.com", broker=broker, auth=token)
    # The real key is on the wire (upstream_headers) but not in the record.
    assert decision.upstream_headers["Authorization"] == f"Bearer {_REAL_KEY}"
    record = canonical_json({"headers": dict(decision.flow.request_headers)})
    assert _REAL_KEY not in record
    assert token not in record  # the scoped token is redacted too
    assert not broker.leaks_a_real_key(record)


def test_a_blocked_flow_carries_its_reason() -> None:
    decision = _decide("evil.example.com")
    assert decision.flow.block_reason
