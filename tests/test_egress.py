"""WP-13 (increment 1): the host-side egress semantics (§10.5, §10.5.0, §10.5.1).

The deterministic core of Plane D — classification, the default-deny allowlist, per-run
caps, header redaction, the egress-induced-failure correlation, and the ARF records they
produce — tested offline. The mitmproxy sidecar, credential injection, and bridge (the
container half) plug in behind ``RecordingProxy`` and are the next increment; the done-when
that asserts the real key never enters the container belongs to that one.
"""

from __future__ import annotations

import json

import pytest

from bellwether.capture import (
    CapLedger,
    EgressAllowlist,
    RecordingProxy,
    classify_egress,
    correlate_egress_induced_failure,
    make_flow,
    provider_hosts,
    redact_headers,
)
from bellwether.capture.egress import EgressFlow
from bellwether.determinism import canonical_json, stable_hash
from bellwether.trace import egress_actions

_PROVIDERS = frozenset({"api.anthropic.com", "api.openai.com"})
_INFRA = frozenset({"telemetry.example-harness.com"})


def _allowlist(extra: frozenset[str] = frozenset()) -> EgressAllowlist:
    return EgressAllowlist(
        provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA, extra=extra
    )


# ---------------------------------------------------------------------------
# §10.5.0 classification
# ---------------------------------------------------------------------------


def test_provider_host_is_model_api() -> None:
    assert (
        classify_egress(
            "api.anthropic.com", provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA
        )
        == "model_api"
    )


def test_infrastructure_endpoint_is_harness_infrastructure() -> None:
    assert (
        classify_egress(
            "telemetry.example-harness.com",
            provider_endpoints=_PROVIDERS,
            infrastructure_endpoints=_INFRA,
        )
        == "harness_infrastructure"
    )


def test_everything_else_is_skill_attributed() -> None:
    assert (
        classify_egress(
            "evil.example.com", provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA
        )
        == "skill_attributed"
    )


def test_a_subdomain_of_a_provider_matches() -> None:
    assert (
        classify_egress(
            "eu.api.anthropic.com", provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA
        )
        == "model_api"
    )


def test_a_lookalike_domain_does_not_match() -> None:
    """A label-boundary suffix match, so ``notanthropic.com`` cannot pose as the provider."""
    assert (
        classify_egress(
            "notapi.anthropic.com.evil.com",
            provider_endpoints=_PROVIDERS,
            infrastructure_endpoints=_INFRA,
        )
        == "skill_attributed"
    )
    assert (
        classify_egress(
            "api.anthropic.com.evil.com",
            provider_endpoints=_PROVIDERS,
            infrastructure_endpoints=_INFRA,
        )
        == "skill_attributed"
    )


def test_provider_hosts_parses_base_urls() -> None:
    hosts = provider_hosts(["https://api.anthropic.com/v1", "api.openai.com:443"])
    assert hosts == {"api.anthropic.com", "api.openai.com"}


# ---------------------------------------------------------------------------
# §10.5.0 default-deny allowlist
# ---------------------------------------------------------------------------


def test_providers_and_infrastructure_are_permitted() -> None:
    allow = _allowlist()
    assert allow.permits("api.anthropic.com")
    assert allow.permits("telemetry.example-harness.com")


def test_an_unknown_host_is_blocked_with_a_reason() -> None:
    allow = _allowlist()
    assert not allow.permits("evil.example.com")
    assert "default-deny" in allow.block_reason("evil.example.com")


def test_an_extra_allowlist_entry_is_permitted() -> None:
    allow = _allowlist(extra=frozenset({"cache.example.com"}))
    assert allow.permits("cache.example.com")


# ---------------------------------------------------------------------------
# §10.5.1 per-run caps
# ---------------------------------------------------------------------------


def test_the_request_cap_is_hit_at_the_boundary() -> None:
    ledger = CapLedger(max_requests=2, max_request_bytes=1_000_000)
    assert ledger.would_exceed(10) is None
    ledger.record(10)
    assert ledger.would_exceed(10) is None
    ledger.record(10)
    assert ledger.would_exceed(10) == "max_requests"


def test_the_byte_cap_is_hit_when_the_next_body_would_cross_it() -> None:
    ledger = CapLedger(max_requests=100, max_request_bytes=100)
    ledger.record(60)
    assert ledger.would_exceed(40) is None
    assert ledger.would_exceed(41) == "max_request_bytes"


# ---------------------------------------------------------------------------
# §10.5 header redaction — an allowlist, so a new auth header cannot leak
# ---------------------------------------------------------------------------


def test_redaction_keeps_allowlisted_headers_and_redacts_the_rest() -> None:
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer sk-real-secret",
        "x-api-key": "another-secret",
    }
    redacted = redact_headers(headers)
    assert redacted["Content-Type"] == "application/json"
    assert redacted["Authorization"] == "<redacted>"
    assert redacted["x-api-key"] == "<redacted>"
    # The names survive so the request shape is legible; the secret values do not.
    assert "sk-real-secret" not in json.dumps(redacted)
    assert "another-secret" not in json.dumps(redacted)


# ---------------------------------------------------------------------------
# make_flow — the raw request → artifact-fit record boundary
# ---------------------------------------------------------------------------


def _flow(host: str, *, body: bytes = b"", extra: frozenset[str] = frozenset()) -> EgressFlow:
    return make_flow(
        ts="2026-08-06T00:00:00+00:00",
        method="POST",
        scheme="https",
        host=host,
        port=443,
        path="/v1/messages",
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        allowlist=_allowlist(extra),
        request_headers={
            "Authorization": "Bearer sk-real-secret",
            "Content-Type": "application/json",
        },
        request_body=body,
    )


def test_make_flow_reduces_the_body_to_a_digest_and_length() -> None:
    body = b'{"prompt": "hello"}'
    flow = _flow("api.anthropic.com", body=body)
    assert flow.request_body_bytes == len(body)
    assert flow.request_body_sha256 == stable_hash(body)
    # The body value is nowhere on the record; only its digest and length.
    assert "hello" not in json.dumps(
        {"h": dict(flow.request_headers), "s": flow.request_body_sha256}
    )


def test_make_flow_blocks_an_unallowlisted_host() -> None:
    flow = _flow("evil.example.com")
    assert flow.blocked
    assert flow.egress_class == "skill_attributed"
    assert flow.block_reason


def test_make_flow_permits_a_provider() -> None:
    flow = _flow("api.anthropic.com")
    assert not flow.blocked
    assert flow.egress_class == "model_api"


def test_only_permitted_skill_attributed_traffic_counts_as_egress() -> None:
    # Blocked skill traffic does not count (it is a separate egress_blocked record);
    # permitted model_api traffic does not count; permitted skill traffic does.
    assert not _flow("evil.example.com").counts_as_egress
    assert not _flow("api.anthropic.com").counts_as_egress
    assert _flow("cache.example.com", extra=frozenset({"cache.example.com"})).counts_as_egress


# ---------------------------------------------------------------------------
# §10.5.0 egress-induced-failure correlation
# ---------------------------------------------------------------------------


def test_a_failure_with_blocked_egress_is_flagged() -> None:
    assert correlate_egress_induced_failure(assertion_failed=True, blocked_flows=1)


def test_a_failure_with_no_blocked_egress_is_not_flagged() -> None:
    assert not correlate_egress_induced_failure(assertion_failed=True, blocked_flows=0)


def test_a_pass_is_never_flagged() -> None:
    assert not correlate_egress_induced_failure(assertion_failed=False, blocked_flows=3)


# ---------------------------------------------------------------------------
# ARF records (§11.2) via trace.egress_actions
# ---------------------------------------------------------------------------


def test_permitted_and_blocked_flows_get_distinct_kinds() -> None:
    flows = [_flow("api.anthropic.com"), _flow("evil.example.com")]
    actions = egress_actions(flows)
    assert [a.kind for a in actions] == ["egress", "egress_blocked"]
    assert all(a.plane == "egress" for a in actions)
    assert [a.seq for a in actions] == [0, 1]


def test_the_record_carries_class_and_body_digest_but_not_the_body() -> None:
    body = b'{"canary": "BW-SECRET-VALUE"}'
    actions = egress_actions([_flow("api.anthropic.com", body=body)])
    payload = actions[0].action
    assert payload["egress_class"] == "model_api"
    assert payload["request_body_sha256"] == stable_hash(body)
    assert payload["request_body_bytes"] == len(body)
    # Neither the body nor the auth secret is anywhere in the serialised record.
    blob = canonical_json(payload)
    assert "BW-SECRET-VALUE" not in blob
    assert "sk-real-secret" not in blob


def test_a_blocked_record_carries_its_reason() -> None:
    actions = egress_actions([_flow("evil.example.com")])
    assert actions[0].action["block_reason"]


def test_egress_actions_are_deterministic() -> None:
    flows = [_flow("api.anthropic.com"), _flow("evil.example.com")]
    a = [canonical_json(x.action) for x in egress_actions(flows)]
    b = [canonical_json(x.action) for x in egress_actions(flows)]
    assert a == b


def test_start_seq_offsets_the_sequence_space() -> None:
    actions = egress_actions([_flow("api.anthropic.com")], start_seq=17)
    assert actions[0].seq == 17


# ---------------------------------------------------------------------------
# The RecordingProxy seam fails loud, not silent
# ---------------------------------------------------------------------------


def test_the_base_recording_proxy_refuses_rather_than_observing_nothing() -> None:
    """A partial proxy that silently observed nothing would produce a zero-egress trace that
    reads as a clean skill — the exact failure §10.5/WP-14 guards against. The base raises."""
    proxy = RecordingProxy()
    with pytest.raises(NotImplementedError):
        proxy.flows()
