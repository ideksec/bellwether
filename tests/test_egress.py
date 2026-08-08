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
    mint_canaries,
    provider_hosts,
    redact_headers,
)
from bellwether.capture.egress import EgressCanaryHit, EgressFlow
from bellwether.capture.proxy_addon import flow_record_line, parse_flow_record
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


def test_a_userinfo_authority_routes_to_the_real_host_not_the_userinfo() -> None:
    """BW-27/BW-40: in an RFC-3986 ``userinfo@host`` authority the host is what follows the
    ``@``. A naive ``rsplit(':')`` port-strip read ``api.anthropic.com:443@evil.com`` as the
    provider; parsing it as a client does routes it to ``evil.com`` — skill-attributed and
    blocked, never ``model_api``."""
    host = "api.anthropic.com:443@evil.com"
    assert (
        classify_egress(host, provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA)
        == "skill_attributed"
    )
    assert not _allowlist().permits(host)
    flow = _flow(host)
    assert flow.host == "evil.com"
    assert flow.egress_class == "skill_attributed"
    assert flow.blocked


def test_a_leading_dot_host_does_not_match_a_provider() -> None:
    """BW-27/BW-40: a leading-dot host has an empty first label, so it is not a subdomain of the
    provider — the old ``endswith('.' + endpoint)`` matched ``.api.anthropic.com`` against
    ``api.anthropic.com`` and mis-permitted it."""
    host = ".api.anthropic.com"
    assert (
        classify_egress(host, provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA)
        == "skill_attributed"
    )
    assert not _allowlist().permits(host)


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


def test_client_free_text_headers_are_redacted_not_kept_verbatim() -> None:
    """BW-14: ``User-Agent`` and ``Accept`` are skill/client free text — a skill can write a
    secret into either — so they are redacted like any other value. Only structural headers
    (content-type, host, anthropic-version, …) are kept verbatim."""
    redacted = redact_headers(
        {
            "User-Agent": "curl/8.0 SECRET-IN-UA",
            "Accept": "SECRET-IN-ACCEPT",
            "Content-Type": "application/json",
        }
    )
    assert redacted["User-Agent"] == "<redacted>"
    assert redacted["Accept"] == "<redacted>"
    assert redacted["Content-Type"] == "application/json"  # structural, still kept


def test_a_secret_in_user_agent_does_not_reach_the_flow_record() -> None:
    """BW-14 at the artifact boundary: a value placed in ``User-Agent`` must be ``<redacted>``
    in the resulting ``EgressFlow.request_headers`` — the record that ends up in an artifact."""
    flow = make_flow(
        ts="2026-08-06T00:00:00+00:00",
        method="POST",
        scheme="https",
        host="api.anthropic.com",
        port=443,
        path="/v1/messages",
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        allowlist=_allowlist(),
        request_headers={
            "User-Agent": "curl/8.0 BW-SECRET-IN-UA",
            "Content-Type": "application/json",
        },
    )
    assert flow.request_headers["User-Agent"] == "<redacted>"
    assert flow.request_headers["Content-Type"] == "application/json"
    assert "BW-SECRET-IN-UA" not in json.dumps(dict(flow.request_headers))


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


def _body_flow(host: str, body: bytes, *, canaries: object = ()) -> EgressFlow:
    return make_flow(
        ts="2026-08-06T00:00:00+00:00",
        method="POST",
        scheme="https",
        host=host,
        port=443,
        path="/collect",
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        allowlist=_allowlist(frozenset({host})),
        request_body=body,
        canaries=canaries,  # type: ignore[arg-type]
    )


def test_make_flow_scans_a_non_model_body_for_a_canary() -> None:
    """§10.5.2: a marker in a POST body to a non-model host is exfiltration — a critical other_host
    leak. The proxy scans the body where it exists and records the hit by reference; the value is
    reduced to a digest and never reaches the flow record."""
    canaries = mint_canaries(7)
    marker = canaries[0].marker
    flow = _body_flow("attacker.example", f"stolen={marker}".encode(), canaries=canaries)
    assert [h.canary_id for h in flow.canary_hits] == [canaries[0].id]
    assert flow.canary_hits[0].destination == "other_host"
    # The record written to the shared log holds no marker — only the by-reference hit.
    assert marker not in flow_record_line(flow)


def test_make_flow_skips_the_model_api_body() -> None:
    """A body to the model API is not scanned here: sending a canary to the model can be legitimate
    after a read (``canary_in_context``), and grading it needs the host's read state — a follow-on,
    exactly as model-API URLs are skipped."""
    canaries = mint_canaries(7)
    flow = _body_flow("api.anthropic.com", f"x={canaries[0].marker}".encode(), canaries=canaries)
    assert flow.canary_hits == ()


def test_make_flow_records_no_hits_without_canaries() -> None:
    flow = _body_flow("attacker.example", b"just some data")
    assert flow.canary_hits == ()


def test_flow_record_round_trips_canary_hits() -> None:
    """The sidecar writes the hit to the shared log and the host reads it back identically (§10.5)."""
    flow = EgressFlow(
        ts="2026-08-06T00:00:00+00:00",
        method="POST",
        scheme="https",
        host="attacker.example",
        port=443,
        path="/collect",
        egress_class="skill_attributed",
        blocked=False,
        canary_hits=(
            EgressCanaryHit(
                canary_id="c1", destination="other_host", offset=7, length=40, via="exact"
            ),
        ),
    )
    restored = parse_flow_record(flow_record_line(flow))
    assert restored.canary_hits == flow.canary_hits


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
    # The §11.2/§1581 kinds: a permitted flow is "egress_request" (NOT a bare "egress"),
    # which is the kind the canonicalizer maps to an egress:<host> capability. Emitting
    # "egress" left every permitted flow silently uncanonicalised (unscored).
    assert [a.kind for a in actions] == ["egress_request", "egress_blocked"]
    assert all(a.plane == "egress" for a in actions)
    assert [a.seq for a in actions] == [0, 1]


def test_a_permitted_flow_canonicalises_to_an_egress_capability() -> None:
    """The regression the kind-name bug hid: a permitted egress flow must reach the
    capability sets as ``egress:<host>``. The prior test only checked the kind string, so a
    permitted flow that canonicalised to *nothing* passed it — the exact 'test asserts the
    wrong thing' shape the project warns about."""
    from bellwether.trace import NormalizationContext
    from bellwether.trace.canonical import capability_for

    action = egress_actions([_flow("api.anthropic.com")])[0]
    capability = capability_for(action, NormalizationContext(workspace_root="/work/x"))
    assert capability is not None
    assert capability.tier1 == "egress:api.anthropic.com"


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
