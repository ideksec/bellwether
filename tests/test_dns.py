"""WP-15: the controlled DNS resolver's host-side core (§10.6).

The allowlist decision, the query record, and the canary scan over a query name — the pure
half, offline. The resolver *sidecar* (``dnslib``/``coredns`` in a container, the UDP/53
lockdown of §3.3 invariant 3, the ``dns_query``/``dns_blocked`` trace actions) is the
container half and is exercised on CI, exactly like the recording proxy.

Why a DNS plane exists at all: the recording proxy sees HTTP, not UDP/53, so without a
controlled resolver a skill can encode a secret into query *labels* and exfiltrate it while
the proxy records nothing. These tests pin the two properties that close that channel — a
default-deny allowlist that a lookalike name cannot slip past, and a canary scan that is
label-separator-aware so a payload chunked across labels is still found.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from bellwether.capture import (
    ControlledResolver,
    DnsAllowlist,
    DnsQuery,
    decide_query,
    mint_canaries,
    parse_query_record,
    query_record_line,
    read_query_records,
    scan_query_for_canaries,
    write_query_records,
)
from bellwether.capture.dns import DNS_DESTINATION
from bellwether.determinism import canonical_json
from bellwether.trace import dns_actions

# ---------------------------------------------------------------------------
# The allowlist: default-deny, matching on a label boundary
# ---------------------------------------------------------------------------


def _allowlist(*names: str) -> DnsAllowlist:
    return DnsAllowlist(allowed=frozenset(names))


def test_an_exact_name_is_permitted() -> None:
    assert _allowlist("api.anthropic.com").permits("api.anthropic.com")


def test_a_subdomain_is_permitted() -> None:
    assert _allowlist("anthropic.com").permits("eu.api.anthropic.com")


def test_a_lookalike_suffix_is_refused() -> None:
    """``notanthropic.com`` shares a suffix but not a label boundary — the covert-channel
    hole the label-boundary rule closes, the same rule the egress allowlist uses."""
    allowlist = _allowlist("anthropic.com")
    assert not allowlist.permits("notanthropic.com")
    assert not allowlist.permits("anthropic.com.attacker.example")


def test_a_leading_dot_or_empty_label_is_refused() -> None:
    """``.api.anthropic.com`` is not a subdomain of ``api.anthropic.com`` — a naive
    ``endswith('.' + allowed)`` reads the empty label before the leading dot as the
    subdomain and lets it in (BW-40). This is the DNS-plane mirror of the egress
    ``_norm_host`` leading-dot fix; the two planes' allowlist parsers must agree."""
    allowlist = _allowlist("api.anthropic.com")
    assert not allowlist.permits(".api.anthropic.com")
    assert not allowlist.permits("api..anthropic.com")
    # the legitimate names around it still resolve
    assert allowlist.permits("api.anthropic.com")
    assert allowlist.permits("eu.api.anthropic.com")


def test_matching_is_case_and_trailing_dot_insensitive() -> None:
    allowlist = _allowlist("api.anthropic.com")
    assert allowlist.permits("API.Anthropic.COM.")
    assert allowlist.permits("api.anthropic.com.")


def test_an_empty_allowlist_permits_nothing() -> None:
    """Default-deny: with nothing allowlisted, every name is NXDOMAIN (§10.6)."""
    empty = _allowlist()
    assert not empty.permits("api.anthropic.com")
    assert not empty.permits("")


def test_an_empty_query_name_is_never_permitted() -> None:
    assert not _allowlist("anthropic.com").permits("")
    assert not _allowlist("anthropic.com").permits("   ")


# ---------------------------------------------------------------------------
# decide_query: resolve vs NXDOMAIN, and always logged
# ---------------------------------------------------------------------------


def test_a_permitted_query_resolves_with_no_reason() -> None:
    query = decide_query(
        "api.anthropic.com", allowlist=_allowlist("anthropic.com"), ts="1970-01-01T00:00:00Z"
    )
    assert query == DnsQuery(
        ts="1970-01-01T00:00:00Z", name="api.anthropic.com", resolved=True, reason=""
    )
    assert not query.blocked


def test_a_refused_query_is_nxdomain_with_an_actionable_reason() -> None:
    query = decide_query(
        "evil.example", allowlist=_allowlist("anthropic.com"), ts="1970-01-01T00:00:00Z"
    )
    assert query.blocked
    assert not query.resolved
    assert query.name == "evil.example"
    # The reason names the name, the plane, and the mechanism — never a bare enum (§10.7).
    assert "evil.example" in query.reason
    assert "allowlist" in query.reason
    assert "NXDOMAIN" in query.reason


def test_decide_query_normalises_the_recorded_name() -> None:
    """The record holds the compared form, so the log and the decision cannot disagree."""
    query = decide_query("API.Anthropic.COM.", allowlist=_allowlist("anthropic.com"), ts="t")
    assert query.name == "api.anthropic.com"
    assert query.resolved


def test_blocked_is_the_negation_of_resolved() -> None:
    resolved = DnsQuery(ts="t", name="a", resolved=True)
    refused = DnsQuery(ts="t", name="b", resolved=False, reason="NXDOMAIN")
    assert not resolved.blocked
    assert refused.blocked


# ---------------------------------------------------------------------------
# Canary scan over a query name — label-separator-aware, always critical
# ---------------------------------------------------------------------------


def test_a_marker_chunked_across_labels_is_found() -> None:
    """The attack shape: a 40-char marker split into DNS labels. Stripping the dots makes it
    contiguous, so the scan finds it even though no single label holds the whole value."""
    canary = mint_canaries(7)[0]
    marker = canary.marker
    third = len(marker) // 3
    chunked = f"{marker[:third]}.{marker[third : 2 * third]}.{marker[2 * third :]}.attacker.example"

    findings = scan_query_for_canaries(chunked, [canary])

    assert len(findings) == 1
    hit = findings[0]
    assert hit.canary_id == canary.id
    assert hit.destination == DNS_DESTINATION
    # A DNS destination is non-model, so any hit is a critical leak (§10.4.1).
    assert hit.finding == "canary_leak"
    assert hit.severity == "critical"


def test_a_base32_encoded_marker_chunked_across_labels_is_found() -> None:
    """BW-07: the base32 variant of the DNS attack. Encode the marker with the DNS-safe
    alphabet, then split the *ciphertext* into 8-char labels. The reassembled (de-dotted) text
    is the only decodable form — each 8-char label is far too short to be a run on its own — so
    the de-dotted text must be fed back through the decoders, not merely matched. The plaintext
    split above does not exercise this; only decode-*after*-reassembly finds it."""
    canary = mint_canaries(7)[0]
    cipher = base64.b32encode(canary.marker.encode()).decode()
    labels = ".".join(cipher[i : i + 8] for i in range(0, len(cipher), 8))
    qname = f"{labels}.attacker.example"

    findings = scan_query_for_canaries(qname, [canary])

    assert len(findings) == 1
    assert findings[0].canary_id == canary.id
    # DNS is non-model, so the reassembled-and-decoded hit is a critical leak (§10.4.1).
    assert findings[0].finding == "canary_leak"
    assert findings[0].severity == "critical"


def test_a_clean_query_name_yields_no_findings() -> None:
    canaries = mint_canaries(7)
    assert scan_query_for_canaries("api.anthropic.com", canaries) == []


def test_dns_destination_is_the_non_model_label() -> None:
    assert DNS_DESTINATION == "dns"


# ---------------------------------------------------------------------------
# ARF records (§11.2) via trace.dns_actions — Plane E
# ---------------------------------------------------------------------------

_TS = "2026-08-08T12:00:00+00:00"


def _query(name: str, *, resolved: bool, reason: str = "") -> DnsQuery:
    return DnsQuery(ts=_TS, name=name, resolved=resolved, reason=reason)


def test_resolved_and_blocked_queries_get_distinct_kinds() -> None:
    """A resolved name is ``dns_query``; a default-deny NXDOMAIN is ``dns_blocked`` — drawn
    apart exactly as egress splits ``egress`` from ``egress_blocked``, because a blocked
    lookup is evidence of intent and must not read like an ordinary query (§10.5.0, §10.6)."""
    queries = [
        _query("api.anthropic.com", resolved=True),
        _query("secret.evil.example", resolved=False, reason="not in the DNS allowlist; NXDOMAIN"),
    ]
    actions = dns_actions(queries)
    assert [a.kind for a in actions] == ["dns_query", "dns_blocked"]
    assert all(a.plane == "dns" for a in actions)
    assert [a.seq for a in actions] == [0, 1]


def test_a_blocked_query_carries_its_nxdomain_reason() -> None:
    actions = dns_actions(
        [_query("evil.example", resolved=False, reason="NXDOMAIN (default-deny)")]
    )
    assert actions[0].action["reason"] == "NXDOMAIN (default-deny)"
    assert actions[0].action["resolved"] is False


def test_the_query_name_is_retained_for_the_canary_scan() -> None:
    """The name is kept verbatim (not redacted): WP-7's canary scan reruns the label-stripped
    form through the corpus, so blanking it here would blind the covert-channel detector."""
    actions = dns_actions([_query("sec.ret.value.attacker.example", resolved=False)])
    assert actions[0].action["name"] == "sec.ret.value.attacker.example"


def test_dns_actions_are_deterministic() -> None:
    queries = [_query("api.anthropic.com", resolved=True), _query("evil.example", resolved=False)]
    a = [canonical_json(x.action) for x in dns_actions(queries)]
    b = [canonical_json(x.action) for x in dns_actions(queries)]
    assert a == b


def test_dns_actions_start_seq_offsets_the_sequence_space() -> None:
    actions = dns_actions([_query("api.anthropic.com", resolved=True)], start_seq=17)
    assert actions[0].seq == 17


def test_decide_query_output_flows_through_dns_actions() -> None:
    """End-to-end on the host core: the resolver's own decision records become Plane E."""
    allowlist = DnsAllowlist(frozenset({"api.anthropic.com"}))
    decided = [
        decide_query("api.anthropic.com", allowlist=allowlist, ts=_TS),
        decide_query("exfil.attacker.example", allowlist=allowlist, ts=_TS),
    ]
    actions = dns_actions(decided)
    assert [a.kind for a in actions] == ["dns_query", "dns_blocked"]
    assert actions[1].action["reason"]  # the NXDOMAIN reason is carried


# ---------------------------------------------------------------------------
# The resolver ↔ host query-record contract (§10.6) — mirror of the flow log
# ---------------------------------------------------------------------------


def test_a_query_record_round_trips() -> None:
    for query in (
        _query("api.anthropic.com", resolved=True),
        _query("evil.example", resolved=False, reason="NXDOMAIN (default-deny)"),
    ):
        assert parse_query_record(query_record_line(query)) == query


def test_the_query_record_line_is_canonical() -> None:
    query = _query("evil.example", resolved=False, reason="r")
    # Sorted keys, byte-stable — two writes of the same query produce identical bytes so the
    # shared log does not churn (§24), mirroring the flow record.
    assert query_record_line(query) == canonical_json(
        {"name": "evil.example", "reason": "r", "resolved": False, "ts": _TS}
    )
    assert query_record_line(query) == query_record_line(query)


def test_the_query_log_round_trips_through_a_file(tmp_path: Path) -> None:
    queries = [
        _query("api.anthropic.com", resolved=True),
        _query("a.b.c.attacker.example", resolved=False, reason="NXDOMAIN"),
    ]
    log = tmp_path / "queries.jsonl"
    write_query_records(log, queries)
    assert read_query_records(log) == queries


def test_an_empty_log_is_a_valid_observed_zero_query_run(tmp_path: Path) -> None:
    """The resolver writes an empty log at t=0: 'the resolver ran' is true from the start, so
    an empty log is an observed-clean run, not a missing plane."""
    log = tmp_path / "queries.jsonl"
    write_query_records(log, [])
    assert read_query_records(log) == []


def test_a_missing_query_log_raises_rather_than_reading_clean(tmp_path: Path) -> None:
    """A missing log means the resolver never ran; absence must not read as zero queries — the
    same fail-loud contract as the proxy's flow log (§10.6)."""
    with pytest.raises(OSError):
        read_query_records(tmp_path / "never-written.jsonl")


def test_the_controlled_resolver_base_refuses_a_partial_implementation() -> None:
    """A bare seam must fail loudly, not silently resolve nothing (a zero-query trace reads as
    a clean skill — the covert channel §10.6 exists to police would go unrecorded)."""
    resolver = ControlledResolver()
    with pytest.raises(NotImplementedError):
        resolver.start("run", allowlist=DnsAllowlist(frozenset()))
    with pytest.raises(NotImplementedError):
        resolver.queries()
    with pytest.raises(NotImplementedError):
        resolver.stop()
