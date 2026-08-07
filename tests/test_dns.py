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

from bellwether.capture import (
    DnsAllowlist,
    DnsQuery,
    decide_query,
    mint_canaries,
    scan_query_for_canaries,
)
from bellwether.capture.dns import DNS_DESTINATION

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


def test_a_clean_query_name_yields_no_findings() -> None:
    canaries = mint_canaries(7)
    assert scan_query_for_canaries("api.anthropic.com", canaries) == []


def test_dns_destination_is_the_non_model_label() -> None:
    assert DNS_DESTINATION == "dns"
