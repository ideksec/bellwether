"""WP-13 (increment 2a): credential isolation — the real key never enters the container.

§3.3 invariant 1 is the most important security property of the tool: the model API key
must not be readable inside the sandbox, and must not reach an artifact. This exercises the
host-side core of that guarantee — the sandbox-scoped token, the proxy-side injection, the
container environment, and the leak guard — offline. The mitmproxy sidecar that applies the
injection in a real container is the next increment; the container-filesystem half of the
done-when belongs to it.
"""

from __future__ import annotations

from bellwether.capture import (
    SANDBOX_TOKEN_PREFIX,
    CredentialBroker,
    EgressAllowlist,
    make_flow,
    mint_sandbox_token,
    proxy_environment,
    strip_and_inject,
)
from bellwether.determinism import SeededRng, canonical_json

_REAL_KEY = "sk-real-ANTHROPIC-secret-value"
_ENVIRON = {"ANTHROPIC_API_KEY": _REAL_KEY, "OPENAI_API_KEY": "sk-real-OPENAI-secret"}
_API_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


def _broker() -> CredentialBroker:
    return CredentialBroker.for_run(_API_KEY_ENV, _ENVIRON, rng=SeededRng(20260806, "cred"))


# ---------------------------------------------------------------------------
# The sandbox-scoped token
# ---------------------------------------------------------------------------


def test_a_minted_token_is_prefixed_and_not_the_real_key() -> None:
    token = mint_sandbox_token(SeededRng(1, "x"))
    assert token.startswith(SANDBOX_TOKEN_PREFIX)
    assert _REAL_KEY not in token


def test_a_token_is_reproducible_from_its_seed() -> None:
    assert mint_sandbox_token(SeededRng(1, "x")) == mint_sandbox_token(SeededRng(1, "x"))


def test_different_seeds_give_different_tokens() -> None:
    assert mint_sandbox_token(SeededRng(1, "x")) != mint_sandbox_token(SeededRng(2, "x"))


# ---------------------------------------------------------------------------
# §10.5.1 injection transform
# ---------------------------------------------------------------------------


def test_injection_swaps_the_scoped_token_for_the_real_key_preserving_scheme() -> None:
    headers = {"Authorization": "Bearer bw-sbx-TOKEN", "Content-Type": "application/json"}
    injected = strip_and_inject(headers, sandbox_token="bw-sbx-TOKEN", real_key=_REAL_KEY)
    assert injected["Authorization"] == f"Bearer {_REAL_KEY}"
    assert injected["Content-Type"] == "application/json"


def test_injection_handles_x_api_key() -> None:
    injected = strip_and_inject(
        {"x-api-key": "bw-sbx-TOKEN"}, sandbox_token="bw-sbx-TOKEN", real_key=_REAL_KEY
    )
    assert injected["x-api-key"] == _REAL_KEY


def test_injection_leaves_a_foreign_token_untouched() -> None:
    """The proxy injects only for the token it minted — a skill that ships its own key does
    not get it swapped for Bellwether's."""
    headers = {"Authorization": "Bearer some-other-key"}
    injected = strip_and_inject(headers, sandbox_token="bw-sbx-TOKEN", real_key=_REAL_KEY)
    assert injected["Authorization"] == "Bearer some-other-key"


# ---------------------------------------------------------------------------
# The broker and the container environment — the critical invariant
# ---------------------------------------------------------------------------


def test_only_providers_with_a_real_key_are_ready() -> None:
    broker = CredentialBroker.for_run(
        {"anthropic": "ANTHROPIC_API_KEY", "missing": "NOT_SET_ENV"},
        _ENVIRON,
        rng=SeededRng(1, "c"),
    )
    assert broker.ready_providers() == ["anthropic"]


def test_the_container_env_carries_the_scoped_token_never_the_real_key() -> None:
    """§3.3 invariant 1: the env handed to the container has the scoped token under the
    provider's key var, and the real key appears nowhere in it."""
    broker = _broker()
    env = broker.sandbox_env("anthropic")
    assert env["ANTHROPIC_API_KEY"].startswith(SANDBOX_TOKEN_PREFIX)
    assert env["ANTHROPIC_API_KEY"] == broker.sandbox_token("anthropic")
    assert _REAL_KEY not in canonical_json(env)
    assert not broker.leaks_a_real_key(canonical_json(env))


def test_the_broker_injects_the_real_key_for_a_provider() -> None:
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    injected = broker.inject("anthropic", {"Authorization": f"Bearer {token}"})
    assert injected["Authorization"] == f"Bearer {_REAL_KEY}"


def test_the_leak_guard_finds_a_real_key_and_ignores_clean_text() -> None:
    broker = _broker()
    assert broker.leaks_a_real_key(f"...{_REAL_KEY}...")
    assert not broker.leaks_a_real_key("nothing sensitive here")


def test_an_empty_real_key_never_counts_as_a_leak() -> None:
    broker = CredentialBroker.for_run({"p": "EMPTY"}, {"EMPTY": ""}, rng=SeededRng(1, "c"))
    assert broker.ready_providers() == []  # no key → not ready
    assert not broker.leaks_a_real_key("")


# ---------------------------------------------------------------------------
# End to end: the real key survives injection but never reaches an artifact
# ---------------------------------------------------------------------------


def test_an_injected_request_never_writes_the_real_key_to_a_trace_record() -> None:
    """The proxy injects the real key into the outbound request, but the flow record it
    writes redacts the auth header — so the real key reaches the provider and nothing
    else. This is the join between credential injection (§10.5.1) and redaction (§10.5)."""
    broker = _broker()
    token = broker.sandbox_token("anthropic")
    injected = broker.inject("anthropic", {"Authorization": f"Bearer {token}"})
    assert injected["Authorization"] == f"Bearer {_REAL_KEY}"  # the wire really carries it

    flow = make_flow(
        ts="2026-08-06T00:00:00+00:00",
        method="POST",
        scheme="https",
        host="api.anthropic.com",
        port=443,
        path="/v1/messages",
        provider_endpoints=frozenset({"api.anthropic.com"}),
        infrastructure_endpoints=frozenset(),
        allowlist=EgressAllowlist(
            provider_endpoints=frozenset({"api.anthropic.com"}),
            infrastructure_endpoints=frozenset(),
        ),
        request_headers=injected,
        request_body=b'{"model": "claude"}',
    )
    record = canonical_json({"headers": dict(flow.request_headers)})
    assert _REAL_KEY not in record
    assert not broker.leaks_a_real_key(record)


# ---------------------------------------------------------------------------
# proxy_environment
# ---------------------------------------------------------------------------


def test_proxy_environment_routes_all_traffic_and_sets_no_bypass() -> None:
    env = proxy_environment("http://127.0.0.1:8080")
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:8080"
    assert env["https_proxy"] == "http://127.0.0.1:8080"
    assert "NO_PROXY" not in env and "no_proxy" not in env


def test_proxy_environment_adds_the_ca_bundle_when_known() -> None:
    env = proxy_environment("http://127.0.0.1:8080", ca_bundle="/etc/ssl/bw-ca.pem")
    assert env["REQUESTS_CA_BUNDLE"] == "/etc/ssl/bw-ca.pem"
    assert env["NODE_EXTRA_CA_CERTS"] == "/etc/ssl/bw-ca.pem"
