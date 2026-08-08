"""Credential isolation — the real key never enters the container (§3.3 invariant 1).

The single most important security property of the whole tool: the model API key MUST NOT
be readable inside the sandbox. A malicious skill's first move, handed a real key, is to
steal it. So the harness inside the container is given a **sandbox-scoped token** — an
opaque per-run string that is worthless anywhere but the recording proxy — and the proxy
strips that token and injects the real credential on the way out (§10.5.1). The container
sees the scoped token; the provider sees the real key; the two never meet inside the
sandbox.

This module is the host-side core of that exchange, and it is deliberately pure so the
invariant is unit-testable without a container:

- :func:`mint_sandbox_token` — a per-run, reproducible, opaque token;
- :class:`CredentialBroker` — holds the scoped-token↔real-key mapping *on the host*, builds
  the container's environment (scoped token in place of the real key), performs the
  injection the proxy addon applies, and answers "does this text leak a real key?" so
  teardown and tests can assert no artifact holds one.

The real key is read from the host environment (the CI runner holds it, §3.3) and is never
written to a container mount, an env var handed to the container, or a trace record.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from bellwether.determinism import SeededRng

__all__ = [
    "SANDBOX_TOKEN_PREFIX",
    "CredentialBroker",
    "mint_sandbox_token",
    "proxy_environment",
    "strip_and_inject",
]

#: Marks a sandbox-scoped token so the proxy addon recognises the value it is meant to
#: replace, and so a leak of the token into an artifact is greppable and obviously not a
#: real key.
SANDBOX_TOKEN_PREFIX = "bw-sbx-"

#: Request headers that may carry an API credential. Matched case-insensitively. Provider-wide,
#: not Anthropic-only: a provider that authenticates with ``x-goog-api-key`` (Google) must have
#: its scoped token swapped too, or the container's token would reach that provider on the wire.
#: Widening is safe — :func:`strip_and_inject` only rewrites a header that actually carries the
#: scoped token, so naming a header no request uses is a no-op.
_AUTH_HEADERS = frozenset(
    {"authorization", "x-api-key", "api-key", "anthropic-api-key", "x-goog-api-key"}
)


def mint_sandbox_token(rng: SeededRng) -> str:
    """A per-run, reproducible, opaque sandbox-scoped token (§10.5.1).

    Reproducible from the run's seed (so an evaluation replays), yet worthless outside the
    proxy: its only power is that the proxy recognises it and swaps in the real key. High
    entropy is defence in depth, not the control — the control is that this string, not the
    real key, is what the container ever holds.
    """
    return f"{SANDBOX_TOKEN_PREFIX}{rng.token(40)}"


def strip_and_inject(
    headers: Mapping[str, str], *, sandbox_token: str, real_key: str
) -> dict[str, str]:
    """Replace the sandbox-scoped token with the real key in any auth header (§10.5.1).

    The transform the proxy addon applies to an outbound model-API request: wherever an
    auth header carries the scoped token, substitute the real key, preserving any scheme
    prefix (``Bearer ``). A header that does not carry the scoped token is passed through
    untouched — the proxy injects only for the token it minted, so a skill that supplies
    its own key does not get it swapped for Bellwether's.
    """
    injected: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _AUTH_HEADERS and sandbox_token in value:
            injected[name] = value.replace(sandbox_token, real_key)
        else:
            injected[name] = value
    return injected


def proxy_environment(proxy_url: str, *, ca_bundle: str | None = None) -> dict[str, str]:
    """The env vars that route the container's traffic through the recording proxy.

    Both upper- and lower-case forms, because different clients read different ones; a
    ``NO_PROXY`` is deliberately *not* set, so nothing escapes the proxy. The CA bundle path
    (installed by WP-14) is included when known so TLS interception is trusted; until then
    the proxy still sees connect attempts and records them.
    """
    env = {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
    }
    if ca_bundle is not None:
        # Every mechanism in the §9.2 table is WP-14's job; this is the common subset that
        # the standard HTTP stacks honour.
        env["REQUESTS_CA_BUNDLE"] = ca_bundle
        env["SSL_CERT_FILE"] = ca_bundle
        env["NODE_EXTRA_CA_CERTS"] = ca_bundle
    return env


@dataclass(frozen=True)
class _ProviderCredential:
    sandbox_token: str
    real_key: str
    api_key_env: str


class CredentialBroker:
    """The host-side ledger mapping each provider's scoped token to its real key.

    Constructed per run from the providers' ``api_key_env`` names and the host environment.
    The real keys live here, on the host, and leave only through :meth:`inject` — never into
    :meth:`sandbox_env`, which is what the container receives.
    """

    def __init__(self, credentials: Mapping[str, _ProviderCredential]) -> None:
        self._by_provider = dict(credentials)

    @classmethod
    def for_run(
        cls,
        api_key_env: Mapping[str, str],
        environ: Mapping[str, str],
        *,
        rng: SeededRng,
    ) -> CredentialBroker:
        """Build a broker for one run.

        Args:
            api_key_env: provider name → the host env var holding its real key (from
                ``providers[*].api_key_env``).
            environ: the host environment (the runner's, which holds the real keys).
            rng: the run's seeded RNG, so tokens are reproducible.

        A provider whose env var is absent or empty gets no entry — it has no real key on
        this runner, so it cannot run, and :meth:`ready_providers` reports it rather than
        the broker silently minting a token that maps to nothing.
        """
        credentials: dict[str, _ProviderCredential] = {}
        for provider in sorted(api_key_env):
            env_name = api_key_env[provider]
            real_key = environ.get(env_name, "")
            if not real_key:
                continue
            credentials[provider] = _ProviderCredential(
                sandbox_token=mint_sandbox_token(rng.derive(f"token/{provider}")),
                real_key=real_key,
                api_key_env=env_name,
            )
        return cls(credentials)

    def ready_providers(self) -> list[str]:
        """Providers with a real key available on this runner (sorted)."""
        return sorted(self._by_provider)

    def sandbox_token(self, provider: str) -> str:
        return self._by_provider[provider].sandbox_token

    def sandbox_env(self, provider: str) -> dict[str, str]:
        """The credential env the *container* receives: the scoped token under the provider's
        own ``api_key_env`` name. The real key is never here — that is the whole point."""
        credential = self._by_provider[provider]
        return {credential.api_key_env: credential.sandbox_token}

    def inject(self, provider: str, headers: Mapping[str, str]) -> dict[str, str]:
        """Apply the proxy-side injection for one provider's request (§10.5.1)."""
        credential = self._by_provider[provider]
        return strip_and_inject(
            headers, sandbox_token=credential.sandbox_token, real_key=credential.real_key
        )

    def leaks_a_real_key(self, text: str) -> bool:
        """Whether ``text`` contains any real key this broker holds.

        The guard teardown and the done-when test use to assert no artifact — no trace, no
        env dump, no container filesystem listing — carries a real credential (§9.1 step 11).
        An empty real key never counts as a leak.
        """
        return any(cred.real_key and cred.real_key in text for cred in self._by_provider.values())

    # -- The sidecar half (§10.5.1) -----------------------------------------------------
    #
    # The recording proxy runs in its own container and needs the *same* token↔key mapping
    # this host broker minted, so that a request carrying the container's scoped token is
    # recognised and swapped for the matching real key. The mapping is handed over in two
    # parts, kept apart on purpose: the non-secret half (which env var, which scoped token)
    # travels in the sidecar's config file, and the real keys travel only as environment
    # variables into the sidecar container — host-controlled infrastructure, never the
    # observed sandbox. :meth:`for_sidecar` rebuilds the broker from those two parts.

    def sidecar_export(self) -> dict[str, dict[str, str]]:
        """The non-secret half the sidecar needs to rebuild this broker: per provider, its
        ``api_key_env`` name and scoped token. **No real key is here** — the scoped token is
        already what the container holds, so exporting it leaks nothing, and the real key is
        supplied separately via :meth:`sidecar_real_key_env`."""
        return {
            provider: {"api_key_env": cred.api_key_env, "sandbox_token": cred.sandbox_token}
            for provider, cred in sorted(self._by_provider.items())
        }

    def sidecar_real_key_env(self) -> dict[str, str]:
        """The environment the launcher injects into the *sidecar* container: each provider's
        real key under its ``api_key_env`` name. This is the one place a real key leaves the
        host, and it goes to the proxy — host-controlled — never to the sandbox, whose env is
        built by :meth:`sandbox_env` and carries the scoped token instead."""
        return {cred.api_key_env: cred.real_key for cred in self._by_provider.values()}

    @classmethod
    def for_sidecar(
        cls, export: Mapping[str, Mapping[str, str]], environ: Mapping[str, str]
    ) -> CredentialBroker:
        """Rebuild the broker inside the sidecar from the non-secret export plus the real keys
        in the sidecar's environment.

        A provider whose real key is absent from ``environ`` is skipped, exactly as
        :meth:`for_run` skips a keyless provider on the host — it is not ``ready`` and must not
        appear injectable. Reconstructing it with an empty key would be worse than dropping it:
        injecting an empty string would *strip* the container's scoped token to a bare scheme and
        forward that, so the semantics are kept identical to the host's instead.
        """
        credentials = {
            provider: _ProviderCredential(
                sandbox_token=entry["sandbox_token"],
                real_key=environ[entry["api_key_env"]],
                api_key_env=entry["api_key_env"],
            )
            for provider, entry in export.items()
            if environ.get(entry["api_key_env"])
        }
        return cls(credentials)
