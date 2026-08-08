"""Building the controlled-resolver provider from config, offline (§10.6).

Mirrors ``test_proxy_provider``: the resolver is wired only when ``dns.image`` is set, and its
allowlist is default-deny — the configured providers' hosts (the sandbox may legitimately resolve
the model endpoint) plus the operator's explicit ``dns.allowlist`` additions. Pinned here without a
daemon; the standup is proven against a real daemon on CI.
"""

from __future__ import annotations

from bellwether.cli.run import build_resolver_provider
from bellwether.config.models.config import Config, DnsConfig, SandboxConfig
from bellwether.config.models.provider import ProviderConfig

_API = {"apiVersion": "bellwether/v1"}
_IMG = "img@sha256:" + "d" * 64
_RESOLVER_IMG = "bw-resolver@sha256:" + "e" * 64


def _config(dns: DnsConfig | None = None) -> Config:
    return Config(
        **_API,
        kind="Config",
        providers={
            "anthropic": ProviderConfig(
                type="anthropic", api_key_env="ANTHROPIC_API_KEY", models={"frontier": "m"}
            )
        },
        sandbox=SandboxConfig(image=_IMG),
        dns=dns or DnsConfig(),
    )


def test_no_image_leaves_the_resolver_unwired() -> None:
    """The shipped default: dns.image empty → no provider → DNS stays not_evaluable. Turning the
    resolver on must be a deliberate config change, never the default."""
    assert build_resolver_provider(_config()) is None


def test_an_image_wires_a_provider_with_a_default_deny_allowlist() -> None:
    dns = DnsConfig(image=_RESOLVER_IMG, allowlist=["internal.corp"])
    provider = build_resolver_provider(_config(dns))
    assert provider is not None
    assert provider.image == _RESOLVER_IMG
    # The configured provider's host is permitted by construction; so is the operator's explicit
    # addition; nothing else.
    assert provider.allowlist.permits("api.anthropic.com")
    assert provider.allowlist.permits("internal.corp")
    assert not provider.allowlist.permits("evil.example.com")


def test_the_provider_points_at_the_configured_sandbox_image() -> None:
    """The backend the resolver's DockerBackend runs on is the run's sandbox image, so the daemon
    and its pinning are shared with the rest of the run."""
    provider = build_resolver_provider(_config(DnsConfig(image=_RESOLVER_IMG)))
    assert provider is not None
    assert provider.backend.image == _IMG
