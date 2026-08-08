"""Building the recording-proxy provider from config, offline (§10.5).

The provider is what turns `bellwether run` into a run that observes egress. It is wired only when
`egress.image` is set, and its allowlist is default-deny — the configured providers by construction,
plus the operator's explicit additions. Both are pinned here without a daemon; the standup itself is
proven against a real daemon on CI.
"""

from __future__ import annotations

from bellwether.cli.run import build_proxy_provider
from bellwether.config.models.config import Config, EgressConfig, PerRunCaps, SandboxConfig
from bellwether.config.models.provider import ProviderConfig

_API = {"apiVersion": "bellwether/v1"}
_IMG = "img@sha256:" + "d" * 64
_PROXY_IMG = "bw-proxy@sha256:" + "e" * 64


def _config(egress: EgressConfig | None = None) -> Config:
    return Config(
        **_API,
        kind="Config",
        providers={
            "anthropic": ProviderConfig(
                type="anthropic", api_key_env="ANTHROPIC_API_KEY", models={"frontier": "m"}
            )
        },
        sandbox=SandboxConfig(image=_IMG),
        egress=egress or EgressConfig(),
    )


def test_no_image_leaves_the_proxy_unwired() -> None:
    """The shipped default: egress.image empty → no provider → the sandbox runs networkless, exactly
    as first-light. Turning the proxy on must be a deliberate config change, never the default."""
    assert build_proxy_provider(_config()) is None


def test_an_image_wires_a_provider_with_a_default_deny_allowlist() -> None:
    egress = EgressConfig(image=_PROXY_IMG, allowlist=["pypi.org"])
    provider = build_proxy_provider(_config(egress))
    assert provider is not None
    assert provider.image == _PROXY_IMG
    # The configured anthropic provider's host is permitted by construction; so is the operator's
    # explicit addition; nothing else.
    assert provider.allowlist.permits("api.anthropic.com")
    assert provider.allowlist.permits("pypi.org")
    assert not provider.allowlist.permits("evil.example.com")


def test_the_broker_is_empty_so_the_sandbox_gets_no_credential() -> None:
    """§3.3 invariant 1 in its strongest form for api-loop: the sandbox is handed no key at all, so
    a real key cannot leak from it because it never held one."""
    provider = build_proxy_provider(_config(EgressConfig(image=_PROXY_IMG)))
    assert provider is not None
    assert provider.broker.ready_providers() == []
    assert not provider.broker.leaks_a_real_key("sk-anything")


def test_caps_come_from_config() -> None:
    egress = EgressConfig(
        image=_PROXY_IMG, per_run_caps=PerRunCaps(max_requests=7, max_request_bytes=1234)
    )
    provider = build_proxy_provider(_config(egress))
    assert provider is not None
    assert (provider.max_requests, provider.max_request_bytes) == (7, 1234)
