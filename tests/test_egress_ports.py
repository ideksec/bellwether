"""The egress allowlist names a port as well as a host (§10.5.0).

An allowlist entry used to permit its host on **any** port. The proxy decided a ``CONNECT`` (and
every request inside one) on the host alone, so an allowlisted name let the sandbox reach every
service its address ran — a database, an admin port, an SSH daemon fronted by HTTP — and the
model provider's host on a port the operator never chose, with the real key injected onto it.

A bare entry now permits :data:`DEFAULT_EGRESS_PORTS` (443 and 80); anything else is written
``host:port`` and permits that port alone. Provider endpoints carry the port of their
``base_url``. These tests are at the wiring — the sidecar's hooks, the run's provider builder, the
sidecar config hand-off — because a correct ``permits`` that a caller never asks about the port is
the shape of every integration defect this project has found.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bellwether.capture import (
    DEFAULT_EGRESS_PORTS,
    DnsAllowlist,
    EgressAllowlist,
    provider_authorities,
    provider_hosts,
)
from bellwether.capture.proxy_addon import read_flow_records
from bellwether.capture.sidecar_entry import SidecarConfig, _RecordingAddon, build_addon
from bellwether.cli.run import build_proxy_provider, build_resolver_provider
from bellwether.config.models.config import Config, DnsConfig, EgressConfig, SandboxConfig
from bellwether.config.models.provider import ProviderConfig
from bellwether.errors import ConfigurationError
from tests.test_sidecar_entry import (
    _HOST_ENVIRON,
    _REAL_KEY,
    _TS,
    _config,
    _FakeRequest,
    _HookFlow,
    _host_broker,
)

_IMG = "img@sha256:" + "d" * 64
_PROXY_IMG = "bw-proxy@sha256:" + "e" * 64
_DNS_IMG = "bw-dns@sha256:" + "f" * 64


def _recording(tmp_path: Path, **overrides: object) -> tuple[_RecordingAddon, Path]:
    flow_log = tmp_path / "flows.jsonl"
    config = replace(_config(_host_broker(), str(flow_log)), **overrides)  # type: ignore[arg-type]
    addon = build_addon(config, _HOST_ENVIRON, clock=lambda: _TS)
    return _RecordingAddon(addon, str(flow_log), render=lambda block: block), flow_log


# --- The sidecar's hooks ---------------------------------------------------------------------


@pytest.mark.parametrize("port", [22, 5432, 8443, 9000])
def test_a_tunnel_to_an_allowlisted_host_on_another_port_is_refused_and_recorded(
    tmp_path: Path, port: int
) -> None:
    """The reported gap: ``CONNECT api.anthropic.com:<port>`` was opened because the host matched."""
    recording, flow_log = _recording(tmp_path)
    flow = _HookFlow(request=_FakeRequest(method="CONNECT", port=port))

    recording.http_connect(flow)

    assert flow.response is not None and flow.response.status == 403  # type: ignore[attr-defined]
    [record] = read_flow_records(flow_log)
    assert (record.method, record.host, record.port, record.blocked) == (
        "CONNECT",
        "api.anthropic.com",
        port,
        True,
    )
    assert f"not on port {port}" in record.block_reason


@pytest.mark.parametrize("port", sorted(DEFAULT_EGRESS_PORTS))
def test_a_tunnel_to_an_allowlisted_host_on_a_default_port_opens(tmp_path: Path, port: int) -> None:
    recording, flow_log = _recording(tmp_path)
    flow = _HookFlow(request=_FakeRequest(method="CONNECT", port=port))

    recording.http_connect(flow)

    assert flow.response is None
    assert read_flow_records(flow_log) == []


def test_a_request_to_the_provider_on_another_port_gets_no_key(tmp_path: Path) -> None:
    """The credential half: a request to the provider host on a port nobody chose is refused before
    injection, so the real key is never written toward it."""
    recording, flow_log = _recording(tmp_path)
    token = _host_broker().sidecar_export()["anthropic"]["sandbox_token"]
    request = _FakeRequest(port=8443, headers={"x-api-key": token})
    flow = _HookFlow(request=request)

    recording.request(flow)

    assert flow.response is not None and flow.response.status == 403  # type: ignore[attr-defined]
    assert _REAL_KEY not in str(request.headers)
    [record] = read_flow_records(flow_log)
    assert record.blocked and record.port == 8443


def test_an_explicit_port_entry_permits_that_port_and_no_other(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path, allowlist_extra=("git.example:8443",))

    opened = _HookFlow(request=_FakeRequest(method="CONNECT", host="git.example", port=8443))
    recording.http_connect(opened)
    default = _HookFlow(request=_FakeRequest(method="CONNECT", host="git.example", port=443))
    recording.http_connect(default)

    assert opened.response is None
    assert default.response is not None  # naming a port is not "that port as well"
    [record] = read_flow_records(flow_log)
    assert (record.host, record.port, record.blocked) == ("git.example", 443, True)


def test_a_websocket_frame_is_judged_on_its_port_too(tmp_path: Path) -> None:
    from tests.test_websocket_egress import _Frame, _send, _WsFlow

    recording, flow_log = _recording(tmp_path, allowlist_extra=("ws.example",))
    flow = _WsFlow(request=_FakeRequest(method="GET", host="ws.example", port=9000, path="/s"))

    frame = _send(recording, flow, _Frame(True, b"hello"))

    assert frame.dropped
    [record] = read_flow_records(flow_log)
    assert record.blocked and record.port == 9000


# --- From config to the sidecar ------------------------------------------------------------


def _run_config(
    *, base_url: str | None = None, egress: list[str] | None = None, dns: list[str] | None = None
) -> Config:
    return Config(
        apiVersion="bellwether/v1",
        kind="Config",
        providers={
            "anthropic": ProviderConfig(
                type="anthropic",
                base_url=base_url,
                api_key_env="ANTHROPIC_API_KEY",
                models={"frontier": "m"},
            )
        },
        sandbox=SandboxConfig(image=_IMG),
        egress=EgressConfig(image=_PROXY_IMG, allowlist=egress or []),
        dns=DnsConfig(image=_DNS_IMG, allowlist=dns or []),
    )


def test_a_provider_on_its_own_port_is_permitted_there_and_nowhere_else() -> None:
    """``run``'s builder: an ``openai_compatible`` server or a local gateway at ``host:8080`` is
    reachable on 8080. Built from the hosts alone it was reachable on every port of that host."""
    provider = build_proxy_provider(_run_config(base_url="http://10.0.0.5:8080"))
    assert provider is not None
    assert provider.allowlist.permits("10.0.0.5", 8080)
    assert not provider.allowlist.permits("10.0.0.5", 9090)
    assert not provider.allowlist.permits("10.0.0.5", 443)


def test_the_default_provider_is_permitted_on_the_default_ports_only() -> None:
    provider = build_proxy_provider(_run_config(egress=["pypi.org", "cache.example:8443"]))
    assert provider is not None
    allowlist = provider.allowlist
    assert allowlist.permits("api.anthropic.com", 443)
    assert not allowlist.permits("api.anthropic.com", 8443)
    assert allowlist.permits("pypi.org", 80) and not allowlist.permits("pypi.org", 22)
    assert allowlist.permits("cache.example", 8443) and not allowlist.permits("cache.example", 443)


def test_the_ported_entries_survive_the_hand_off_to_the_sidecar(tmp_path: Path) -> None:
    """The host builds the allowlist; the sidecar rebuilds it from the serialised config. The port
    must cross that wire, or the sidecar decides on a different list from the one configured."""
    provider = build_proxy_provider(
        _run_config(base_url="http://10.0.0.5:8080", egress=["cache.example:8443"])
    )
    assert provider is not None
    allowlist = provider.allowlist
    config = SidecarConfig(
        provider_endpoints=tuple(sorted(allowlist.provider_endpoints)),
        infrastructure_endpoints=tuple(sorted(allowlist.infrastructure_endpoints)),
        allowlist_extra=tuple(sorted(allowlist.extra)),
        provider_of_host={},
        credential_export={},
        max_requests=10,
        max_request_bytes=1000,
        flow_log_path=str(tmp_path / "flows.jsonl"),
    )
    rebuilt = build_addon(SidecarConfig.from_json(config.to_json()), {}, clock=lambda: _TS)
    assert rebuilt.allowlist == allowlist


def test_the_dns_plane_stays_host_only() -> None:
    """A query carries no port, so the resolver's allowlist holds the provider's *host*."""
    resolver = build_resolver_provider(_run_config(base_url="http://gateway.internal:8080"))
    assert resolver is not None
    assert resolver.allowlist.permits("gateway.internal")


# --- Entries that would match nothing are refused --------------------------------------------


@pytest.mark.parametrize(
    "entry",
    ["cache.example:abc", "cache.example:99999", "cache.example:0", "https://cache.example",
     "user@cache.example", "cache.example/path", ".cache.example", ""],
)  # fmt: skip
def test_an_egress_entry_that_names_no_host_and_port_is_refused(entry: str) -> None:
    with pytest.raises(ConfigurationError) as caught:
        build_proxy_provider(_run_config(egress=[entry]))
    assert "egress.allowlist" in str(caught.value)


def test_a_dns_entry_with_a_port_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="carries no port"):
        build_resolver_provider(_run_config(dns=["cache.example:8443"]))
    with pytest.raises(ConfigurationError):
        DnsAllowlist(frozenset({"cache.example:53"}))


# --- One authority, two readings ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("base_url", "authority", "host", "port"),
    [
        ("https://api.anthropic.com", "api.anthropic.com", "api.anthropic.com", 443),
        ("https://api.anthropic.com/v1", "api.anthropic.com", "api.anthropic.com", 80),
        ("https://API.Anthropic.com.:443", "api.anthropic.com:443", "api.anthropic.com", 443),
        ("http://10.0.0.5:8080/v1", "10.0.0.5:8080", "10.0.0.5", 8080),
        ("http://[::1]:8080", "[::1]:8080", "::1", 8080),
        ("https://[::1]", "[::1]", "::1", 443),
        ("api.openai.com:443", "api.openai.com:443", "api.openai.com", 443),
    ],
)
def test_a_base_url_yields_one_authority_and_one_host(
    base_url: str, authority: str, host: str, port: int
) -> None:
    """The egress allowlist reads the authority, the DNS allowlist the host: one URL, two
    readings that must agree on the host and differ only in the port."""
    assert provider_authorities([base_url]) == {authority}
    assert provider_hosts([base_url]) == {host}
    allowlist = EgressAllowlist(
        provider_endpoints=frozenset({authority}), infrastructure_endpoints=frozenset()
    )
    assert allowlist.permits(host, port)
    assert not allowlist.permits(host, 2222)
