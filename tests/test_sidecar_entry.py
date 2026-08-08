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
    method: str = "POST"
    scheme: str = "https"
    pretty_host: str = "api.anthropic.com"
    port: int = 443
    path: str = "/v1/messages"
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | None = b""


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
            pretty_host="attacker.example",
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
