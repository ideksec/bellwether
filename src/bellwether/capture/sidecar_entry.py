"""What runs *inside* the recording-proxy sidecar — the mitmdump entry point (§10.5).

The sidecar is a separate container running ``mitmdump -s <this-as-a-script>``. At load it reads
its config from a file the host wrote to the shared volume, rebuilds a :class:`ProxyAddon`
(reconstructing the run's credential broker so the container's scoped token is recognised and
swapped for the real key), and registers a mitmproxy addon whose ``request`` hook hands each flow
to ``on_request`` and applies the result — inject-and-forward, or a synthetic block response.

The whole module is written so its logic is testable without mitmproxy or a container: config
round-trips, the addon is rebuilt and exercised against a fake request, and a block is reduced to
a pure ``(status, body, headers)`` triple. The only genuinely mitmproxy-shaped line — assigning
``flow.response`` — is one lazy call, validated by the live docker test that stands the sidecar up
on CI. The host launcher that starts this container is the following slice.

Config is the *non-secret* half of the run (endpoints, allowlist, caps, scoped tokens); the real
keys arrive only as environment variables in the sidecar's own environment, so nothing the
observed container could read holds a credential.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bellwether.capture.credential import CredentialBroker
from bellwether.capture.egress import CapLedger, EgressAllowlist
from bellwether.capture.proxy_addon import BlockResponse, ProxyAddon, write_flow_records
from bellwether.determinism import canonical_json

__all__ = [
    "CONFIG_ENV_VAR",
    "SidecarConfig",
    "block_response_args",
    "build_addon",
    "load_addon_from_env",
]

#: The env var naming the config file the host wrote to the shared volume. The sidecar reads it
#: at load; its absence is a hard error, not an empty run — a proxy with no config would forward
#: nothing and record nothing, the clean-looking failure this plane exists to distrust.
CONFIG_ENV_VAR = "BW_SIDECAR_CONFIG"


@dataclass(frozen=True)
class SidecarConfig:
    """The non-secret run configuration the host hands the sidecar (§10.5).

    Everything the proxy needs to decide a request *except* the real keys, which travel as
    environment variables. ``credential_export`` is :meth:`CredentialBroker.sidecar_export` —
    per provider, its ``api_key_env`` name and scoped token — so the sidecar rebuilds the exact
    token↔key mapping the host minted. ``flow_log_path`` is where the flow records are written,
    on the shared volume the host reads back.
    """

    provider_endpoints: tuple[str, ...]
    infrastructure_endpoints: tuple[str, ...]
    allowlist_extra: tuple[str, ...]
    provider_of_host: Mapping[str, str]
    credential_export: Mapping[str, Mapping[str, str]]
    max_requests: int
    max_request_bytes: int
    flow_log_path: str
    listen_port: int = 8080

    def to_json(self) -> str:
        """Canonical JSON, so the config the host writes and the sidecar reads is byte-stable."""
        return canonical_json(
            {
                "provider_endpoints": list(self.provider_endpoints),
                "infrastructure_endpoints": list(self.infrastructure_endpoints),
                "allowlist_extra": list(self.allowlist_extra),
                "provider_of_host": dict(self.provider_of_host),
                "credential_export": {
                    provider: dict(entry) for provider, entry in self.credential_export.items()
                },
                "max_requests": self.max_requests,
                "max_request_bytes": self.max_request_bytes,
                "flow_log_path": self.flow_log_path,
                "listen_port": self.listen_port,
            }
        )

    @classmethod
    def from_json(cls, text: str) -> SidecarConfig:
        payload: dict[str, Any] = json.loads(text)
        return cls(
            provider_endpoints=tuple(payload["provider_endpoints"]),
            infrastructure_endpoints=tuple(payload["infrastructure_endpoints"]),
            allowlist_extra=tuple(payload["allowlist_extra"]),
            provider_of_host=dict(payload["provider_of_host"]),
            credential_export={
                provider: dict(entry) for provider, entry in payload["credential_export"].items()
            },
            max_requests=payload["max_requests"],
            max_request_bytes=payload["max_request_bytes"],
            flow_log_path=payload["flow_log_path"],
            listen_port=payload.get("listen_port", 8080),
        )


def build_addon(
    config: SidecarConfig,
    environ: Mapping[str, str],
    *,
    clock: Callable[[], str],
) -> ProxyAddon:
    """Rebuild the run's :class:`ProxyAddon` inside the sidecar from its config and environment.

    The security-critical step: :meth:`CredentialBroker.for_sidecar` reconstructs the broker from
    the scoped tokens in the config plus the real keys in ``environ``, so a request carrying the
    container's scoped token is recognised and swapped for the matching real key. The allowlist,
    caps and endpoint sets are rebuilt from the same config the host's ``decide_request`` used.
    """
    provider_endpoints = frozenset(config.provider_endpoints)
    infrastructure_endpoints = frozenset(config.infrastructure_endpoints)
    return ProxyAddon(
        allowlist=EgressAllowlist(
            provider_endpoints=provider_endpoints,
            infrastructure_endpoints=infrastructure_endpoints,
            extra=frozenset(config.allowlist_extra),
        ),
        provider_endpoints=provider_endpoints,
        infrastructure_endpoints=infrastructure_endpoints,
        broker=CredentialBroker.for_sidecar(config.credential_export, environ),
        provider_of_host=dict(config.provider_of_host),
        caps=CapLedger(
            max_requests=config.max_requests, max_request_bytes=config.max_request_bytes
        ),
        clock=clock,
    )


def block_response_args(block: BlockResponse) -> tuple[int, bytes, dict[str, str]]:
    """Reduce a :class:`BlockResponse` to the ``(status, body, headers)`` triple mitmproxy's
    ``http.Response.make`` takes. Pure, so the block path is tested without mitmproxy; the hook
    below is the one line that feeds this to mitmproxy."""
    return block.status, block.reason.encode("utf-8"), {"content-type": "text/plain; charset=utf-8"}


def _wall_clock() -> str:
    """Real capture time, ISO-8601 UTC. The egress plane's timestamps are genuine wall-clock and
    are anchored to epochs later (§11.5), so a real clock here is correct, not a determinism hole —
    the same pattern the sink and the api-loop adapter use."""
    import datetime as dt

    return dt.datetime.now(dt.UTC).isoformat()


class _RecordingAddon:
    """The mitmproxy addon object. Its ``request`` hook is the only mitmproxy-shaped surface: it
    calls ``on_request`` (all logic, tested) and, on a block, assigns ``flow.response``. Flows are
    flushed to the shared log after every request so a crash mid-run still leaves what was seen —
    a partial log is evidence; a missing one reads as a clean run and must not happen silently."""

    def __init__(self, addon: ProxyAddon, flow_log_path: str) -> None:
        self._addon = addon
        self._path = Path(flow_log_path)
        self._flush()  # write an empty log immediately: "the proxy ran" is true from t=0

    def request(self, flow: Any) -> None:
        block = self._addon.on_request(flow.request)
        if block is not None:
            # Lazy, and unresolved off the sidecar image: mitmproxy is a dependency of the proxy
            # container only, never of bellwether itself (§10.5 keeps their dep trees apart), so
            # mypy cannot see it here and the block path is proven by the CI docker test instead.
            from mitmproxy import http  # type: ignore[import-not-found]

            flow.response = http.Response.make(*block_response_args(block))
        self._flush()

    def done(self) -> None:
        self._flush()

    def _flush(self) -> None:
        write_flow_records(self._path, self._addon.flows())


def load_addon_from_env(environ: Mapping[str, str] | None = None) -> _RecordingAddon:
    """Build the addon mitmdump registers, from the config file named by ``CONFIG_ENV_VAR``.

    A missing env var or file is a hard error: a sidecar that cannot find its config must fail to
    start, not run as an open, unrecording proxy.
    """
    env = os.environ if environ is None else environ
    config_path = env.get(CONFIG_ENV_VAR)
    if not config_path:
        raise RuntimeError(
            f"{CONFIG_ENV_VAR} is not set; the sidecar has no configuration and refuses to run"
        )
    config = SidecarConfig.from_json(Path(config_path).read_text(encoding="utf-8"))
    return _RecordingAddon(build_addon(config, env, clock=_wall_clock), config.flow_log_path)


# The mitmdump entry point (``mitmdump -s``) is the loader at ``sidecar/proxy/proxy_entry.py`` in
# the sidecar image; it calls :func:`load_addon_from_env` and assigns the ``addons`` list mitmproxy
# discovers. This module deliberately does *not* build an addon at import, so importing it for its
# testable helpers never touches a config file or mitmproxy.
