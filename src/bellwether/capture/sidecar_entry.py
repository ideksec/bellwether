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

import contextlib
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bellwether.capture.canary import Canary
from bellwether.capture.credential import CredentialBroker
from bellwether.capture.egress import CapLedger, EgressAllowlist
from bellwether.capture.proxy_addon import (
    BLOCK_STATUS_ERROR,
    BlockResponse,
    ProxyAddon,
    write_flow_records,
)
from bellwether.determinism import canonical_json

__all__ = [
    "CONFIG_ENV_VAR",
    "SidecarConfig",
    "block_response_args",
    "build_addon",
    "client_sni",
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
    #: The run's planted canaries as ``(id, marker)`` pairs, so the sidecar can scan request bodies
    #: for them (§10.5.2). Sensitive like the scoped tokens above — both live only on the shared
    #: volume, which the CI upload excludes (``runs/**``), so no marker reaches an artifact (§10.4.3).
    canary_markers: tuple[tuple[str, str], ...] = ()

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
                "canary_markers": [list(pair) for pair in self.canary_markers],
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
            canary_markers=tuple((pair[0], pair[1]) for pair in payload.get("canary_markers", ())),
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
    # Reconstruct the run's canaries for body scanning. Only id and marker travel and only they are
    # used by the scan; kind/path are the sandbox-side plant sites, irrelevant to matching in a body.
    canaries = tuple(
        Canary(id=canary_id, marker=marker, kind="", path="")
        for canary_id, marker in config.canary_markers
    )
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
        canaries=canaries,
    )


def client_sni(flow: Any) -> str:
    """The server name the client offered in its TLS handshake, or ``""`` where there was none.

    A third asserted identity beside the request-line authority and the ``Host`` header, read off
    the client connection because that is the only place it exists. Defensive ``getattr``: the
    attribute is absent on a plaintext connection and on the plain fakes the addon is unit-tested
    with, and a proxy that crashed on a missing optional field would fail closed by dying rather
    than by blocking — which loses the flow log the plane depends on.
    """
    connection = getattr(flow, "client_conn", None)
    sni = getattr(connection, "sni", None)
    return sni if isinstance(sni, str) else ""


def block_response_args(block: BlockResponse) -> tuple[int, bytes, dict[str, str]]:
    """Reduce a :class:`BlockResponse` to the ``(status, body, headers)`` triple mitmproxy's
    ``http.Response.make`` takes. Pure, so the block path is tested without mitmproxy."""
    return block.status, block.reason.encode("utf-8"), {"content-type": "text/plain; charset=utf-8"}


def _wall_clock() -> str:
    """Real capture time, ISO-8601 UTC. The egress plane's timestamps are genuine wall-clock and
    are anchored to epochs later (§11.5), so a real clock here is correct, not a determinism hole —
    the same pattern the sink and the api-loop adapter use."""
    import datetime as dt

    return dt.datetime.now(dt.UTC).isoformat()


def _mitmproxy_response(block: BlockResponse) -> Any:
    """Render a block as a mitmproxy response. Lazy, and unresolved off the sidecar image:
    mitmproxy is a dependency of the proxy container only, never of bellwether itself (§10.5
    keeps their dep trees apart), so mypy cannot see it here; tests inject their own renderer."""
    from mitmproxy import http  # type: ignore[import-not-found]

    return http.Response.make(*block_response_args(block))


class _RecordingAddon:
    """The mitmproxy addon object — the only mitmproxy-shaped surface. Each hook calls into
    :class:`ProxyAddon` (all logic, tested) and applies the result. Flows are flushed to the shared
    log after every decision so a crash mid-run still leaves what was seen — a partial log is
    evidence; a missing one reads as a clean run and must not happen silently.

    **Every hook fails closed.** mitmproxy's ``safecall`` catches an addon's exception, logs it
    and *carries on with the flow* — so an exception escaping a hook is an open, unrecorded proxy
    for that request (a ``Content-Encoding: gzip`` header on a body that is not gzip made
    ``request.content`` raise, and the request went out undecided). Each hook therefore turns any
    failure into a recorded refusal, and if even rendering the refusal fails, kills the flow.

    Four kinds of hook, because HTTP requests are not the only thing a proxy relays:

    * ``http_connect`` gates a ``CONNECT`` tunnel on the allowlist *before* mitmproxy dials it —
      without it, mitmproxy answers ``200 Connection established`` to any host:port.
    * ``request`` decides each HTTP request, inside a tunnel or not.
    * ``websocket_message`` decides each client-to-server frame after a permitted upgrade —
      recorded, scanned for canaries, charged to the caps — which mitmproxy otherwise relays
      with only the upgrade request on record.
    * ``tcp_start``/``tcp_message`` refuse a raw-TCP stream (bytes that are neither TLS nor HTTP,
      which mitmproxy otherwise relays verbatim and no request hook ever sees). ``rawtcp=false``
      on the command line stops mitmproxy choosing that layer at all; these are the backstop, and
      ``tcp_message`` empties each payload because killing a TCP flow does not stop its relay.
    """

    def __init__(
        self,
        addon: ProxyAddon,
        flow_log_path: str,
        *,
        render: Callable[[BlockResponse], Any] = _mitmproxy_response,
    ) -> None:
        self._addon = addon
        self._path = Path(flow_log_path)
        self._render = render
        self._flush()  # write an empty log immediately: "the proxy ran" is true from t=0

    def http_connect(self, flow: Any) -> None:
        try:
            request = flow.request
            block = self._addon.on_connect(
                request.host, request.port, claimed_host=request.host_header or ""
            )
        except Exception as error:
            block = self._error(flow, "http_connect", error)
        self._settle(flow, block)

    def request(self, flow: Any) -> None:
        try:
            block = self._addon.on_request(flow.request, sni=client_sni(flow))
        except Exception as error:
            block = self._error(flow, "request", error)
        self._settle(flow, block)

    def tcp_start(self, flow: Any) -> None:
        try:
            host, port = _server_address(flow)
            self._addon.on_raw_tcp(host, port)
        except Exception as error:
            self._error(flow, "tcp_start", error)
        self._kill(flow)
        self._flush_or_ignore()

    def tcp_message(self, flow: Any) -> None:
        # Nothing of a raw stream is relayed: mitmproxy sends the message's content *after* this
        # hook returns, so emptying it is what actually stops the bytes (a kill does not).
        messages = getattr(flow, "messages", None) or ()
        for message in messages[-1:]:
            message.content = b""
        self._kill(flow)

    def websocket_message(self, flow: Any) -> None:
        """Decide each client-to-server frame; a refused frame is dropped and the socket closed.

        A server-to-client frame is not the sandbox's egress and passes untouched. Anything that
        fails — reading the frame, deciding it, or recording the decision — drops the frame rather
        than relaying it undecided, the same fail-closed rule as the other hooks.
        """
        message: Any = None
        try:
            message = flow.websocket.messages[-1]
            if not message.from_client:
                return
            request = flow.request
            block = self._addon.on_websocket_message(
                request.host,
                request.port,
                scheme=request.scheme,
                path=request.path,
                content=message.content,
                sni=client_sni(flow),
            )
        except Exception as error:
            block = self._error(flow, "websocket_message", error)
        try:
            self._flush()
        except Exception as error:
            block = block or BlockResponse(
                status=BLOCK_STATUS_ERROR,
                reason=f"the flow log could not be written ({type(error).__name__})",
            )
        if block is None:
            return
        # mitmproxy relays the frame after this hook returns; ``drop`` is what stops it. The socket
        # is *not* closed: measured against mitmproxy 12.2.3, ``flow.kill()`` on a WebSocket flow
        # marks it and keeps relaying later frames. So the control is this hook deciding every
        # frame — past a cap each one is refused on its own, as the cap stays exceeded.
        if message is not None:
            with contextlib.suppress(Exception):
                message.drop()

    def done(self) -> None:
        self._flush()

    def _error(self, flow: Any, hook: str, error: BaseException) -> BlockResponse:
        request = getattr(flow, "request", None)
        host = getattr(request, "host", "")
        port = getattr(request, "port", 0)
        method = getattr(request, "method", "")
        return self._addon.on_hook_error(
            hook,
            error,
            host=host if isinstance(host, str) else "",
            port=port if isinstance(port, int) else 0,
            method=method if isinstance(method, str) else "",
        )

    def _settle(self, flow: Any, block: BlockResponse | None) -> None:
        """Persist the decision, then apply it. The log is written *before* a request is let
        through: a forwarded request the log cannot record is refused instead (§10.5.0)."""
        try:
            self._flush()
        except Exception as error:
            block = block or BlockResponse(
                status=BLOCK_STATUS_ERROR,
                reason=f"the flow log could not be written ({type(error).__name__})",
            )
        if block is None:
            return
        try:
            flow.response = self._render(block)
        except Exception:
            self._kill(flow)

    @staticmethod
    def _kill(flow: Any) -> None:
        # A flow that cannot be killed is already dead.
        with contextlib.suppress(Exception):
            if getattr(flow, "killable", True):
                flow.kill()

    def _flush_or_ignore(self) -> None:
        # The stream is refused either way; a lost record cannot un-refuse it.
        with contextlib.suppress(Exception):
            self._flush()

    def _flush(self) -> None:
        write_flow_records(self._path, self._addon.flows())


def _server_address(flow: Any) -> tuple[str, int]:
    """The ``(host, port)`` a TCP flow was headed for, or ``("", 0)`` where mitmproxy has none."""
    address = getattr(getattr(flow, "server_conn", None), "address", None)
    if isinstance(address, tuple) and len(address) >= 2:
        host, port = address[0], address[1]
        return (host if isinstance(host, str) else "", port if isinstance(port, int) else 0)
    return ("", 0)


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
