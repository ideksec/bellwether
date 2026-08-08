"""What runs *inside* the controlled-resolver sidecar — the dnslib entry point (§10.6).

The resolver is a separate container running a small UDP/53 server. At load it reads its config
from a file the host wrote to the shared volume, rebuilds the run's :class:`DnsAllowlist`, and
serves queries: an allowlisted name is answered (forwarded to the sidecar's own upstream — the
Docker embedded resolver, which knows the proxy's container name and the model endpoints), and
everything else is NXDOMAIN. **Every** query is recorded to the shared query log first, resolved
or not — the log is Plane E's ground truth, and a refused name is exactly the covert-channel
evidence the resolver exists to capture (§10.6).

The whole module is written so its logic is testable without dnslib or a container: the config
round-trips, and the recording decision (:meth:`_RecordingResolver.record`) is a pure
``decide_query`` + append that a test drives directly. The only genuinely dnslib-shaped surface —
parsing the query packet and building the reply — is one method, lazily importing dnslib and
validated by the live docker test that stands the resolver up on CI. The host launcher that starts
this container is the following slice.

Unlike the recording proxy, the resolver holds **no credentials**: it injects nothing, so there is
no broker and no real key anywhere near it. Its config is entirely non-secret (the allowlist, the
log path, the upstream).
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bellwether.capture.dns import DnsAllowlist, DnsQuery, decide_query, write_query_records
from bellwether.determinism import canonical_json

__all__ = [
    "RESOLVER_CONFIG_ENV_VAR",
    "ResolverConfig",
    "build_allowlist",
    "load_resolver_from_env",
]

#: The env var naming the config file the host wrote to the shared volume. The resolver reads it
#: at load; its absence is a hard error, not an empty run — a resolver with no config would answer
#: nothing (or everything) and record nothing, the clean-looking failure this plane distrusts.
RESOLVER_CONFIG_ENV_VAR = "BW_RESOLVER_CONFIG"

#: The upstream the resolver forwards an *allowlisted* name to. Inside a Docker user-defined
#: network every container reaches the embedded DNS at 127.0.0.11, which resolves both the
#: sibling container names (the recording proxy) and public names (by forwarding to the host's
#: resolver). Non-allowlisted names never reach it — they are NXDOMAINed and logged here.
DEFAULT_UPSTREAM = "127.0.0.11"


@dataclass(frozen=True)
class ResolverConfig:
    """The non-secret run configuration the host hands the resolver (§10.6).

    Everything the resolver needs to decide and record a query: the allowlist, the query-log path
    on the shared volume the host reads back, the upstream to forward allowlisted names to, and the
    UDP port to listen on. No secret ever appears here — the resolver holds none.
    """

    allowed: tuple[str, ...]
    query_log_path: str
    upstream: str = DEFAULT_UPSTREAM
    listen_port: int = 53

    def to_json(self) -> str:
        """Canonical JSON, so the config the host writes and the resolver reads is byte-stable."""
        return canonical_json(
            {
                "allowed": list(self.allowed),
                "query_log_path": self.query_log_path,
                "upstream": self.upstream,
                "listen_port": self.listen_port,
            }
        )

    @classmethod
    def from_json(cls, text: str) -> ResolverConfig:
        payload: dict[str, Any] = json.loads(text)
        return cls(
            allowed=tuple(payload["allowed"]),
            query_log_path=payload["query_log_path"],
            upstream=payload.get("upstream", DEFAULT_UPSTREAM),
            listen_port=payload.get("listen_port", 53),
        )


def build_allowlist(config: ResolverConfig) -> DnsAllowlist:
    """Rebuild the run's :class:`DnsAllowlist` from the resolver's config."""
    return DnsAllowlist(allowed=frozenset(config.allowed))


def _wall_clock() -> str:
    """Real capture time, ISO-8601 UTC. Plane E timestamps are genuine wall-clock and are anchored
    to epochs later (§11.5), so a real clock here is correct, not a determinism hole — the same
    pattern the sink, the api-loop adapter, and the recording proxy use."""
    import datetime as dt

    return dt.datetime.now(dt.UTC).isoformat()


class _RecordingResolver:
    """The dnslib resolver object. Its ``resolve`` hook is the only dnslib-shaped surface: it
    extracts the query name, calls :meth:`record` (all decision logic, tested), and builds a reply —
    forwarding an allowlisted name to the upstream, NXDOMAIN otherwise. Queries are flushed to the
    shared log after every one, so a crash mid-run still leaves what was seen — a partial log is
    evidence; a missing one reads as a clean run and must not happen silently.
    """

    def __init__(
        self,
        allowlist: DnsAllowlist,
        query_log_path: str,
        *,
        clock: Callable[[], str],
        upstream: str = DEFAULT_UPSTREAM,
    ) -> None:
        self._allowlist = allowlist
        self._path = Path(query_log_path)
        self._clock = clock
        self._upstream = upstream
        self._queries: list[DnsQuery] = []
        self._flush()  # write an empty log immediately: "the resolver ran" is true from t=0

    def record(self, name: str) -> DnsQuery:
        """Decide one query against the allowlist, append it to the log, and return it. Pure but
        for the append/flush — the whole recording contract, exercised directly in tests."""
        query = decide_query(name, allowlist=self._allowlist, ts=self._clock())
        self._queries.append(query)
        self._flush()
        return query

    def recorded(self) -> list[DnsQuery]:
        return list(self._queries)

    def _flush(self) -> None:
        write_query_records(self._path, self._queries)

    # -- The dnslib surface (§10.6) -----------------------------------------------------------
    #
    # dnslib is a dependency of the resolver container only, never of bellwether itself (the two
    # dep trees are kept apart exactly as the proxy's mitmproxy is), so this method is imported
    # lazily and proven by the CI docker test rather than the offline suite.

    def resolve(self, request: Any, handler: Any) -> Any:  # noqa: ARG002  # dnslib interface
        """The dnslib ``resolve`` interface: record the query, then answer or NXDOMAIN.

        ``handler`` (the dnslib client handler) is part of the required signature but unused —
        the recording decision needs only the query name. This method is the one dnslib-shaped
        surface, proven by the CI docker test, not the offline suite.

        An allowlisted name is forwarded to :attr:`_upstream` and its answer returned; anything else
        gets an ``NXDOMAIN`` reply. The name is recorded *before* the resolve decision so a refused
        query is still ground truth.
        """
        from dnslib import RCODE  # type: ignore[import-not-found]
        from dnslib.dns import DNSRecord  # type: ignore[import-not-found]

        name = str(request.q.qname).rstrip(".")
        query = self.record(name)
        if not query.resolved:
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        upstream_reply = DNSRecord.parse(
            request.send(self._upstream, 53, timeout=5)  # forward allowlisted names only
        )
        return upstream_reply


def load_resolver_from_env(environ: Mapping[str, str] | None = None) -> _RecordingResolver:
    """Build the resolver the dnslib server drives, from the config named by ``RESOLVER_CONFIG_ENV_VAR``.

    A missing env var or file is a hard error: a resolver that cannot find its config must fail to
    start, not run as an open (or silently empty) resolver.
    """
    env = os.environ if environ is None else environ
    config_path = env.get(RESOLVER_CONFIG_ENV_VAR)
    if not config_path:
        raise RuntimeError(
            f"{RESOLVER_CONFIG_ENV_VAR} is not set; the resolver has no configuration and refuses "
            "to run"
        )
    config = ResolverConfig.from_json(Path(config_path).read_text(encoding="utf-8"))
    return _RecordingResolver(
        build_allowlist(config),
        config.query_log_path,
        clock=_wall_clock,
        upstream=config.upstream,
    )
