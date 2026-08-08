"""Standing the controlled resolver up around one sandbox run (§10.6, §3.3 invariant 3).

The DNS analog of :mod:`bellwether.cli.proxy_run`, and deliberately simpler: the resolver is **not**
dual-homed. It has one job — answer allowlisted names, NXDOMAIN and log everything else — and needs
no route out of its own, so it lives on the run's internal bridge as a second peer beside the
sandbox (and, when egress is on, beside the recording proxy). There is no egress bridge and no CA:
a resolver forwards allowlisted names to the internal embedded DNS, and it injects nothing.

Topology, and why the network is shared rather than owned:

- The sandbox has exactly one network, and both the proxy and the resolver must be reachable on it.
  So when the recording proxy is on it owns the run's internal bridge, and the resolver **joins**
  that same bridge (``network=`` passed in). When egress is off there is no proxy and no bridge, so
  the resolver **creates** the internal bridge itself and the sandbox joins it.
- The sandbox is pointed at the resolver by **IP** (``docker --dns``), because ``--dns`` is resolved
  before any name resolution exists — unlike the proxy, which the sandbox reaches by container name.

:class:`DnsResolverProvider.open` drives the Docker standup and is proven against a real daemon on
CI; the standup logic (create-or-join, start, read the IP, tear down on failure) is unit-tested here
offline with a fake backend and resolver, the same treatment the proxy provider gets.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from bellwether.capture import DnsAllowlist, DnsQuery, DnsResolverSidecar
from bellwether.sandbox import DockerBackend

__all__ = ["DnsResolverProvider", "RunResolver"]


@dataclass
class RunResolver:
    """One live resolver on the run's internal bridge. :meth:`close` tears it down.

    Constructed by :meth:`DnsResolverProvider.open`; the executor asks it for the sandbox's DNS
    address (:meth:`sandbox_dns`) and — when the resolver owns the bridge — its network
    (:meth:`sandbox_network`), reads the recorded :meth:`queries` after the run, and always calls
    :meth:`close` in a ``finally``.
    """

    backend: DockerBackend
    sidecar: DnsResolverSidecar
    network: str
    owns_network: bool
    resolver_ip: str

    def sandbox_network(self) -> str:
        """The internal bridge the resolver is on — the sandbox's network when the resolver created
        it (egress off). When the proxy owns the bridge, the executor already has the name from it."""
        return self.network

    def sandbox_dns(self) -> str:
        """The resolver's bridge IP, for the sandbox's ``docker --dns`` (§9.2). An IP, not a name:
        ``--dns`` is consulted before name resolution exists."""
        return self.resolver_ip

    def queries(self) -> list[DnsQuery]:
        """Every query the resolver recorded for this run — Plane E of the trace (§10.6)."""
        return self.sidecar.queries()

    def close(self) -> None:
        """Stop the resolver, and remove the internal bridge **only if this run created it**.

        When the recording proxy owns the bridge, it removes it in its own ``close`` — removing it
        here too would be a double free (harmless, since ``remove_network`` swallows a missing
        network, but the ownership flag keeps the responsibility clear). Teardown is best-effort.
        """
        self.sidecar.stop()
        if self.owns_network:
            self.backend.remove_network(self.network)


#: How a resolver sidecar is built for one run. Injected so the standup is testable without a
#: daemon; the default constructs the real :class:`DnsResolverSidecar` on the run's internal bridge.
ResolverFactory = Callable[[str, Path], DnsResolverSidecar]


@dataclass
class DnsResolverProvider:
    """Builds a :class:`RunResolver` per run from the daemon and the run's DNS allowlist.

    Constructed once per evaluation with the resolver image and the default-deny allowlist;
    :meth:`open` is called per repetition. ``extra_allowed`` at open time carries names known only
    at standup — chiefly the recording proxy's container name, which the sandbox must be able to
    resolve to reach its ``HTTPS_PROXY`` when egress is on.
    """

    backend: DockerBackend
    image: str
    allowlist: DnsAllowlist
    resolver_factory: ResolverFactory | None = None

    def open(
        self,
        run_id: str,
        *,
        shared_dir: Path,
        network: str | None = None,
        extra_allowed: Iterable[str] = (),
    ) -> RunResolver:
        """Create or join the internal bridge, start the resolver on it, read its IP, and return the
        wired :class:`RunResolver`. Any failure mid-standup tears down whatever came up, so a crashed
        open leaks no network or container.

        ``network=None`` means egress is off and the resolver owns a fresh internal bridge; a given
        ``network`` means the proxy already created it and the resolver only joins it.
        """
        owns_network = network is None
        net = f"bw-int-{run_id}" if network is None else network
        if owns_network:
            # create_network is non-idempotent; clear any leak from a crashed prior run first, or a
            # name collision would attach this run to a bridge we did not place.
            self.backend.remove_network(net)
            self.backend.create_network(net, internal=True)

        sidecar: DnsResolverSidecar | None = None
        try:
            sidecar = self._build_sidecar(net, shared_dir)
            allowlist = DnsAllowlist(self.allowlist.allowed | frozenset(extra_allowed))
            sidecar.start(run_id, allowlist=allowlist)
            resolver_ip = sidecar.resolver_ip()
        except BaseException:
            if sidecar is not None:
                sidecar.stop()
            if owns_network:
                self.backend.remove_network(net)
            raise

        return RunResolver(
            backend=self.backend,
            sidecar=sidecar,
            network=net,
            owns_network=owns_network,
            resolver_ip=resolver_ip,
        )

    def _build_sidecar(self, network: str, shared_dir: Path) -> DnsResolverSidecar:
        if self.resolver_factory is not None:
            return self.resolver_factory(network, shared_dir)
        return DnsResolverSidecar(image=self.image, network=network, shared_dir=shared_dir)
