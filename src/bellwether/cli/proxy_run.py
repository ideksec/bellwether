"""Standing the recording proxy up around one sandbox run — the dual-homed topology (§3.3, §10.5).

The executor runs a skill in a container that must have exactly one route out: the recording
proxy, which sees and records every flow. §3.3 invariant 3 makes that a routing fact rather than a
policy — the sandbox lives on a Docker ``--internal`` bridge with no gateway, so the kernel refuses
any socket to a public address. But the skill still *needs* the internet (a skill that cannot reach
out either fails or, worse, learns it is in a sandbox and behaves), so the proxy needs a way out the
sandbox does not have. That is the **dual-homed** topology this module assembles:

- an **internal** bridge, the sandbox's only home — no route out;
- an **egress** bridge, an ordinary bridge with a gateway;
- the **sidecar** attached to *both* — internal so the sandbox can reach it, egress so it can
  forward allowlisted traffic on. It is the sole crossing between the two worlds, and it records
  every crossing.

The sandbox is pointed at the sidecar with ``HTTPS_PROXY`` and told to trust its CA (§9.2), so TLS
is intercepted rather than silently failing to a zero-egress trace. What the proxy records becomes
Plane D of the run's ARF trace, and the egress plane finally reads *observed* instead of unavailable.

:func:`sandbox_proxy_env` — the env a sandbox needs to route through the proxy and trust it — is
pure and unit-tested offline; :class:`SidecarProxyProvider` drives the Docker standup and is proven
against a real daemon on CI.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from bellwether.capture import (
    DEFAULT_CA_CONTAINER_PATH,
    Canary,
    CapLedger,
    CredentialBroker,
    EgressAllowlist,
    EgressFlow,
    MitmproxySidecar,
    ca_trust_environment,
    proxy_environment,
)
from bellwether.sandbox import DockerBackend

__all__ = ["RunProxy", "SidecarProxyProvider", "sandbox_proxy_env"]

#: The container path the proxy CA is mounted at and the trust env points to. A single constant so
#: the mount target and every CA-bundle variable cannot drift apart.
_CA_CONTAINER_PATH = PurePosixPath(DEFAULT_CA_CONTAINER_PATH)


def sandbox_proxy_env(
    proxy_url: str, *, ca_container_path: str = DEFAULT_CA_CONTAINER_PATH
) -> dict[str, str]:
    """The environment a sandbox needs to route through the proxy and trust its CA (§9.2, §10.5).

    Two independent halves, and both are load-bearing. The ``HTTP(S)_PROXY`` variables send every
    connection to the sidecar; the CA-bundle variables (the complete §9.2 env table) make the
    container's runtimes trust the proxy's certificate. Without the second half, the first produces
    a run where every HTTPS handshake fails and the trace reads clean — the exact silent-interception
    failure §9.2 exists to prevent. No secret is here: these are ordinary env values, and the real
    key never enters the container (§3.3).
    """
    return {**proxy_environment(proxy_url), **ca_trust_environment(ca_container_path)}


@dataclass
class RunProxy:
    """One live sidecar, dual-homed around one sandbox run. :meth:`close` tears it all down.

    Constructed by :meth:`SidecarProxyProvider.open`; the executor asks it how to wire the sandbox
    (:meth:`sandbox_network`, :meth:`sandbox_env`, :meth:`sandbox_ro_binds`), reads the recorded
    :meth:`flows` after the run, and always calls :meth:`close` in a ``finally``.
    """

    backend: DockerBackend
    sidecar: MitmproxySidecar
    internal_network: str
    egress_network: str
    ca_host_path: Path

    def sandbox_network(self) -> str:
        """The internal bridge — the sandbox's only home, with no route out but to the proxy."""
        return self.internal_network

    def sandbox_env(self) -> dict[str, str]:
        """``HTTPS_PROXY`` + the CA-trust vars pointing the sandbox at this sidecar (§9.2)."""
        return sandbox_proxy_env(self.sidecar.proxy_url())

    def sandbox_ro_binds(self) -> list[tuple[Path, PurePosixPath]]:
        """The proxy CA, mounted read-only at the container trust path so TLS is intercepted."""
        return [(self.ca_host_path, _CA_CONTAINER_PATH)]

    def flows(self) -> list[EgressFlow]:
        """Every flow the proxy recorded for this run — Plane D of the trace (§10.5)."""
        return self.sidecar.flows()

    def close(self) -> None:
        """Stop the sidecar, then remove both bridges.

        Order matters: a network with a container still attached refuses removal, so the sidecar
        (attached to both) goes first. The sandbox is already gone by the time the executor calls
        this. Teardown is best-effort — ``remove_network`` swallows a missing network — so a
        half-built proxy still cleans up completely.
        """
        self.sidecar.stop()
        self.backend.remove_network(self.egress_network)
        self.backend.remove_network(self.internal_network)


#: How a sidecar is built for one run. Injected so the standup is testable without a daemon; the
#: default constructs the real :class:`MitmproxySidecar` on the run's internal bridge.
SidecarFactory = Callable[[str, Path], MitmproxySidecar]


@dataclass
class SidecarProxyProvider:
    """Builds a dual-homed :class:`RunProxy` per run from the daemon and the run's egress policy.

    Constructed once per evaluation with the proxy image, the default-deny allowlist, and the
    per-run caps; :meth:`open` is called per repetition. The broker is empty for the ``api-loop``
    harness — the model runs host-side with the real key, so the sandbox is handed no credential at
    all, and the strongest form of §3.3 invariant 1 holds trivially: there is nothing to steal.
    """

    backend: DockerBackend
    image: str
    allowlist: EgressAllowlist
    max_requests: int
    max_request_bytes: int
    broker: CredentialBroker
    #: host → provider name, for the sidecar's credential injection. Empty when no provider key is
    #: brokered into the sandbox (the ``api-loop`` case), which is the default.
    provider_of_host: dict[str, str] = field(default_factory=dict)
    sidecar_factory: SidecarFactory | None = None

    def open(self, run_id: str, *, shared_dir: Path, canaries: Sequence[Canary] = ()) -> RunProxy:
        """Create the two bridges, start the sidecar on the internal one, dual-home it, wait for
        its CA, and return the wired :class:`RunProxy`. Any failure mid-standup tears down whatever
        came up, so a crashed open leaks no network or container.

        ``canaries`` are the run's planted markers; they travel into the sidecar config so the proxy
        scans each request body for them (§10.5.2). Empty when planting is off.
        """
        internal = f"bw-int-{run_id}"
        egress = f"bw-egr-{run_id}"
        # create_network is deliberately non-idempotent; clear any leak from a crashed prior run
        # before creating, or a name collision would attach this run to a bridge we did not place.
        self.backend.remove_network(internal)
        self.backend.remove_network(egress)

        sidecar: MitmproxySidecar | None = None
        self.backend.create_network(internal, internal=True)
        try:
            self.backend.create_network(egress, internal=False)
            sidecar = self._build_sidecar(internal, shared_dir)
            sidecar.start(
                run_id,
                allowlist=self.allowlist,
                caps=CapLedger(
                    max_requests=self.max_requests, max_request_bytes=self.max_request_bytes
                ),
                canaries=canaries,
            )
            # Dual-home: the sidecar came up on the internal bridge (reachable by the sandbox); now
            # attach it to the egress bridge too, so it — and only it — has a route out (§3.3).
            self.backend.connect_network(egress, sidecar.container_name())
            ca_host_path = sidecar.ca_cert_path()
        except BaseException:
            if sidecar is not None:
                sidecar.stop()
            self.backend.remove_network(egress)
            self.backend.remove_network(internal)
            raise

        return RunProxy(
            backend=self.backend,
            sidecar=sidecar,
            internal_network=internal,
            egress_network=egress,
            ca_host_path=ca_host_path,
        )

    def _build_sidecar(self, network: str, shared_dir: Path) -> MitmproxySidecar:
        if self.sidecar_factory is not None:
            return self.sidecar_factory(network, shared_dir)
        return MitmproxySidecar(
            image=self.image,
            network=network,
            broker=self.broker,
            provider_of_host=self.provider_of_host,
            shared_dir=shared_dir,
        )
