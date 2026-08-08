"""Standing the recording proxy up around a run — the dual-homed topology, offline (§3.3, §10.5).

The Docker standup is proven against a real daemon on CI; here the pure and orchestration logic is
pinned with fakes: the env a sandbox needs to trust the proxy, the two-bridge topology the provider
builds, the dual-home attach, and the teardown order that a network-with-attached-container refusal
makes load-bearing.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from bellwether.capture import CredentialBroker, EgressAllowlist, EgressFlow
from bellwether.cli.proxy_run import RunProxy, SidecarProxyProvider, sandbox_proxy_env
from bellwether.errors import BellwetherError

_ALLOWLIST = EgressAllowlist(
    provider_endpoints=frozenset({"api.anthropic.com"}), infrastructure_endpoints=frozenset()
)


# ---------------------------------------------------------------------------
# sandbox_proxy_env — both halves, or the run reads clean while nothing works
# ---------------------------------------------------------------------------


def test_sandbox_proxy_env_carries_both_the_route_and_the_trust() -> None:
    env = sandbox_proxy_env("http://bw-proxy-r1:8080")
    # Every connection goes to the sidecar, both cases because different clients read different ones.
    assert env["HTTPS_PROXY"] == "http://bw-proxy-r1:8080"
    assert env["https_proxy"] == "http://bw-proxy-r1:8080"
    # And every runtime is told to trust the proxy's CA — the half whose absence turns interception
    # into a silent zero-egress trace (§9.2).
    for var in ("NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
        assert var in env
        assert env[var].endswith("bellwether-proxy.crt")


# ---------------------------------------------------------------------------
# Fakes for the daemon-touching collaborators
# ---------------------------------------------------------------------------


class _FakeBackend:
    def __init__(self) -> None:
        self.created: list[tuple[str, bool]] = []
        self.connected: list[tuple[str, str]] = []
        self.removed: list[str] = []

    def create_network(self, name: str, *, internal: bool = True) -> str:
        self.created.append((name, internal))
        return name

    def connect_network(self, network: str, container: str) -> None:
        self.connected.append((network, container))

    def remove_network(self, name: str) -> None:
        self.removed.append(name)


class _FakeSidecar:
    def __init__(self, *, shared_dir: Path, network: str, fail_start: bool = False) -> None:
        self.shared_dir = shared_dir
        self.network = network
        self.fail_start = fail_start
        self.started = False
        self.stopped = False
        self._flows: list[EgressFlow] = []

    def start(self, run_id: str, *, allowlist: EgressAllowlist, caps: object) -> None:
        if self.fail_start:
            raise BellwetherError("sidecar refused to come up")
        self.started = True
        self._run_id = run_id

    def container_name(self) -> str:
        return f"bw-proxy-{self._run_id}"

    def ca_cert_path(self) -> Path:
        return self.shared_dir / "mitmproxy" / "mitmproxy-ca-cert.pem"

    def proxy_url(self) -> str:
        return f"http://bw-proxy-{self._run_id}:8080"

    def flows(self) -> list[EgressFlow]:
        return self._flows

    def stop(self) -> None:
        self.stopped = True


def _provider(backend: _FakeBackend, *, fail_start: bool = False):  # type: ignore[no-untyped-def]
    made: dict[str, _FakeSidecar] = {}

    def factory(network: str, shared_dir: Path) -> _FakeSidecar:  # type: ignore[return-value]
        sidecar = _FakeSidecar(shared_dir=shared_dir, network=network, fail_start=fail_start)
        made["sidecar"] = sidecar
        return sidecar  # type: ignore[return-value]

    provider = SidecarProxyProvider(
        backend=backend,  # type: ignore[arg-type]
        image="bw-proxy@sha256:x",
        allowlist=_ALLOWLIST,
        max_requests=10,
        max_request_bytes=1000,
        broker=CredentialBroker({}),
        sidecar_factory=factory,  # type: ignore[arg-type]
    )
    return provider, made


# ---------------------------------------------------------------------------
# open — the two bridges, the dual-home, the wiring the sandbox receives
# ---------------------------------------------------------------------------


def test_open_builds_the_dual_homed_topology(tmp_path: Path) -> None:
    backend = _FakeBackend()
    provider, made = _provider(backend)

    run_proxy = provider.open("run1", shared_dir=tmp_path / "proxy")
    sidecar = made["sidecar"]

    # An internal bridge (no route out) and an ordinary egress bridge (has a gateway).
    assert ("bw-int-run1", True) in backend.created
    assert ("bw-egr-run1", False) in backend.created
    # The sidecar started on the internal bridge, then was attached to the egress bridge too.
    assert sidecar.network == "bw-int-run1"
    assert sidecar.started
    assert ("bw-egr-run1", "bw-proxy-run1") in backend.connected

    # The sandbox is wired to the internal bridge, routed through the proxy, trusting its CA.
    assert run_proxy.sandbox_network() == "bw-int-run1"
    env = run_proxy.sandbox_env()
    assert env["HTTPS_PROXY"] == "http://bw-proxy-run1:8080"
    (ca_host, ca_container) = run_proxy.sandbox_ro_binds()[0]
    assert ca_host == sidecar.ca_cert_path()
    assert ca_container == PurePosixPath("/usr/local/share/ca-certificates/bellwether-proxy.crt")


def test_open_clears_a_leaked_network_before_creating(tmp_path: Path) -> None:
    """create_network is non-idempotent; a name leaked by a crashed prior run must be removed
    first, or this run attaches to a bridge whose peers we did not place."""
    backend = _FakeBackend()
    provider, _ = _provider(backend)
    provider.open("run1", shared_dir=tmp_path / "proxy")
    # Both names are removed before the run, defensively.
    assert "bw-int-run1" in backend.removed
    assert "bw-egr-run1" in backend.removed


def test_open_tears_everything_down_when_the_sidecar_fails(tmp_path: Path) -> None:
    """A failure mid-standup must leak no network or container — the whole reason open owns its
    own cleanup rather than leaving it to the caller."""
    backend = _FakeBackend()
    provider, made = _provider(backend, fail_start=True)

    with pytest.raises(BellwetherError, match="refused to come up"):
        provider.open("run1", shared_dir=tmp_path / "proxy")

    sidecar = made["sidecar"]
    assert sidecar.stopped
    # Both bridges created during the failed standup are removed again (plus the pre-clear).
    assert backend.removed.count("bw-egr-run1") >= 1
    assert backend.removed.count("bw-int-run1") >= 1


# ---------------------------------------------------------------------------
# close — order matters
# ---------------------------------------------------------------------------


def test_close_stops_the_sidecar_before_removing_its_networks(tmp_path: Path) -> None:
    """A network with a container still attached refuses removal, so the sidecar (on both) must be
    stopped first."""
    backend = _FakeBackend()
    provider, made = _provider(backend)
    run_proxy = provider.open("run1", shared_dir=tmp_path / "proxy")
    backend.removed.clear()  # ignore the defensive pre-clear; watch only teardown

    run_proxy.close()
    sidecar = made["sidecar"]
    assert sidecar.stopped
    # Egress then internal, both after the stop.
    assert backend.removed == ["bw-egr-run1", "bw-int-run1"]


def test_flows_delegates_to_the_sidecar(tmp_path: Path) -> None:
    backend = _FakeBackend()
    provider, made = _provider(backend)
    run_proxy: RunProxy = provider.open("run1", shared_dir=tmp_path / "proxy")
    assert run_proxy.flows() == []
    assert made["sidecar"].flows() == []
