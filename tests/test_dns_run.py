"""WP-15: standing the controlled resolver up around one run (§10.6), offline.

The live standup is the CI docker test; here a fake backend and a fake resolver pin the standup
logic — create-or-join the internal bridge, start the resolver, read its IP, augment the allowlist
with the proxy name, and tear down on failure — the same treatment ``test_proxy_run`` gives the
recording proxy. The one shape that differs from the proxy is deliberate: the resolver is *not*
dual-homed, so there is no egress bridge, and it only *owns* the bridge when egress is off.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bellwether.capture import DnsAllowlist, DnsQuery
from bellwether.cli.dns_run import DnsResolverProvider, RunResolver
from bellwether.errors import BellwetherError

_ALLOWLIST = DnsAllowlist(frozenset({"api.anthropic.com"}))


class _FakeBackend:
    def __init__(self) -> None:
        self.created: list[tuple[str, bool]] = []
        self.removed: list[str] = []

    def create_network(self, name: str, *, internal: bool = True) -> str:
        self.created.append((name, internal))
        return name

    def remove_network(self, name: str) -> None:
        self.removed.append(name)


class _FakeResolver:
    def __init__(self, *, shared_dir: Path, network: str, fail_start: bool = False) -> None:
        self.shared_dir = shared_dir
        self.network = network
        self.fail_start = fail_start
        self.started_allowlist: DnsAllowlist | None = None
        self.stopped = False
        self._queries: list[DnsQuery] = []

    def start(self, run_id: str, *, allowlist: DnsAllowlist) -> None:
        if self.fail_start:
            raise BellwetherError("resolver refused to come up")
        self.started_allowlist = allowlist
        self._run_id = run_id

    def resolver_ip(self) -> str:
        return "172.30.0.7"

    def queries(self) -> list[DnsQuery]:
        return self._queries

    def stop(self) -> None:
        self.stopped = True


def _provider(backend: _FakeBackend, *, fail_start: bool = False):  # type: ignore[no-untyped-def]
    made: dict[str, _FakeResolver] = {}

    def factory(network: str, shared_dir: Path) -> _FakeResolver:  # type: ignore[return-value]
        resolver = _FakeResolver(shared_dir=shared_dir, network=network, fail_start=fail_start)
        made["resolver"] = resolver
        return resolver  # type: ignore[return-value]

    provider = DnsResolverProvider(
        backend=backend,  # type: ignore[arg-type]
        image="bw-resolver@sha256:x",
        allowlist=_ALLOWLIST,
        resolver_factory=factory,  # type: ignore[arg-type]
    )
    return provider, made


# ---------------------------------------------------------------------------
# open — create-vs-join, the IP the sandbox is pointed at, the augmented allowlist
# ---------------------------------------------------------------------------


def test_open_creates_the_internal_bridge_when_egress_is_off(tmp_path: Path) -> None:
    backend = _FakeBackend()
    provider, made = _provider(backend)

    run_resolver = provider.open("run1", shared_dir=tmp_path / "dns")
    resolver = made["resolver"]

    # No proxy owns a bridge, so the resolver creates the internal one (no route out) and owns it.
    assert ("bw-int-run1", True) in backend.created
    assert resolver.network == "bw-int-run1"
    assert resolver.started_allowlist is not None
    assert run_resolver.sandbox_network() == "bw-int-run1"
    # The sandbox is pointed at the resolver by IP.
    assert run_resolver.sandbox_dns() == "172.30.0.7"
    assert run_resolver.owns_network


def test_open_joins_an_existing_bridge_when_the_proxy_owns_it(tmp_path: Path) -> None:
    """Egress on: the proxy already created ``bw-int-run1``; the resolver joins it as a second peer
    and must NOT create (or later remove) it."""
    backend = _FakeBackend()
    provider, made = _provider(backend)

    run_resolver = provider.open("run1", shared_dir=tmp_path / "dns", network="bw-int-run1")

    assert backend.created == []  # joined, did not create
    assert made["resolver"].network == "bw-int-run1"
    assert not run_resolver.owns_network


def test_extra_allowed_names_reach_the_resolver_allowlist(tmp_path: Path) -> None:
    """The proxy's container name is known only at standup and must be resolvable, or the sandbox
    cannot reach its HTTPS_PROXY. It is passed in as extra_allowed and merged into the allowlist."""
    backend = _FakeBackend()
    provider, made = _provider(backend)

    provider.open(
        "run1", shared_dir=tmp_path / "dns", network="bw-int-run1", extra_allowed=["bw-proxy-run1"]
    )
    allowlist = made["resolver"].started_allowlist
    assert allowlist is not None
    assert allowlist.permits("bw-proxy-run1")
    assert allowlist.permits("api.anthropic.com")  # base allowlist preserved


# ---------------------------------------------------------------------------
# teardown — ownership decides who removes the bridge; failure leaks nothing
# ---------------------------------------------------------------------------


def test_close_removes_the_bridge_only_when_the_resolver_owns_it(tmp_path: Path) -> None:
    backend = _FakeBackend()
    provider, made = _provider(backend)

    owned = provider.open("run1", shared_dir=tmp_path / "dns")  # owns it
    owned.close()
    assert made["resolver"].stopped
    assert "bw-int-run1" in backend.removed

    backend2 = _FakeBackend()
    provider2, made2 = _provider(backend2)
    joined = provider2.open("run2", shared_dir=tmp_path / "dns2", network="bw-int-run2")  # joined
    joined.close()
    assert made2["resolver"].stopped
    assert backend2.removed == []  # the proxy owns and removes bw-int-run2, not the resolver


def test_open_tears_down_when_the_resolver_fails(tmp_path: Path) -> None:
    """A failure mid-standup must leak no network or container — open owns its own cleanup."""
    backend = _FakeBackend()
    provider, made = _provider(backend, fail_start=True)

    with pytest.raises(BellwetherError, match="refused to come up"):
        provider.open("run1", shared_dir=tmp_path / "dns")

    assert made["resolver"].stopped
    assert "bw-int-run1" in backend.removed  # the bridge it created is torn down


def test_a_failed_join_does_not_remove_the_proxys_bridge(tmp_path: Path) -> None:
    """When the resolver only joined the proxy's bridge, a standup failure must not remove that
    bridge out from under the proxy."""
    backend = _FakeBackend()
    provider, _ = _provider(backend, fail_start=True)

    with pytest.raises(BellwetherError):
        provider.open("run1", shared_dir=tmp_path / "dns", network="bw-int-run1")

    assert backend.removed == []  # not ours to remove


def test_queries_are_read_from_the_resolver(tmp_path: Path) -> None:
    backend = _FakeBackend()
    provider, made = _provider(backend)
    run_resolver: RunResolver = provider.open("run1", shared_dir=tmp_path / "dns")
    made["resolver"]._queries = [DnsQuery(ts="t", name="evil.example", resolved=False, reason="x")]
    assert [q.name for q in run_resolver.queries()] == ["evil.example"]
