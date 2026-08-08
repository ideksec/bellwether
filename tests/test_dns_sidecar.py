"""WP-15: the host side of the controlled-resolver sidecar (§10.6), offline.

The live standup against a real resolver container is the docker-marked test on CI; here the
``runner``/``sleep`` seams let the whole lifecycle run without a daemon, the same split
``test_sidecar`` gets for the recording proxy. What is pinned: the argv topology, that there is no
credential channel (a resolver holds none), config written + readiness, the ``docker inspect`` IP
read the sandbox's ``--dns`` needs, and the fail-loud paths (no IP, no log, failed start).
"""

from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath

import pytest

from bellwether.capture import DnsAllowlist, DnsResolverSidecar, ResolverConfig, read_query_records
from bellwether.capture.dns_sidecar import RESOLVER_ENTRY_PATH
from bellwether.capture.resolver_entry import RESOLVER_CONFIG_ENV_VAR
from bellwether.errors import BellwetherError

_ALLOWLIST = DnsAllowlist(frozenset({"api.anthropic.com"}))


class _FakeRunner:
    """Records commands, and for the resolver start simulates the container by writing the empty
    query log the real entry writes at load (the readiness signal); for ``docker inspect`` it
    returns the container's bridge IP."""

    def __init__(
        self, *, query_log: Path, start_rc: int = 0, write_log: bool = True, ip: str = "172.30.0.5"
    ) -> None:
        self.query_log = query_log
        self.start_rc = start_rc
        self.write_log = write_log
        self.ip = ip
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if argv[:3] == ["docker", "run", "--rm"]:
            if self.write_log and self.start_rc == 0:
                self.query_log.write_text("", encoding="utf-8")  # resolver's empty log at t=0
            return subprocess.CompletedProcess(argv, self.start_rc, stdout="cid\n", stderr="boom")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout=f"{self.ip}\n", stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def _resolver(shared: Path, runner: _FakeRunner) -> DnsResolverSidecar:
    return DnsResolverSidecar(
        image="bw-resolver@sha256:deadbeef",
        network="bw-int-run",
        shared_dir=shared,
        runner=runner,
        sleep=lambda _s: None,
    )


# ---------------------------------------------------------------------------
# argv — topology, entry, and the absence of any credential channel
# ---------------------------------------------------------------------------


def test_the_argv_carries_the_topology_and_entry() -> None:
    sidecar = DnsResolverSidecar(
        image="bw-resolver@sha256:deadbeef", network="bw-int-run", shared_dir=Path("/shared")
    )
    argv = " ".join(
        sidecar.resolver_argv("bw-resolver-r1", PurePosixPath("/bw/resolver-config.json"))
    )
    assert "--network bw-int-run" in argv
    assert "/shared:/bw:rw" in argv
    assert "bw-resolver@sha256:deadbeef" in argv
    assert f"python {RESOLVER_ENTRY_PATH}" in argv
    assert f"{RESOLVER_CONFIG_ENV_VAR}=/bw/resolver-config.json" in argv


def test_there_is_no_credential_channel() -> None:
    """A resolver injects nothing, so its argv carries exactly one ``-e`` — the config path — and
    never a ``-e KEY`` credential name (contrast the recording proxy, which forwards real keys)."""
    sidecar = DnsResolverSidecar(image="img@sha256:x", network="net", shared_dir=Path("/shared"))
    argv = sidecar.resolver_argv("bw-resolver-r1", PurePosixPath("/bw/resolver-config.json"))
    assert argv.count("-e") == 1
    assert any(token.startswith(f"{RESOLVER_CONFIG_ENV_VAR}=") for token in argv)


# ---------------------------------------------------------------------------
# start — config written, readiness, handle
# ---------------------------------------------------------------------------


def test_start_writes_the_allowlist_config_and_becomes_ready(tmp_path: Path) -> None:
    runner = _FakeRunner(query_log=tmp_path / "queries.jsonl")
    sidecar = _resolver(tmp_path, runner)
    sidecar.start("r1", allowlist=_ALLOWLIST)

    assert sidecar.container_name() == "bw-resolver-r1"
    written = ResolverConfig.from_json((tmp_path / "resolver-config.json").read_text())
    assert written.allowed == ("api.anthropic.com",)
    assert written.query_log_path == "/bw/queries.jsonl"
    # Ready because the (empty) query log exists — an observed zero-query run, not a missing plane.
    assert sidecar.queries() == []


def test_resolver_ip_reads_the_container_address(tmp_path: Path) -> None:
    runner = _FakeRunner(query_log=tmp_path / "queries.jsonl", ip="172.30.0.9")
    sidecar = _resolver(tmp_path, runner)
    sidecar.start("r1", allowlist=_ALLOWLIST)
    assert sidecar.resolver_ip() == "172.30.0.9"
    # The inspect used the index-based template (the network name has hyphens).
    inspect = next(c for c in runner.calls if c[:2] == ["docker", "inspect"])
    assert 'index .NetworkSettings.Networks "bw-int-run"' in " ".join(inspect)


def test_a_resolver_with_no_ip_is_a_loud_failure(tmp_path: Path) -> None:
    runner = _FakeRunner(query_log=tmp_path / "queries.jsonl", ip="")  # inspect returns empty
    sidecar = _resolver(tmp_path, runner)
    sidecar.start("r1", allowlist=_ALLOWLIST)
    with pytest.raises(BellwetherError, match="uncontrolled"):
        sidecar.resolver_ip()


def test_a_stale_query_log_is_cleared_before_the_run(tmp_path: Path) -> None:
    stale = tmp_path / "queries.jsonl"
    stale.write_text('{"ts":"old","name":"leftover.example","resolved":false,"reason":"x"}\n')
    runner = _FakeRunner(query_log=stale)
    sidecar = _resolver(tmp_path, runner)
    sidecar.start("r1", allowlist=_ALLOWLIST)
    # The prior run's query must not be handed to this run.
    assert sidecar.queries() == []


def test_a_resolver_that_never_writes_its_log_is_a_loud_timeout(tmp_path: Path) -> None:
    runner = _FakeRunner(query_log=tmp_path / "queries.jsonl", write_log=False)
    sidecar = DnsResolverSidecar(
        image="i@sha256:x",
        network="net",
        shared_dir=tmp_path,
        runner=runner,
        sleep=lambda _s: None,
        ready_timeout=0.3,
    )
    with pytest.raises(BellwetherError, match="did not become ready"):
        sidecar.start("r1", allowlist=_ALLOWLIST)


def test_a_failed_start_raises_with_the_reason(tmp_path: Path) -> None:
    runner = _FakeRunner(query_log=tmp_path / "queries.jsonl", start_rc=1)
    sidecar = _resolver(tmp_path, runner)
    with pytest.raises(BellwetherError, match="could not start the controlled-resolver"):
        sidecar.start("r1", allowlist=_ALLOWLIST)


# ---------------------------------------------------------------------------
# queries / stop lifecycle guards
# ---------------------------------------------------------------------------


def test_queries_before_start_raises_rather_than_returning_empty(tmp_path: Path) -> None:
    sidecar = _resolver(tmp_path, _FakeRunner(query_log=tmp_path / "queries.jsonl"))
    with pytest.raises(BellwetherError, match="has not been started"):
        sidecar.queries()


def test_the_recorded_queries_are_read_back(tmp_path: Path) -> None:
    runner = _FakeRunner(query_log=tmp_path / "queries.jsonl")
    sidecar = _resolver(tmp_path, runner)
    sidecar.start("r1", allowlist=_ALLOWLIST)
    # Simulate the resolver appending a query mid-run.
    (tmp_path / "queries.jsonl").write_text(
        '{"name":"exfil.evil.example","reason":"NXDOMAIN","resolved":false,"ts":"t"}\n',
        encoding="utf-8",
    )
    recorded = sidecar.queries()
    assert [q.name for q in recorded] == ["exfil.evil.example"]
    assert recorded[0].blocked


def test_stop_force_removes_the_container(tmp_path: Path) -> None:
    runner = _FakeRunner(query_log=tmp_path / "queries.jsonl")
    sidecar = _resolver(tmp_path, runner)
    sidecar.start("r1", allowlist=_ALLOWLIST)
    sidecar.stop()
    assert ["docker", "rm", "-f", "bw-resolver-r1"] in runner.calls


def test_stop_without_start_is_a_noop(tmp_path: Path) -> None:
    runner = _FakeRunner(query_log=tmp_path / "queries.jsonl")
    _resolver(tmp_path, runner).stop()
    assert runner.calls == []


def test_read_back_uses_the_real_query_serializer(tmp_path: Path) -> None:
    """Guards the read path against drift from the write path — the same serializer the resolver
    uses inside the container."""
    log = tmp_path / "queries.jsonl"
    log.write_text('{"name":"api.anthropic.com","reason":"","resolved":true,"ts":"t"}\n')
    assert read_query_records(log)[0].resolved
