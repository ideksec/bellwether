"""WP-13 (increment 2b-ii): the host side of the recording-proxy sidecar (§10.5).

The lifecycle around the ``mitmdump`` container, tested without a daemon via the ``runner`` and
``sleep`` seams — the same way ``DockerBackend.build_argv`` is tested offline. The live standup
against a real ``mitmproxy`` image is the docker-marked test, on CI. What matters most here is the
host-side security property: the real key is forwarded by *name*, never valued on the command
line, so it appears in no argv, config, or artifact.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from bellwether.capture import (
    CapLedger,
    CredentialBroker,
    EgressAllowlist,
    MitmproxySidecar,
)
from bellwether.capture.sidecar import SIDECAR_ENTRY_PATH
from bellwether.capture.sidecar_entry import SidecarConfig
from bellwether.determinism import SeededRng
from bellwether.errors import BellwetherError

_REAL_KEY = "sk-real-ANTHROPIC-secret-value"
_HOST_ENVIRON = {"ANTHROPIC_API_KEY": _REAL_KEY}
_PROVIDERS = frozenset({"api.anthropic.com"})
_INFRA = frozenset({"telemetry.example-harness.com"})


def _broker() -> CredentialBroker:
    return CredentialBroker.for_run(
        {"anthropic": "ANTHROPIC_API_KEY"}, _HOST_ENVIRON, rng=SeededRng(1, "cred")
    )


def _allowlist() -> EgressAllowlist:
    return EgressAllowlist(provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA)


class _FakeRunner:
    """Records the commands it is asked to run and, for the sidecar start, simulates the container
    by writing the empty flow log the real entry writes at load — which is the readiness signal."""

    def __init__(self, *, flow_log: Path, start_rc: int = 0, write_log: bool = True) -> None:
        self.flow_log = flow_log
        self.start_rc = start_rc
        self.write_log = write_log
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if argv[:3] == ["docker", "run", "--rm"]:
            if self.write_log and self.start_rc == 0:
                self.flow_log.write_text("", encoding="utf-8")  # sidecar's empty log at t=0
            return subprocess.CompletedProcess(argv, self.start_rc, stdout="cid\n", stderr="boom")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def _sidecar(shared: Path, runner: _FakeRunner) -> MitmproxySidecar:
    return MitmproxySidecar(
        image="bw-proxy@sha256:deadbeef",
        network="bw-net-run",
        broker=_broker(),
        provider_of_host={"api.anthropic.com": "anthropic"},
        shared_dir=shared,
        runner=runner,
        sleep=lambda _s: None,
    )


# ---------------------------------------------------------------------------
# argv — and the credential that must not appear in it
# ---------------------------------------------------------------------------


def test_the_argv_carries_the_topology_and_entry() -> None:
    sidecar = MitmproxySidecar(
        image="bw-proxy@sha256:deadbeef",
        network="bw-net-run",
        broker=_broker(),
        provider_of_host={},
        shared_dir=Path("/shared"),
    )
    from pathlib import PurePosixPath

    argv = " ".join(sidecar.sidecar_argv("bw-proxy-r1", PurePosixPath("/bw/config.json")))
    assert "--network bw-net-run" in argv
    assert "/shared:/bw:rw" in argv
    assert "bw-proxy@sha256:deadbeef" in argv
    assert f"-s {SIDECAR_ENTRY_PATH}" in argv
    assert "block_global=false" in argv
    assert "--listen-port 8080" in argv


def test_the_real_key_is_forwarded_by_name_never_valued_on_the_command_line() -> None:
    """§3.3: the key must reach the sidecar but never the process table or a recorded command. It
    is named with `-e KEY` and forwarded from the launcher's env, so its value is in no argv."""
    sidecar = MitmproxySidecar(
        image="img@sha256:x",
        network="net",
        broker=_broker(),
        provider_of_host={},
        shared_dir=Path("/shared"),
    )
    from pathlib import PurePosixPath

    argv = sidecar.sidecar_argv("bw-proxy-r1", PurePosixPath("/bw/config.json"))
    assert "-e" in argv
    # The env var is named...
    assert "ANTHROPIC_API_KEY" in argv
    # ...but its value never appears, in any token.
    assert all(_REAL_KEY not in token for token in argv)


# ---------------------------------------------------------------------------
# start — config written, readiness, handle
# ---------------------------------------------------------------------------


def test_start_writes_a_secretless_config_and_becomes_ready(tmp_path: Path) -> None:
    runner = _FakeRunner(flow_log=tmp_path / "flows.jsonl")
    sidecar = _sidecar(tmp_path, runner)

    sidecar.start(
        "r1", allowlist=_allowlist(), caps=CapLedger(max_requests=5, max_request_bytes=100)
    )

    config_text = (tmp_path / "config.json").read_text(encoding="utf-8")
    config = SidecarConfig.from_json(config_text)
    assert config.provider_endpoints == ("api.anthropic.com",)
    assert config.max_requests == 5
    # The real key is never written to the shared config the container can read.
    assert _REAL_KEY not in config_text
    assert sidecar.proxy_url() == "http://bw-proxy-r1:8080"


def test_a_stale_flow_log_is_cleared_before_the_run(tmp_path: Path) -> None:
    """A leaked log from a crashed run would make readiness trivially true and hand this run
    someone else's flows; it must be removed before the sidecar recreates it."""
    stale = tmp_path / "flows.jsonl"
    stale.write_text('{"stale": true}\n', encoding="utf-8")
    runner = _FakeRunner(flow_log=stale)
    sidecar = _sidecar(tmp_path, runner)

    sidecar.start(
        "r1", allowlist=_allowlist(), caps=CapLedger(max_requests=5, max_request_bytes=100)
    )
    # The runner wrote a fresh empty log; the stale record is gone.
    assert sidecar.flows() == []


def test_a_sidecar_that_never_writes_its_log_is_a_loud_timeout(tmp_path: Path) -> None:
    runner = _FakeRunner(flow_log=tmp_path / "flows.jsonl", write_log=False)
    sidecar = MitmproxySidecar(
        image="img@sha256:x",
        network="net",
        broker=_broker(),
        provider_of_host={},
        shared_dir=tmp_path,
        runner=runner,
        sleep=lambda _s: None,
        ready_timeout=0.5,
    )
    with pytest.raises(BellwetherError, match="did not become ready"):
        sidecar.start(
            "r1", allowlist=_allowlist(), caps=CapLedger(max_requests=5, max_request_bytes=100)
        )


def test_a_failed_start_raises_with_the_reason(tmp_path: Path) -> None:
    runner = _FakeRunner(flow_log=tmp_path / "flows.jsonl", start_rc=1)
    sidecar = _sidecar(tmp_path, runner)
    with pytest.raises(BellwetherError, match="could not start"):
        sidecar.start(
            "r1", allowlist=_allowlist(), caps=CapLedger(max_requests=5, max_request_bytes=100)
        )


# ---------------------------------------------------------------------------
# flows / stop
# ---------------------------------------------------------------------------


def test_flows_before_start_raises_rather_than_returning_empty(tmp_path: Path) -> None:
    sidecar = _sidecar(tmp_path, _FakeRunner(flow_log=tmp_path / "flows.jsonl"))
    with pytest.raises(BellwetherError, match="not been started"):
        sidecar.flows()


def test_stop_force_removes_the_container(tmp_path: Path) -> None:
    runner = _FakeRunner(flow_log=tmp_path / "flows.jsonl")
    sidecar = _sidecar(tmp_path, runner)
    sidecar.start(
        "r1", allowlist=_allowlist(), caps=CapLedger(max_requests=5, max_request_bytes=100)
    )
    sidecar.stop()
    assert ["docker", "rm", "-f", "bw-proxy-r1"] in runner.calls


def test_stop_without_start_is_a_noop(tmp_path: Path) -> None:
    runner = _FakeRunner(flow_log=tmp_path / "flows.jsonl")
    sidecar = _sidecar(tmp_path, runner)
    sidecar.stop()  # must not raise
    assert runner.calls == []
