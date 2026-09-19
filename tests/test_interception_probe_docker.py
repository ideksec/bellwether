"""WP-14's live half, for real: a container that trusts the proxy, proven by a request (§9.2).

**CI-only.** Building the sidecar image needs the public registries the restricted build
environment blocks, so this is gated on ``CI`` and skips locally with a stated reason.

This is the done-when the CA trust chain never had. The existing interception test
(`test_sidecar_docker.py`) deliberately used plain HTTP, which proves routing and blocking but
says nothing about whether the sandbox would accept the proxy's certificate — and a sandbox
that would not produces zero-egress traces that read as a clean skill. Here a real container on
the run's own internal bridge, carrying the §9.2 trust environment, completes a genuine TLS
handshake against the proxy and the flow appears in the proxy's own log.

The counter-case is asserted too, because a probe that cannot fail proves nothing: the same
request from a container with the CA *removed* from the trust environment is rejected, no flow
is recorded, and the probe reports the dangerous state rather than an inconclusive shrug.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from bellwether.capture import CredentialBroker
from bellwether.cli.interception_probe import PROBE_HOST, ProbeRunner, run_interception_probe
from bellwether.cli.proxy_run import SidecarProxyProvider
from bellwether.determinism import SeededRng
from bellwether.sandbox import DockerBackend
from tests.test_interception_probe import without_ca_trust

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not os.environ.get("CI"),
        reason="the sidecar image build needs open egress; CI only",
    ),
]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_IMAGE_TAG = "bw-proxy-sidecar:probe-test"


def _daemon_available() -> bool:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True
    )
    return probe.returncode == 0


@pytest.fixture(scope="module")
def sidecar_image() -> str:
    if not _daemon_available():
        pytest.skip("no Docker daemon")
    build = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(_REPO_ROOT / "sidecar" / "proxy" / "Dockerfile"),
            "-t",
            _IMAGE_TAG,
            str(_REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.fail(
            "sidecar image build failed:\n"
            f"--- stdout ---\n{build.stdout[-4000:]}\n--- stderr ---\n{build.stderr[-4000:]}"
        )
    return _IMAGE_TAG


def _provider(image: str) -> SidecarProxyProvider:
    from bellwether.cli.interception_probe import probe_allowlist

    return SidecarProxyProvider(
        backend=DockerBackend(image=image),
        image=image,
        allowlist=probe_allowlist(),
        max_requests=10,
        max_request_bytes=1_000_000,
        broker=CredentialBroker.for_run({}, {}, rng=SeededRng(1, "probe")),
    )


def test_a_real_container_completes_tls_against_the_proxy_and_the_flow_is_recorded(
    sidecar_image: str,
) -> None:
    """The chain a run actually gets: internal bridge, the run's trust environment, the CA at
    the executor's container path, a genuine HTTPS request. The probe host is unresolvable, so
    nothing leaves the machine — reaching the proxy is the whole of what is proven."""
    probe = run_interception_probe(_provider(sidecar_image), client_image=sidecar_image)

    assert probe.confirmed, f"interception not confirmed: {probe.reason}"
    assert not probe.ca_rejected
    assert PROBE_HOST in {host.lower().rstrip(".") for host in probe.recorded_hosts}


def test_without_the_ca_the_same_request_is_refused_and_the_probe_says_so(
    sidecar_image: str,
) -> None:
    """A probe that cannot fail proves nothing. Strip the CA from the trust environment and the
    client rejects the proxy's certificate: no flow is recorded, and the probe names the state
    in which every later run would look clean while observing nothing."""

    class _WithoutCaTrust(ProbeRunner):
        """The same probe, run by a client given no reason to believe the proxy."""

        def run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                without_ca_trust(argv), capture_output=True, text=True, timeout=120, check=False
            )

    probe = run_interception_probe(
        _provider(sidecar_image), client_image=sidecar_image, runner=_WithoutCaTrust()
    )
    assert not probe.confirmed, "a client with no CA must not confirm interception"
    assert probe.ca_rejected, f"expected a certificate rejection, got: {probe.reason}"
    assert not probe.recorded_hosts
