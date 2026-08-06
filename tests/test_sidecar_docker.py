"""WP-13 done-when (partial): the recording-proxy sidecar image builds and loads the addon (§10.5).

**CI-only.** Building the image pulls ``python:3.12-slim`` and ``mitmproxy`` from the public
registries, which the restricted build environment these tests were written in blocks — so this is
gated on ``CI`` and skips locally with a stated reason, the same honesty the ``docker``-mark skips
carry. It proves the things that genuinely cannot be checked offline: the Dockerfile builds
reproducibly from its digest-pinned base, Bellwether imports inside the mitmproxy runtime, ``mitmdump``
loads our addon, and the empty-log-at-t0 readiness contract (``sidecar_entry``) holds in a real
container. The full interception + injection + block path through a client container is the next
slice, standing on this proven image.

On a readiness failure the sidecar's container logs are dumped into the assertion, so a first-run
CI failure is diagnosable from the job output rather than by guesswork.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from bellwether.capture import (
    CapLedger,
    CredentialBroker,
    EgressAllowlist,
    MitmproxySidecar,
)
from bellwether.determinism import SeededRng
from bellwether.errors import BellwetherError

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not os.environ.get("CI"),
        reason="the sidecar image build needs open egress to the public registries; CI only",
    ),
]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_IMAGE_TAG = "bw-proxy-sidecar:test"
_NETWORK = "bridge"  # the default bridge always exists; the smoke test needs no isolation


@pytest.fixture(scope="module")
def sidecar_image() -> str:
    """Build the sidecar image. A build failure fails loudly with the tail of the output — this is
    the point of the job, not something to skip past."""
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


def _daemon_available() -> bool:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True
    )
    return probe.returncode == 0


def _broker() -> CredentialBroker:
    return CredentialBroker.for_run(
        {"anthropic": "ANTHROPIC_API_KEY"},
        {"ANTHROPIC_API_KEY": "sk-real-value-for-the-sidecar"},
        rng=SeededRng(1, "cred"),
    )


def test_the_image_builds_and_mitmdump_loads_the_addon(sidecar_image: str, tmp_path: Path) -> None:
    """The empty flow log appearing is proof mitmdump came up and registered our addon — the
    inside-the-container half running for real, in a reproducibly-built image."""
    run_id = f"smoke-{os.getpid()}"
    sidecar = MitmproxySidecar(
        image=sidecar_image,
        network=_NETWORK,
        broker=_broker(),
        provider_of_host={"api.anthropic.com": "anthropic"},
        shared_dir=tmp_path / "shared",
        ready_timeout=60.0,
    )
    # Clear any container leaked by a crashed prior run so the name is free.
    subprocess.run(["docker", "rm", "-f", f"bw-proxy-{run_id}"], capture_output=True, text=True)

    try:
        sidecar.start(
            run_id,
            allowlist=EgressAllowlist(
                provider_endpoints=frozenset({"api.anthropic.com"}),
                infrastructure_endpoints=frozenset(),
            ),
            caps=CapLedger(max_requests=10, max_request_bytes=100_000),
        )
    except BellwetherError as exc:
        logs = subprocess.run(
            ["docker", "logs", f"bw-proxy-{run_id}"], capture_output=True, text=True
        )
        pytest.fail(f"{exc}\n--- container logs ---\n{logs.stdout}\n{logs.stderr}")

    try:
        # A written-but-empty log: the proxy is up and has seen nothing, which is the honest
        # state of a sidecar that just started.
        assert sidecar.flows() == []
        assert sidecar.proxy_url() == f"http://bw-proxy-{run_id}:8080"
    finally:
        sidecar.stop()
