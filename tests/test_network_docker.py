"""WP-13/§3.3 invariant 3: the sandbox bridge has no unmediated route out.

The recording proxy is only trustworthy if it is the *only* way out — a container that can
open a socket straight to the internet produces traces that under-report its egress, which
is the clean-looking failure this project exists to distrust. The mechanism is a Docker
``--internal`` bridge: a container on it reaches only its peers, so the sole routes out are
the proxy and the resolver, which are those peers.

These assertions read ``/proc/net/route`` rather than shelling out to ``nc``/``curl``/bash
``/dev/tcp`` — the absence of a *default route* is invariant 3 as a routing fact, provable
with a plain file read that behaves identically on the alpine CI image and the mariner
default, before any userspace egress code could run. The live half — the proxy peer actually
being reachable and recording the flow — is the sidecar's job (WP-13 pt 2b-ii), validated on
CI; the isolation the sidecar depends on is proven here.

Marked ``docker`` and skipped, loudly, where no daemon is reachable.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bellwether.determinism import SeededRng
from bellwether.sandbox import DockerBackend, overlay_available, prepare_sandbox
from bellwether.skill import load_skill

pytestmark = pytest.mark.docker

TEST_IMAGE = os.environ.get(
    "BELLWETHER_TEST_IMAGE",
    "mcr.microsoft.com/cbl-mariner/base/core:2.0@sha256:c833841d2dcfd3081d2ee807050d19368854f70d9b6faef027463e2c6f45ee41",
)


@pytest.fixture(scope="session")
def backend() -> DockerBackend:
    docker = DockerBackend(image=TEST_IMAGE)
    usable, reason = docker.available()
    if not usable:
        pytest.skip(f"no Docker daemon: {reason}")
    return docker


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    root = tmp_path / "probe-skill"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: probe-skill\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    (root / "evals" / "scenarios.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: ScenarioSuite\n"
        "scenarios:\n  - id: s\n    expectation: should_trigger\n"
        '    prompt: "p"\n    assert:\n      - skill_activated: true\n',
        encoding="utf-8",
    )
    return root


@pytest.fixture
def fixture_source(tmp_path: Path) -> Path:
    source = tmp_path / "fixture"
    source.mkdir()
    (source / "README.md").write_text("# project\n", encoding="utf-8")
    return source


@pytest.fixture
def mounted(backend: DockerBackend, skill_dir: Path, fixture_source: Path, tmp_path: Path):  # type: ignore[no-untyped-def]
    usable, reason = overlay_available()
    if not usable:
        pytest.skip(f"no host-side overlay: {reason}")
    prepared = prepare_sandbox(
        load_skill(skill_dir),
        fixture_source,
        tmp_path / "run",
        rng=SeededRng(20260806, "network-run"),
    )
    backend.mount(prepared)
    try:
        yield prepared
    finally:
        backend.unmount(prepared)


@pytest.fixture
def internal_network(backend: DockerBackend):  # type: ignore[no-untyped-def]
    name = "bw-test-internal"
    backend.remove_network(name)  # clear any leak from a crashed prior run
    backend.create_network(name, internal=True)
    try:
        yield name
    finally:
        backend.remove_network(name)


def _has_default_route(proc_net_route: str) -> bool:
    """A default route is a line whose Destination column (field 1) is all-zero. Its
    presence means a gateway to everything off the local subnet; its absence is invariant 3.
    """
    for line in proc_net_route.splitlines()[1:]:  # skip the header row
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "00000000":
            return True
    return False


def _subnet_route_count(proc_net_route: str) -> int:
    """How many routes exist at all — a non-zero count on the internal bridge proves the
    container is attached to a real bridge with a subnet route, not merely networkless."""
    return len([line for line in proc_net_route.splitlines()[1:] if line.split()])


def test_create_network_reports_internal_true(backend: DockerBackend) -> None:
    """The isolation is a property of the network, so assert it at the source rather than
    trusting the flag was honoured."""
    import subprocess

    name = "bw-test-inspect"
    backend.remove_network(name)
    backend.create_network(name, internal=True)
    try:
        result = subprocess.run(
            [backend.binary, "network", "inspect", "--format", "{{.Internal}}", name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "true"
    finally:
        backend.remove_network(name)


def test_a_container_on_the_internal_bridge_has_no_route_out(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
    internal_network: str,
) -> None:
    """§3.3 invariant 3, the load-bearing assertion: attached to the bridge (a subnet route
    exists) but with no default route, so no socket can reach a public address — the kernel
    refuses it before any egress code runs, and the proxy is the only way out."""
    result = backend.run(mounted, ["sh", "-c", "cat /proc/net/route"], network=internal_network)
    assert result.exit_code == 0, result.stderr
    assert _subnet_route_count(result.stdout) >= 1, (
        f"container not attached to the bridge; routes:\n{result.stdout}"
    )
    assert not _has_default_route(result.stdout), (
        f"internal bridge handed out a default route — invariant 3 is broken:\n{result.stdout}"
    )


def test_the_internal_bridge_is_not_merely_a_networkless_container(
    backend: DockerBackend,
    mounted,  # type: ignore[no-untyped-def]
    internal_network: str,
) -> None:
    """The negative above must not pass for the trivial reason that the container had no
    network at all: contrast `--network none`, which yields *no* routes, against the
    internal bridge, which yields a subnet route and still no default route. The block is
    the bridge's missing gateway, not the absence of a bridge."""
    on_bridge = backend.run(mounted, ["sh", "-c", "cat /proc/net/route"], network=internal_network)
    networkless = backend.run(mounted, ["sh", "-c", "cat /proc/net/route"], network="none")

    assert _subnet_route_count(on_bridge.stdout) >= 1
    assert _subnet_route_count(networkless.stdout) == 0
    # Neither can reach out; the interesting difference is that the bridge container *is*
    # on a network (so a proxy peer would be reachable) and still has no route out.
    assert not _has_default_route(on_bridge.stdout)
    assert not _has_default_route(networkless.stdout)


def test_connect_network_dual_homes_a_container(backend: DockerBackend) -> None:
    """§3.3 dual-homing: a container starts on the internal bridge (no route out) and is then
    attached to an ordinary egress bridge, gaining a default route — how the proxy sidecar gets
    a way out the sandbox does not. Proven by the default route appearing only after the connect.
    """
    import subprocess

    internal = "bw-test-int-dual"
    egress = "bw-test-egr-dual"
    container = "bw-test-dual-homed"
    for name in (internal, egress):
        backend.remove_network(name)
    subprocess.run([backend.binary, "rm", "-f", container], capture_output=True, text=True)
    backend.create_network(internal, internal=True)
    backend.create_network(egress, internal=False)

    started = subprocess.run(
        [
            backend.binary,
            "run",
            "--rm",
            "-d",
            "--name",
            container,
            "--network",
            internal,
            backend.image,
            "sleep",
            "60",
        ],
        capture_output=True,
        text=True,
    )
    assert started.returncode == 0, started.stderr
    try:
        before = subprocess.run(
            [backend.binary, "exec", container, "cat", "/proc/net/route"],
            capture_output=True,
            text=True,
        )
        assert before.returncode == 0, before.stderr
        assert not _has_default_route(before.stdout), "internal bridge should hand out no gateway"

        backend.connect_network(egress, container)

        after = subprocess.run(
            [backend.binary, "exec", container, "cat", "/proc/net/route"],
            capture_output=True,
            text=True,
        )
        assert after.returncode == 0, after.stderr
        assert _has_default_route(after.stdout), (
            f"the egress bridge should have added a default route:\n{after.stdout}"
        )
    finally:
        subprocess.run([backend.binary, "rm", "-f", container], capture_output=True, text=True)
        backend.remove_network(egress)
        backend.remove_network(internal)


def test_connect_network_names_the_reason_it_could_not(backend: DockerBackend) -> None:
    """Attaching a container that does not exist is a loud failure with the reason, not a silent
    pass — the dual-home is load-bearing for §3.3 and must never fail quietly."""
    from bellwether.errors import BellwetherError

    backend.remove_network("bw-test-egr-missing")
    backend.create_network("bw-test-egr-missing", internal=False)
    try:
        with pytest.raises(BellwetherError, match="could not connect"):
            backend.connect_network("bw-test-egr-missing", "bw-container-does-not-exist")
    finally:
        backend.remove_network("bw-test-egr-missing")


def test_remove_network_is_idempotent(backend: DockerBackend) -> None:
    """Teardown of a network that is already gone is the same clean end state as removing a
    live one — a crashed run must not leave a name that blocks the next."""
    backend.remove_network("bw-test-does-not-exist")  # must not raise
