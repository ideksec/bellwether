"""The new argv seams the recording-proxy wiring needs, rendered offline (§10.5, §9.2).

``build_argv`` is the single place the docker command line is assembled, so what is recorded, shown
to a human, and actually run cannot drift apart. These pin the two additions the dual-homed proxy
depends on — extra environment merged over the sandbox's own, and read-only file binds for the CA —
without a daemon, the same way the sidecar's argv is tested.
"""

from __future__ import annotations

from itertools import pairwise
from pathlib import Path, PurePosixPath

import pytest

from bellwether.determinism import SeededRng
from bellwether.sandbox import DockerBackend, prepare_sandbox
from bellwether.skill import load_skill

_IMAGE = "sandbox@sha256:" + "a" * 64


@pytest.fixture
def prepared(tmp_path: Path):  # type: ignore[no-untyped-def]
    root = tmp_path / "probe-skill"
    (root / "evals").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: probe-skill\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "README.md").write_text("# project\n", encoding="utf-8")
    return prepare_sandbox(
        load_skill(root, load_evals=False),
        fixture,
        tmp_path / "run",
        rng=SeededRng(1, "argv"),
    )


def _env_pairs(argv: list[str]) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for flag, value in pairwise(argv):
        if flag == "-e" and "=" in value:
            key, val = value.split("=", 1)
            pairs[key] = val
    return pairs


def test_extra_env_is_merged_over_the_sandbox_environment(prepared) -> None:  # type: ignore[no-untyped-def]
    """`extra_env` is how the proxy is wired in — HTTPS_PROXY and the CA-trust vars — and it wins
    a key collision, because it is the caller's deliberate override of a pinned default."""
    backend = DockerBackend(image=_IMAGE)
    argv = backend.build_argv(
        prepared,
        ["true"],
        extra_env={"HTTPS_PROXY": "http://proxy:8080", "TZ": "override"},
    )
    env = _env_pairs(argv)
    assert env["HTTPS_PROXY"] == "http://proxy:8080"
    # The sandbox's own pinned env is still there...
    assert env["HOSTNAME"] == prepared.identifiers.hostname
    # ...but a key present in both takes the extra_env value, last-wins.
    assert env["TZ"] == "override"


def test_extra_env_absent_leaves_the_environment_untouched(prepared) -> None:  # type: ignore[no-untyped-def]
    backend = DockerBackend(image=_IMAGE)
    plain = backend.build_argv(prepared, ["true"])
    assert _env_pairs(plain)["TZ"] == "UTC"


def test_extra_ro_binds_render_read_only_after_the_payload(prepared) -> None:  # type: ignore[no-untyped-def]
    """The CA is mounted read-only; and it must render *after* the payload so a CA under a
    writable parent stays read-only, the same ordering the payload mount relies on."""
    backend = DockerBackend(image=_IMAGE)
    ca_host = Path("/host/ca.pem")
    ca_container = PurePosixPath("/usr/local/share/ca-certificates/bellwether-proxy.crt")
    argv = backend.build_argv(prepared, ["true"], extra_ro_binds=[(ca_host, ca_container)])
    bind = f"{ca_host}:{ca_container}:ro"
    assert bind in argv

    joined = " ".join(argv)
    assert joined.index(str(prepared.payload.root)) < joined.index(str(ca_host)), (
        "the CA bind must come after the payload mount so it sits on top"
    )
    # Read-only: the container never writes the CA.
    assert f"{ca_host}:{ca_container}:rw" not in joined
