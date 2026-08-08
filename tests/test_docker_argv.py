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

from bellwether.capture import plan_canary_planting
from bellwether.cli import execution as execution_mod
from bellwether.cli.execution import (
    SandboxRunExecutor,
    isolation_from_config,
    zone_map_from_config,
)
from bellwether.cli.orchestrator import RunPlan, TargetInfo
from bellwether.config.models.config import SandboxConfig, ZoneConfig
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.determinism import SeededRng
from bellwether.sandbox import (
    DockerBackend,
    IsolationProfile,
    ZoneMap,
    derive_identifiers,
    prepare_sandbox,
)
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


def test_dns_points_the_container_at_the_controlled_resolver(prepared) -> None:  # type: ignore[no-untyped-def]
    """--dns names the resolver by IP (§10.6): one nameserver, and single-request so glibc sends
    one query per lookup rather than splitting A/AAAA, so the resolver sees them all. The internal
    bridge (no route out) is what makes that the only resolver reachable (§3.3 invariant 3)."""
    backend = DockerBackend(image=_IMAGE)
    argv = backend.build_argv(prepared, ["true"], dns="172.30.0.7")
    joined = " ".join(argv)
    assert "--dns 172.30.0.7" in joined
    assert "--dns-option single-request" in joined


def test_no_dns_flag_when_the_resolver_is_unset(prepared) -> None:  # type: ignore[no-untyped-def]
    backend = DockerBackend(image=_IMAGE)
    assert "--dns" not in backend.build_argv(prepared, ["true"])


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


# ---------------------------------------------------------------------------
# BW-36: a fallback tmpfs is size-bounded (§9.2)
# ---------------------------------------------------------------------------


def test_fallback_tmpfs_mounts_are_size_bounded(prepared) -> None:  # type: ignore[no-untyped-def]
    """A declared writable path with no captured-zone overlay falls back to tmpfs, which draws
    from host memory. An uncapped one is a host-DoS — a skill filling ``/tmp`` exhausts it — so
    every fallback tmpfs must carry a ``size=`` bound, the same reason ``--memory`` is set."""
    backend = DockerBackend(image=_IMAGE)
    argv = backend.build_argv(prepared, ["true"])

    tmpfs_specs = [value for flag, value in pairwise(argv) if flag == "--tmpfs"]
    assert tmpfs_specs, "expected fallback tmpfs mounts for the declared writable paths"
    for spec in tmpfs_specs:
        assert "size=" in spec, f"an unbounded tmpfs is a host-DoS: {spec!r}"


# ---------------------------------------------------------------------------
# BW-18: the pinned machine-id is bound read-only at /etc/machine-id (§9.2 MUST)
# ---------------------------------------------------------------------------


def test_the_pinned_machine_id_is_bound_read_only(prepared) -> None:  # type: ignore[no-untyped-def]
    """§9.2 requires ``/etc/machine-id`` pinned so no tool derives a varying identifier from it.
    Under a ``--read-only`` root the container cannot write the file, so the pin is a read-only
    bind of a host file — and the recorded command line must show it, not just the live run."""
    backend = DockerBackend(image=_IMAGE)
    argv = backend.build_argv(prepared, ["true"])

    assert prepared.machine_id_file is not None
    # A Docker bind-mount source must be absolute or the daemon reads it as a named volume.
    assert prepared.machine_id_file.is_absolute()
    assert f"{prepared.machine_id_file}:/etc/machine-id:ro" in argv
    # The bound file holds the pinned value (§9.2), not a per-run-varying one.
    assert prepared.machine_id_file.read_text().strip() == prepared.isolation.pinned.machine_id


# ---------------------------------------------------------------------------
# BW-08 / BW-09 / BW-37: config reaches the sandbox, per-eval identifiers, scenario env
# ---------------------------------------------------------------------------


def _target() -> TargetInfo:
    return TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")


def _scenario(env: dict[str, str] | None = None) -> Scenario:
    return Scenario(
        id="s",
        expectation="should_trigger",
        prompt="p",
        env=env or {},
        assertions=[AssertionSpec(name="skill_activated", params=True)],
    )


def _executor(tmp_path: Path, **overrides):  # type: ignore[no-untyped-def]
    eval_id = overrides.get("eval_id", "eval-1")
    root = tmp_path / f"skill-{eval_id}"
    (root / "evals").mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(
        "---\nname: exec-skill\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    fixture = tmp_path / f"fixture-{eval_id}"
    fixture.mkdir(exist_ok=True)
    (fixture / "README.md").write_text("# p\n", encoding="utf-8")
    kwargs: dict[str, object] = {
        "backend": DockerBackend(image=_IMAGE),
        "package": load_skill(root, load_evals=False),
        "fixture": fixture,
        "client_factory": lambda _plan: (None, "model"),
        "eval_id": eval_id,
        "run_root": tmp_path / f"runs-{eval_id}",
    }
    kwargs.update(overrides)
    return SandboxRunExecutor(**kwargs)  # type: ignore[arg-type]


def test_sandbox_config_maps_onto_the_isolation_profile_flags() -> None:
    """BW-08: a non-default ``sandbox.*`` must actually reach the flags the container runs
    under, rather than being silently ignored in favour of the hardcoded baseline."""
    cfg = SandboxConfig(
        image=_IMAGE,
        memory="1g",
        cpus=3.0,
        pids_limit=99,
        timeout_seconds=123,
        writable_paths=["/work", "/scratch"],
    )
    iso = isolation_from_config(cfg)

    # timeout_seconds is enforced by the subprocess wait, not a docker flag, but must carry.
    assert iso.timeout_seconds == 123
    assert iso.writable_paths == ("/work", "/scratch")

    flags = " ".join(iso.docker_flags())
    assert "--memory 1g" in flags
    assert "--cpus 3.0" in flags
    assert "--pids-limit 99" in flags
    # The §9.2 hardening is not user-overridable through this mapping and stays at baseline.
    assert "--cap-drop ALL" in flags
    assert iso.violations() == []


def test_zone_config_maps_onto_the_zone_map() -> None:
    """BW-08: ``capture.zones`` reaches the zone map the sandbox actually mounts by (§10.2)."""
    zmap = zone_map_from_config(
        ZoneConfig(workspace="/work", harness_state="/home/agent/.claude", scratch="/scr")
    )
    assert zmap.workspace == PurePosixPath("/work")
    assert zmap.harness_state == PurePosixPath("/home/agent/.claude")
    assert zmap.scratch == PurePosixPath("/scr")


class _StopError(Exception):
    """Sentinel so execute() unwinds at prepare_sandbox, before any daemon is touched."""


def test_execute_forwards_config_derived_isolation_zones_and_eval_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BW-08 + BW-09: execute() must hand the configured profile and zone map to
    prepare_sandbox — not run the hardcoded ``IsolationProfile()`` — and its RNG stream must be
    namespaced by ``eval_id`` so identifiers differ per evaluation."""
    iso = IsolationProfile(memory="1g", timeout_seconds=123)
    zmap = ZoneMap.from_config(workspace="/w", harness_state="/w/.state", scratch="/scr")
    executor = _executor(
        tmp_path,
        eval_id="eval-XYZ",
        isolation=iso,
        zones=zmap,
        randomize_identifiers=False,
    )

    captured: dict[str, object] = {}

    def fake_prepare(package, fixture, root, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        raise _StopError

    monkeypatch.setattr(execution_mod, "prepare_sandbox", fake_prepare)

    plan = RunPlan(scenario=_scenario(), target=_target(), repetition=2)
    with pytest.raises(_StopError):
        executor.execute(plan)

    assert captured["isolation"] is iso
    assert captured["zones"] is zmap
    assert captured["randomize_identifiers"] is False
    # The RNG label carries eval_id first, so two evaluations draw different identifiers.
    assert captured["rng"].label.startswith("eval-XYZ/")  # type: ignore[union-attr]


def test_two_evaluations_get_different_container_names(tmp_path: Path) -> None:
    """BW-09: the same (scenario, target, repetition) in two evaluations must not produce the
    same container name — identical names collide on a concurrent matrix and are themselves a
    §3.5 tell — while staying reproducible for a fixed eval_id."""
    plan = RunPlan(scenario=_scenario(), target=_target(), repetition=1)

    a = derive_identifiers(
        _executor(tmp_path, eval_id="eval-A")._sandbox_rng(plan).derive("identifiers")
    )
    b = derive_identifiers(
        _executor(tmp_path, eval_id="eval-B")._sandbox_rng(plan).derive("identifiers")
    )
    assert a.container_name != b.container_name
    assert a.hostname != b.hostname

    # Reproducible: the same eval_id and coordinate redraw the identical identifiers.
    again = derive_identifiers(
        _executor(tmp_path, eval_id="eval-A")._sandbox_rng(plan).derive("identifiers")
    )
    assert again.container_name == a.container_name


def test_scenario_env_is_delivered_into_the_container(tmp_path: Path) -> None:
    """BW-37: a scenario's ``env`` (values may be canaries, §7.2) has to actually reach the
    container; execute() had no path for it. It flows through the ``extra_env`` seam, and the
    proxy's own env is merged last so a scenario cannot unset the observed channel."""
    executor = _executor(tmp_path)
    plan = RunPlan(
        scenario=_scenario(env={"CANARY_TOKEN": "bw-canary-abc123"}),
        target=_target(),
        repetition=1,
    )

    env = executor._extra_env(plan, None, None)
    assert env["CANARY_TOKEN"] == "bw-canary-abc123"

    # It reaches the real docker argv through the extra_env seam build_argv exposes.
    prepared = prepare_sandbox(
        executor.package, executor.fixture, tmp_path / "one-run", rng=SeededRng(1, "x")
    )
    argv = executor.backend.build_argv(prepared, ["true"], extra_env=env)
    assert _env_pairs(argv)["CANARY_TOKEN"] == "bw-canary-abc123"

    # The proxy's infrastructure env wins a collision, so a scenario cannot unset it.
    class _StubProxy:
        def sandbox_env(self) -> dict[str, str]:
            return {"HTTPS_PROXY": "http://proxy:8080", "CANARY_TOKEN": "proxy-wins"}

    merged = executor._extra_env(plan, _StubProxy(), None)  # type: ignore[arg-type]
    assert merged["HTTPS_PROXY"] == "http://proxy:8080"
    assert merged["CANARY_TOKEN"] == "proxy-wins"


# ---------------------------------------------------------------------------
# WP-16: canary planting into the sandbox and the marker-free identity record.
# The scan itself is trace.canary_actions (tested in test_canary.py); these pin
# the executor-side wiring — minting, delivery, seed stability, and provenance —
# without a daemon.
# ---------------------------------------------------------------------------


def test_canaries_are_off_unless_planting_is_enabled(tmp_path: Path) -> None:
    """The credentials plane is opt-in like egress and DNS: no planting, no minted canaries, and
    a scenario with no env of its own reaches the container with an untouched environment."""
    executor = _executor(tmp_path)
    assert executor._canaries() == []
    plan = RunPlan(scenario=_scenario(), target=_target(), repetition=1)
    assert executor._extra_env(plan, None, None) == {}


def test_the_env_canary_is_delivered_into_the_container(tmp_path: Path) -> None:
    """With planting on, the env-var canary reaches the container through the same extra_env seam a
    scenario's env uses (§10.4) — the marker a canary-thief would read and try to exfiltrate."""
    executor = _executor(tmp_path, plant_canaries=True)
    canaries = executor._canaries()
    planting = plan_canary_planting(canaries)
    plan = RunPlan(scenario=_scenario(), target=_target(), repetition=1)

    env = executor._extra_env(plan, None, planting)
    # The pool's one env-var slot is INTERNAL_API_TOKEN, carrying its canary's marker verbatim.
    token = next(c for c in canaries if c.kind == "envvar")
    assert env["INTERNAL_API_TOKEN"] == token.marker

    # It reaches the real docker argv through the extra_env seam build_argv exposes.
    prepared = prepare_sandbox(
        executor.package, executor.fixture, tmp_path / "one", rng=SeededRng(1, "x")
    )
    argv = executor.backend.build_argv(prepared, ["true"], extra_env=env)
    assert _env_pairs(argv)["INTERNAL_API_TOKEN"] == token.marker


def test_the_canary_seed_is_per_evaluation_stable_across_repetitions(tmp_path: Path) -> None:
    """§9.3: markers are minted once per *evaluation*, identical across its repetitions (so the run
    cache keyed on ``fixture_digest`` still hits), and different between evaluations."""
    a1 = _executor(tmp_path, eval_id="eval-A", plant_canaries=True)._canaries()
    a2 = _executor(tmp_path, eval_id="eval-A", plant_canaries=True)._canaries()
    b = _executor(tmp_path, eval_id="eval-B", plant_canaries=True)._canaries()
    assert [c.marker for c in a1] == [c.marker for c in a2]  # stable within one evaluation
    assert [c.marker for c in a1] != [c.marker for c in b]  # differs between evaluations


def test_a_canary_env_wins_over_a_scenario_but_loses_to_the_proxy(tmp_path: Path) -> None:
    """Merge order is scenario → canary → proxy (§10.4, §21): the canary plant is a core control, so
    it overrides a scenario that shadows the name, and the proxy's channel overrides everything."""
    executor = _executor(tmp_path, plant_canaries=True)
    canaries = executor._canaries()
    planting = plan_canary_planting(canaries)
    token = next(c for c in canaries if c.kind == "envvar")
    plan = RunPlan(
        scenario=_scenario(env={"INTERNAL_API_TOKEN": "scenario-shadow"}),
        target=_target(),
        repetition=1,
    )

    # A scenario cannot shadow the plant: the canary marker wins over the scenario's value.
    assert executor._extra_env(plan, None, planting)["INTERNAL_API_TOKEN"] == token.marker

    # But the proxy's infrastructure env still wins the final merge.
    class _StubProxy:
        def sandbox_env(self) -> dict[str, str]:
            return {"INTERNAL_API_TOKEN": "proxy-wins"}

    merged = executor._extra_env(plan, _StubProxy(), planting)  # type: ignore[arg-type]
    assert merged["INTERNAL_API_TOKEN"] == "proxy-wins"


def test_identity_records_planted_canaries_by_reference_never_the_value(tmp_path: Path) -> None:
    """§10.4.3 / §9.3: the header records the seed and the whole planted pool as marker-free
    references — id, path, kind — so the run is reproducible without the block ever holding a value.
    The executor passes all delivered canaries (env var + file slots), so all five are recorded."""
    executor = _executor(tmp_path, plant_canaries=True)
    canaries = executor._canaries()
    planting = plan_canary_planting(canaries)

    identity = executor._identity_block(planting, canaries)
    assert identity.canary_seed == str(executor._canary_seed())
    assert identity.env_credential_names == ["INTERNAL_API_TOKEN"]  # env-var canary names only
    assert {(pc.id, pc.kind) for pc in identity.canaries_planted} == {
        (c.id, c.kind) for c in canaries
    }
    # Not one marker value — of any minted canary — appears anywhere in the block.
    blob = identity.model_dump_json()
    assert all(c.marker not in blob for c in canaries)


def test_identity_is_empty_when_nothing_is_planted(tmp_path: Path) -> None:
    identity = _executor(tmp_path)._identity_block(None, [])
    assert identity.canaries_planted == []
    assert identity.canary_seed is None


def test_resolve_canary_path_maps_home_relative_and_absolute() -> None:
    """The pool's realistic slots resolve to where a real credential lives (§10.4): ``~`` to the
    container HOME, a bare relative path to the workspace CWD, an absolute path verbatim."""
    resolve = execution_mod._resolve_canary_path
    home, ws = "/home/agent", "/work/ws-abc"
    assert str(resolve("~/.aws/credentials", home=home, workspace_root=ws)) == (
        "/home/agent/.aws/credentials"
    )
    assert str(resolve(".env", home=home, workspace_root=ws)) == "/work/ws-abc/.env"
    assert str(resolve("/etc/secret", home=home, workspace_root=ws)) == "/etc/secret"


def test_stage_canary_files_writes_content_and_binds_at_resolved_paths(tmp_path: Path) -> None:
    """The file canaries are written to host files and returned as read-only binds at their resolved
    container paths — the delivery path a thief reads them through, and the marker never on the argv."""
    executor = _executor(tmp_path, plant_canaries=True)
    canaries = executor._canaries()
    planting = plan_canary_planting(canaries)
    prepared = prepare_sandbox(
        executor.package, executor.fixture, tmp_path / "prep", rng=SeededRng(1, "x")
    )

    binds = executor._stage_canary_files(planting, prepared, tmp_path / "run")

    # One bind per file canary (the four non-env slots), each an absolute host file → container path.
    assert len(binds) == len(planting.files)
    by_target = {str(container): host for host, container in binds}
    home = prepared.environment()["HOME"]
    aws_target = f"{home}/.aws/credentials"
    assert aws_target in by_target
    assert by_target[aws_target].is_absolute()
    # The host file carries the marker (bare content this brick); the trace never will.
    aws_marker = next(c.marker for c in canaries if c.kind == "aws")
    assert by_target[aws_target].read_text(encoding="utf-8") == aws_marker


def test_stage_canary_files_is_empty_when_nothing_is_planted(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    prepared = prepare_sandbox(
        executor.package, executor.fixture, tmp_path / "prep", rng=SeededRng(1, "x")
    )
    assert executor._stage_canary_files(None, prepared, tmp_path / "run") == []
