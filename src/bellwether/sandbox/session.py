"""One run's sandbox: what was prepared, and where it is (§9.1).

This is the host-side half of the lifecycle — steps 1 to 5 of §9.1, everything that
happens before a container starts. It is separated from the backend deliberately: the
preparation is where the determinism guarantees live and it is fully testable without a
daemon, while the backend is where the daemon lives and almost nothing else.

The remaining steps — mount the overlay, start the capture planes and sidecars, run the
harness, read the upper directory, tear down — belong to a :class:`SandboxBackend`.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable

from bellwether.determinism import SeededRng
from bellwether.sandbox.fixtures import MaterializedFixture, materialize_fixture
from bellwether.sandbox.identifiers import SandboxIdentifiers, derive_identifiers
from bellwether.sandbox.isolation import IsolationProfile
from bellwether.sandbox.staging import StagedPayload, stage_payload
from bellwether.sandbox.zones import Zone, ZoneMap
from bellwether.skill import SkillPackage

__all__ = ["PreparedSandbox", "SandboxBackend", "ZoneOverlay", "prepare_sandbox"]


@dataclass(frozen=True)
class ZoneOverlay:
    """Host-side overlay directories for one captured zone other than the workspace.

    §10.2 records harness state and scratch *separately* from the workspace diff — which
    requires actually capturing them. A tmpfs cannot be read after the container exits,
    so a zone mounted as tmpfs is a zone whose writes are unobservable: every harness
    state write and every scratch write would vanish with the container, and the
    ``harness_state_write`` finding and the tier-2 scratch capabilities of §10.2 could
    never be produced. Each captured zone therefore gets the same treatment as the
    workspace: an overlayfs whose upper directory lives on the host.

    The lower directory is empty — these zones start blank — so every observed change
    reads as ``created``.
    """

    zone: Zone
    container_path: PurePosixPath
    lower: Path
    upper: Path
    work: Path
    merged: Path


@dataclass(frozen=True)
class PreparedSandbox:
    """Everything a backend needs to start a container, and nothing that needs one."""

    identifiers: SandboxIdentifiers
    zones: ZoneMap
    isolation: IsolationProfile
    workspace: MaterializedFixture
    payload: StagedPayload
    #: Host-side overlay upper directory, outside the container's reach. Reading the diff
    #: from here is O(changes) rather than O(tree), which is what keeps a large matrix's
    #: wall clock reasonable (§9.1 step 9).
    upper_dir: Path
    work_dir: Path
    #: Overlay directories for the harness state and scratch zones (§10.2). Empty where a
    #: caller opted out; a zone without one falls back to tmpfs and its writes are
    #: unobservable, which the coverage block must then say.
    captured_zones: tuple[ZoneOverlay, ...] = ()
    #: Host file holding the pinned ``/etc/machine-id`` value (§9.2), bound read-only into
    #: the container by the backend. Absolute so it is a valid Docker bind-mount source and
    #: never read as a named volume. ``None`` only where a caller assembled a sandbox by
    #: hand; :func:`prepare_sandbox` always sets it.
    machine_id_file: Path | None = None

    def mounts(self) -> list[tuple[Path, PurePosixPath, str]]:
        """``(host path, container path, mode)`` for each mount.

        The payload is mounted read-only: a skill that can rewrite its own installed body
        mid-run makes the trace describe something other than the reviewed artifact.
        """
        return [
            (self.workspace.root, self.identifiers.workspace_root, "rw"),
            (self.payload.root, self.payload.install_path, "ro"),
        ]

    def environment(self) -> dict[str, str]:
        """Environment pinned inside the container (§9.2)."""
        return {
            "TZ": self.isolation.pinned.timezone,
            "LANG": self.isolation.pinned.locale,
            "LC_ALL": self.isolation.pinned.locale,
            "HOSTNAME": self.identifiers.hostname,
            "HOME": "/home/agent",
        }


def prepare_sandbox(
    package: SkillPackage,
    fixture: Path,
    root: Path,
    *,
    rng: SeededRng,
    zones: ZoneMap | None = None,
    isolation: IsolationProfile | None = None,
    randomize_identifiers: bool = True,
    canary_paths: frozenset[str] | None = None,
) -> PreparedSandbox:
    """Carry out §9.1 steps 1–5, host-side.

    Args:
        package: The skill under test, already parsed.
        fixture: The fixture directory to materialise as the workspace.
        root: A per-run directory on the host to build everything under.
        rng: A per-run stream, derived from the evaluation seed.
        canary_paths: Workspace-relative paths where canaries will be planted, excluded
            from ``fixture_digest`` so per-evaluation randomisation does not miss the
            cache on every evaluation (§9.3).
    """
    zone_map = zones or ZoneMap()
    identifiers = derive_identifiers(
        rng.derive("identifiers"),
        workspace_base=zone_map.workspace,
        randomize=randomize_identifiers,
    )

    profile = isolation or IsolationProfile()

    workspace = materialize_fixture(
        fixture,
        root / "workspace",
        exclude_from_digest=canary_paths,
        owner=profile.owner,
    )
    payload = stage_payload(package, root / "payload", owner=profile.owner)

    # The overlay upper and work directories are written *through* by the container's
    # own uid, so they need the same ownership as the workspace. A root-owned upper dir
    # makes every write fail with EACCES, which reads as a skill that did nothing.
    upper = root / "overlay" / "upper"
    work = root / "overlay" / "work"
    for directory in (upper, work):
        directory.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(PermissionError):
            os.chown(directory, *profile.owner)

    machine_id_file = _write_machine_id(root, profile)

    return PreparedSandbox(
        identifiers=identifiers,
        zones=zone_map,
        isolation=profile,
        workspace=workspace,
        payload=payload,
        upper_dir=upper,
        work_dir=work,
        captured_zones=_prepare_zone_overlays(root, zone_map, profile),
        machine_id_file=machine_id_file,
    )


def _write_machine_id(root: Path, profile: IsolationProfile) -> Path:
    """Write the pinned ``/etc/machine-id`` value to a run-scoped host file (§9.2).

    Pinned rather than randomised: a varying machine-id leaks into logs from anything using
    systemd's ID as a seed, turning an environment difference into what reads as skill
    nondeterminism (§3.5). The backend binds this file read-only over ``/etc/machine-id``,
    which is the only way to pin it under a ``--read-only`` root the container cannot write.

    The path is resolved to an absolute one because it becomes a Docker bind-mount source,
    and a relative source is read by the daemon as a (missing) named volume, not a file.
    Mode ``0444`` matches a real ``/etc/machine-id`` and is world-readable, so the non-root
    container user can read it without any ownership dance.
    """
    path = (root / "machine-id").resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    # systemd expects 32 lowercase hex characters followed by a single newline.
    path.write_text(f"{profile.pinned.machine_id}\n", encoding="utf-8")
    path.chmod(0o444)
    return path


def _prepare_zone_overlays(
    root: Path, zone_map: ZoneMap, profile: IsolationProfile
) -> tuple[ZoneOverlay, ...]:
    """Create the host-side overlay directories for the harness state and scratch zones.

    Each zone's directory modes match what the container expects to find at that path:
    scratch is ``1777`` because it is mounted at ``/tmp`` and anything inside assumes
    world-writable-with-sticky semantics; harness state is ``0755`` owned by the agent
    uid, because it is the agent's own state directory. The merged root shows the *upper*
    directory's attributes, so both the lower and upper get the treatment.
    """
    overlays: list[ZoneOverlay] = []
    specs: tuple[tuple[Zone, PurePosixPath, int, bool], ...] = (
        ("harness_state", zone_map.harness_state, 0o755, True),
        ("scratch", zone_map.scratch, 0o1777, False),
    )
    for zone, container_path, mode, chown in specs:
        base = root / "zones" / zone
        dirs = {name: base / name for name in ("lower", "upper", "work", "merged")}
        for name, directory in dirs.items():
            directory.mkdir(parents=True, exist_ok=True)
            if name in ("lower", "upper"):
                directory.chmod(mode)
                if chown:
                    with contextlib.suppress(PermissionError):
                        os.chown(directory, *profile.owner)
        overlays.append(
            ZoneOverlay(
                zone=zone,
                container_path=container_path,
                lower=dirs["lower"],
                upper=dirs["upper"],
                work=dirs["work"],
                merged=dirs["merged"],
            )
        )
    return tuple(overlays)


@runtime_checkable
class SandboxBackend(Protocol):
    """What a container backend must provide.

    Kept as a protocol from the start so that gVisor and Firecracker land as
    implementations rather than as branches inside the Docker path — the same treatment
    the recording proxy gets, and for the same reason: a backend swapped without touching
    capture code is a backend whose evidence stays comparable.
    """

    name: str

    def available(self) -> tuple[bool, str]:
        """``(usable, reason)``. The reason is shown by ``bellwether doctor``."""
        ...

    def start(self, prepared: PreparedSandbox) -> str:
        """Start a container and return its id."""
        ...

    def stop(self, container_id: str) -> None: ...

    def changed_paths(self, prepared: PreparedSandbox) -> list[str]:
        """Workspace-relative paths changed during the run, from the overlay upper dir."""
        ...
