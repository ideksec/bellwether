"""One run's sandbox: what was prepared, and where it is (§9.1).

This is the host-side half of the lifecycle — steps 1 to 5 of §9.1, everything that
happens before a container starts. It is separated from the backend deliberately: the
preparation is where the determinism guarantees live and it is fully testable without a
daemon, while the backend is where the daemon lives and almost nothing else.

The remaining steps — mount the overlay, start the capture planes and sidecars, run the
harness, read the upper directory, tear down — belong to a :class:`SandboxBackend`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable

from bellwether.determinism import SeededRng
from bellwether.sandbox.fixtures import MaterializedFixture, materialize_fixture
from bellwether.sandbox.identifiers import SandboxIdentifiers, derive_identifiers
from bellwether.sandbox.isolation import IsolationProfile
from bellwether.sandbox.staging import StagedPayload, stage_payload
from bellwether.sandbox.zones import ZoneMap
from bellwether.skill import SkillPackage

__all__ = ["PreparedSandbox", "SandboxBackend", "prepare_sandbox"]


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

    workspace = materialize_fixture(
        fixture,
        root / "workspace",
        exclude_from_digest=canary_paths,
    )
    payload = stage_payload(package, root / "payload")

    upper = root / "overlay" / "upper"
    work = root / "overlay" / "work"
    upper.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)

    return PreparedSandbox(
        identifiers=identifiers,
        zones=zone_map,
        isolation=isolation or IsolationProfile(),
        workspace=workspace,
        payload=payload,
        upper_dir=upper,
        work_dir=work,
    )


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
