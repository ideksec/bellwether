"""Sandbox lifecycle: containers, mounts, fixtures, payload staging, teardown (§9).

Responsibility
    The eleven steps of §9.1: materialise a fixture with normalized mtimes, modes and
    ownership; plant canaries; install the skill payload by **allowlist** so ``evals/``
    never enters the container; mount the overlay with a host-side upper directory;
    start the capture planes and the proxy and resolver sidecars; run; read the overlay
    diff by zone; tear down.

MUST NOT
    Know about models. Anything model-shaped belongs to :mod:`bellwether.harness`.

WP-4 built the host-side half — zones, fixture materialisation, payload staging,
identifiers, and the isolation profile as data — all of which is testable without a
container daemon. The backend that starts containers, mounts the overlay and reads the
upper directory is the remaining half.

The isolation profile of §9.2 (``--cap-drop=ALL``, ``--read-only``, ``--pids-limit 512``,
``no-new-privileges``, 900s default timeout) is achievable only because no capture code
runs inside the container (§10.0). Keep it that way.
"""

from __future__ import annotations

from bellwether.sandbox.fixtures import (
    DIRECTORY_MODE,
    EXECUTABLE_MODE,
    FILE_MODE,
    NORMALIZED_MTIME,
    MaterializedFixture,
    fixture_digest,
    materialize_fixture,
    normalize_metadata,
)
from bellwether.sandbox.identifiers import SandboxIdentifiers, derive_identifiers
from bellwether.sandbox.isolation import IsolationProfile, PinnedEnvironment
from bellwether.sandbox.session import PreparedSandbox, SandboxBackend, prepare_sandbox
from bellwether.sandbox.staging import StagedPayload, stage_payload
from bellwether.sandbox.zones import (
    ZONE_RULES,
    Zone,
    ZonedPath,
    ZoneMap,
    ZoneRules,
    normalize_container_path,
)

__all__ = [
    "DIRECTORY_MODE",
    "EXECUTABLE_MODE",
    "FILE_MODE",
    "NORMALIZED_MTIME",
    "ZONE_RULES",
    "IsolationProfile",
    "MaterializedFixture",
    "PinnedEnvironment",
    "PreparedSandbox",
    "SandboxBackend",
    "SandboxIdentifiers",
    "StagedPayload",
    "Zone",
    "ZoneMap",
    "ZoneRules",
    "ZonedPath",
    "derive_identifiers",
    "fixture_digest",
    "materialize_fixture",
    "normalize_container_path",
    "normalize_metadata",
    "prepare_sandbox",
    "stage_payload",
]
