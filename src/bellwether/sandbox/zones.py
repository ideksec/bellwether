"""The three filesystem zones (§10.2).

Without this separation, harness session state and logs appear as filesystem changes on
every run: ``workspace_unchanged`` never passes for any skill, and capability sets differ
run-to-run for reasons that have nothing to do with the skill — inflating the capability
term that carries the heaviest weight in the BCI.

============= ======================= ==================== ==============================
Zone          Example                 In workspace diff?   In capability set?
============= ======================= ==================== ==============================
workspace     ``/work/<random>``      yes                  yes
harness_state ``/home/agent/.claude`` no, recorded apart   only if written by a tool call
scratch       ``/tmp``                no, recorded apart   yes, coarsened to tier 2
============= ======================= ==================== ==============================

A skill writing to the harness state directory is a genuinely interesting finding — it is
recorded and surfaced as ``harness_state_write`` — it just must not pollute the workspace
diff. Zone membership is recorded on **every** filesystem action record, because the
assertion engine and the capability builder consume it differently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal

__all__ = ["ZONE_RULES", "Zone", "ZoneMap", "ZoneRules", "ZonedPath", "normalize_container_path"]

#: ``outside`` is not a configured zone; it is everything the container can reach that is
#: none of the three — ``/etc``, ``/home/agent`` outside harness state, a mounted cache.
#: Reaching it is what ``outside_workspace_read`` and ``outside_workspace_write`` describe.
Zone = Literal["workspace", "harness_state", "scratch", "outside"]


@dataclass(frozen=True)
class ZoneRules:
    """How one zone is treated by the diff, the capability set, and the report."""

    in_workspace_diff: bool
    in_capability_set: bool
    #: Scratch paths are recorded at tier 2 rather than tier 3: a temp file's exact name
    #: is noise, but *which directory* a skill scribbles in is not.
    coarsen_to_tier2: bool
    #: Emitted as its own finding kind when written to, regardless of declared scope.
    write_finding_kind: str | None = None


ZONE_RULES: dict[Zone, ZoneRules] = {
    "workspace": ZoneRules(in_workspace_diff=True, in_capability_set=True, coarsen_to_tier2=False),
    "harness_state": ZoneRules(
        in_workspace_diff=False,
        in_capability_set=True,
        coarsen_to_tier2=False,
        write_finding_kind="harness_state_write",
    ),
    "scratch": ZoneRules(in_workspace_diff=False, in_capability_set=True, coarsen_to_tier2=True),
    "outside": ZoneRules(in_workspace_diff=False, in_capability_set=True, coarsen_to_tier2=False),
}


def normalize_container_path(path: str | PurePosixPath) -> PurePosixPath:
    """Resolve ``.`` and ``..`` lexically, without touching the filesystem.

    Lexical rather than ``Path.resolve()`` on purpose: these are paths *inside a
    container*, which do not exist on the host, and resolving them against the host would
    both fail and — where a name happened to match — resolve against the wrong tree.

    Traversal is collapsed before classification, so ``/work/x/../../etc/passwd`` is
    classified as ``outside`` rather than as a workspace path. A classifier that compared
    prefixes on the raw string would let a traversal read as an in-scope access, which is
    the same near-miss the platform baseline has to defend against (§12.6).
    """
    candidate = PurePosixPath(path)
    parts: list[str] = []
    for part in candidate.parts:
        if part == ".":
            continue
        if part == "..":
            # `..` above the root stays at the root, matching kernel behaviour.
            if parts and parts[-1] not in ("/", ""):
                parts.pop()
            continue
        parts.append(part)
    return PurePosixPath(*parts) if parts else PurePosixPath("/")


@dataclass(frozen=True)
class ZonedPath:
    """A container path, with the zone it belongs to and its path within that zone."""

    absolute: PurePosixPath
    zone: Zone
    #: Path relative to the zone root, or to ``/`` for ``outside``.
    relative: PurePosixPath
    #: True where the raw path used ``..`` to reach where it ended up. Not an error on its
    #: own, but §12.6 flags a traversal that lands near a baseline entry as a near-miss.
    used_traversal: bool = False

    @property
    def rules(self) -> ZoneRules:
        return ZONE_RULES[self.zone]


@dataclass(frozen=True)
class ZoneMap:
    """Where each zone is mounted inside the container (§21 ``capture.zones``)."""

    workspace: PurePosixPath = field(default_factory=lambda: PurePosixPath("/work"))
    harness_state: PurePosixPath = field(
        default_factory=lambda: PurePosixPath("/home/agent/.claude")
    )
    scratch: PurePosixPath = field(default_factory=lambda: PurePosixPath("/tmp"))

    @classmethod
    def from_config(cls, workspace: str, harness_state: str, scratch: str) -> ZoneMap:
        return cls(
            workspace=normalize_container_path(workspace),
            harness_state=normalize_container_path(harness_state),
            scratch=normalize_container_path(scratch),
        )

    def roots(self) -> list[tuple[Zone, PurePosixPath]]:
        """Zone roots, **longest first**.

        Longest-prefix wins so that a harness state directory configured underneath the
        workspace — which is how some harnesses lay themselves out — is classified as
        harness state rather than swallowed by the workspace.
        """
        pairs: list[tuple[Zone, PurePosixPath]] = [
            ("workspace", self.workspace),
            ("harness_state", self.harness_state),
            ("scratch", self.scratch),
        ]
        return sorted(pairs, key=lambda pair: len(pair[1].parts), reverse=True)

    def classify(self, path: str | PurePosixPath) -> ZonedPath:
        """Assign a container path to its zone."""
        raw = PurePosixPath(path)
        absolute = normalize_container_path(raw)
        used_traversal = ".." in raw.parts

        for zone, root in self.roots():
            if absolute == root or absolute.is_relative_to(root):
                return ZonedPath(
                    absolute=absolute,
                    zone=zone,
                    relative=absolute.relative_to(root),
                    used_traversal=used_traversal,
                )

        return ZonedPath(
            absolute=absolute,
            zone="outside",
            relative=absolute,
            used_traversal=used_traversal,
        )
