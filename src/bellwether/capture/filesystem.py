"""Plane B — filesystem capture, partitioned by zone (§10.2).

The mechanism is the host-side overlay diff: :func:`bellwether.sandbox.read_overlay_diff`
turns each zone's upper directory into a set of :class:`PathChange` items. This module's
job is the partitioning — attaching zone membership, the container-absolute path, and the
canary-path flag to every observed change, in a deterministic order — and stating the
plane's fidelity per §10.7.

What this module deliberately does not do:

- **Interpret.** Whether a change exceeded declared scope belongs to
  :mod:`bellwether.assertions`; the capability tiers belong to the normalizer (§11.2).
  A capture plane records what happened, not what it means.
- **Order.** Overlay-diff capture observes *sets*, not sequences — an upper directory has
  no per-event timestamps. Order is a quality question and sets are a security question
  (§10.1); at this fidelity Plane B contributes nothing to the trajectory spine, which is
  why ``CanonBlock.traj_planes`` excludes it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from bellwether.sandbox import PathChange, Zone, ZoneMap

__all__ = [
    "FilesystemEvent",
    "PlaneStatus",
    "collect_filesystem_events",
    "filesystem_writes_status",
]

#: Zone order for deterministic output: workspace first because it is what most readers
#: are looking for, then the others alphabetically.
_ZONE_ORDER: tuple[Zone, ...] = ("workspace", "harness_state", "outside", "scratch")


@dataclass(frozen=True)
class PlaneStatus:
    """One plane's fidelity and — where degraded — why, in capture-layer terms.

    The trace layer turns this into a :class:`~bellwether.trace.PlaneCoverage`; capture
    cannot, because the module layering runs ``capture -> trace`` and a capture module
    importing trace models would invert it.
    """

    fidelity: Literal["full", "partial", "overlay_diff", "unavailable", "none_offered"]
    reason: str | None = None


@dataclass(frozen=True)
class FilesystemEvent:
    """One observed filesystem change, with its zone membership (§10.2).

    Everything §10.2 requires a filesystem record to carry, except the capability tiers
    (normalizer, §11.2) and the declared-scope evaluation (assertions): the absolute
    container path, the zone, the path relative to the zone root, and whether the path is
    a canary plant site.
    """

    #: Absolute path inside the container, e.g. ``/tmp/probe`` or ``/work/a1b2c3/x.py``.
    absolute: str
    zone: Zone
    #: Relative to the zone root — what the workspace diff and assertions match against.
    relative: str
    change: PathChange
    #: True where the path is one the evaluation planted a canary at. Plane C correlates
    #: the marker itself; the path flag is recorded here because the capture layer is the
    #: only place that still knows both the plant sites and the observed set.
    canary_path: bool = False

    @property
    def kind(self) -> str:
        """The ARF action kind this event becomes (§11.3)."""
        return "file_delete" if self.change.kind == "deleted" else "file_write"


def collect_filesystem_events(
    zone_changes: dict[Zone, list[PathChange]],
    zone_map: ZoneMap,
    *,
    workspace_root: PurePosixPath | None = None,
    canary_paths: frozenset[str] = frozenset(),
) -> list[FilesystemEvent]:
    """Partition per-zone overlay diffs into zone-annotated filesystem events.

    Args:
        zone_changes: Changed paths per zone, as read from each zone's upper directory.
            A zone *absent* from this mapping was unobserved — that is a coverage fact,
            not an event, and it must reach the coverage block rather than vanish here.
        zone_map: Where each zone is mounted inside the container.
        workspace_root: The *run's* workspace root — ``/work/<slug>``, from the sandbox
            identifiers — not the zone base. The zone map knows only ``/work``; a record
            whose absolute path dropped the per-run segment would name a path that never
            existed in the container.
        canary_paths: Workspace-relative plant sites, as passed to ``prepare_sandbox``.

    Returns:
        Events sorted by ``(zone order, relative path)``, so the same observed set
        produces the same list on every machine (§24).
    """
    zone_roots: dict[Zone, PurePosixPath] = {
        "workspace": workspace_root or zone_map.workspace,
        "harness_state": zone_map.harness_state,
        "scratch": zone_map.scratch,
        "outside": PurePosixPath("/"),
    }

    events: list[FilesystemEvent] = []
    for zone in _ZONE_ORDER:
        changes = zone_changes.get(zone)
        if not changes:
            continue
        root = zone_roots[zone]
        for change in sorted(changes, key=lambda c: c.path):
            events.append(
                FilesystemEvent(
                    absolute=(root / change.path).as_posix(),
                    zone=zone,
                    relative=change.path,
                    change=change,
                    canary_path=zone == "workspace" and change.path in canary_paths,
                )
            )
    return events


def filesystem_writes_status(observed_zones: set[Zone]) -> PlaneStatus:
    """The write-capture fidelity of Plane B on this run (§10.7).

    Overlay-diff capture is the v0.1 mechanism, so ``overlay_diff`` is the ceiling — it
    records persisted writes but not reads or transients, and it contributes no ordering.
    A zone that was never mounted degrades the plane to ``partial`` with the zone named,
    because a write there vanished with the container and an assertion like
    ``no_harness_state_write`` cannot honestly pass on this run.
    """
    expected: tuple[Zone, ...] = ("workspace", "harness_state", "scratch")
    missing = [zone for zone in expected if zone not in observed_zones]
    if not missing:
        return PlaneStatus(fidelity="overlay_diff")
    if "workspace" in observed_zones:
        return PlaneStatus(
            fidelity="partial",
            reason=(
                "zone(s) not captured: " + ", ".join(missing) + "; writes there died with "
                "the container. Mount the zone overlay(s) to observe them."
            ),
        )
    return PlaneStatus(
        fidelity="unavailable",
        reason="no zone overlay was mounted; no filesystem writes were observable",
    )
