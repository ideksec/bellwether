"""Canonicalization: the comparable form of a trace (§11.4, §4.1).

Nondeterminism math needs a canonical form, or every run looks unique because
timestamps and paths differ. ``canonicalize`` orders a run's events by epoch anchoring,
drops everything run-local, and produces the three derived structures the metrics layer
consumes:

- the **step sequence** — ordered ``(kind, tool, tier1)`` signatures: *how* the skill
  worked;
- the **capability sets** at three tiers — *what class of thing* it touched, down to
  *exactly what*;
- the **sensitive hits** — the tier-2 entries intersecting the sensitive-directory
  list, which fire findings on a single occurrence (§13.5.4).

Step signatures use tier 1, not the exact target, deliberately: a code-reviewing agent
legitimately reads different files each run — that is task variance, not capability
instability — and only tier 1 is stable enough for a threshold to be meaningful.

The rules here are versioned. ``canon_version`` covers the whole; ``traj_planes`` is
recorded separately so that a new capture plane coming online invalidates trajectory
comparisons only, not every capability baseline in the repository (§11.6).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import cast

from bellwether.constants import SENSITIVE_DIRECTORIES
from bellwether.sandbox import ZONE_RULES, Zone, ZoneMap
from bellwether.trace.epochs import anchor_events
from bellwether.trace.models import Action, CanonBlock, Capability

__all__ = [
    "CanonicalTrace",
    "NormalizationContext",
    "StepSignature",
    "canonicalize",
    "capability_for",
]

#: One step of the trajectory: ``(kind, tool name, tier-1 capability)``. Tool name and
#: tier are None where the event has neither (a model turn, a final output).
StepSignature = tuple[str, str | None, str | None]

#: §11.2 assigns each ARF plane a trajectory-plane letter; §11.6's ``canon.traj_planes``
#: lists which letters contribute *ordering*. A plane whose letter is absent from that
#: list is still observed for its **capabilities** but kept out of the step sequence.
#: The standing case is filesystem (B): at overlay-diff fidelity Plane B records a
#: post-run *set* with no genuine ordering (§10.2, build.py), so admitting its events to
#: the sequence injects spurious trajectory variance — two runs identical in Plane-A
#: behaviour but differing in how many output files they wrote would score as
#: sequence-unstable, corrupting the differentiating metric. ``proxy_inferred`` and
#: ``normalizer`` carry no letter at all (§11.2) and never contribute ordering.
_PLANE_TRAJ_LETTER: dict[str, str] = {
    "harness": "A",
    "filesystem": "B",
    "credentials": "C",
    "egress": "D",
    "dns": "E",
    "process": "D′",  # D-prime, U+2032 — matches the spec's spelling (§10.3, §11.2)
}


def _in_trajectory(action: Action, trajectory_planes: frozenset[str]) -> bool:
    """Whether this action contributes a step to the trajectory (§11.6)."""
    letter = _PLANE_TRAJ_LETTER.get(action.plane)
    return letter is not None and letter in trajectory_planes


@dataclass(frozen=True)
class NormalizationContext:
    """What canonicalization needs to know about the run to erase it.

    The workspace root is per-run (randomised, §3.5); home and tmp are the zone mounts.
    Everything here comes from the run header and the zone map, never from the host the
    analysis happens to run on.
    """

    workspace_root: str
    home: str = "/home/agent"
    tmp: str = "/tmp"

    def normalize_path(self, path: str) -> str:
        """Replace run-local roots with stable placeholders (§11.4)."""
        candidates = (
            (self.workspace_root, "${WORKSPACE}"),
            (self.tmp, "${TMP}"),
            (self.home, "${HOME}"),
        )
        for root, placeholder in candidates:
            if path == root:
                return placeholder
            if path.startswith(root.rstrip("/") + "/"):
                return placeholder + path[len(root.rstrip("/")) :]
        return path


@dataclass(frozen=True)
class CanonicalTrace:
    """The comparable form: no timestamps, no run-local names, no volume (§11.4)."""

    step_sequence: tuple[StepSignature, ...]
    caps_t1: tuple[str, ...]
    caps_t2: tuple[str, ...]
    caps_t3: tuple[str, ...]
    #: Tier-2 entries whose directory class is on the sensitive list. Any single
    #: appearance is a finding; frequency is irrelevant (§13.5.4).
    sensitive_hits: tuple[str, ...]
    canon: CanonBlock = field(default_factory=CanonBlock)


def canonicalize(
    actions: Iterable[Action],
    context: NormalizationContext,
    *,
    platform_baseline_t3: frozenset[str] = frozenset(),
    sensitive_directories: tuple[str, ...] = SENSITIVE_DIRECTORIES,
    canon: CanonBlock | None = None,
) -> CanonicalTrace:
    """Produce the canonical form of one run's events.

    Args:
        actions: The run's action records, any order; epoch anchoring orders them.
        context: The run-local names to erase.
        platform_baseline_t3: Normalized tier-3 entries the platform baseline absorbs,
            subtracted from the capability sets **before** they are produced (§11.4) —
            matched literally. The glob-aware matcher, near-miss flagging included, is
            WP-8's; whatever it matches ultimately funnels through this parameter.
            Baseline subtraction applies to capability sets only: the step sequence
            keeps every step, because *how* the skill worked includes its
            infrastructure moves even where *what it touched* is absorbed.
        sensitive_directories: The §13.5.4 list; configurable, defaulted centrally.
        canon: The versioning block to embed; defaults to current versions.

    The same set of events produces the same ``CanonicalTrace`` on every machine: the
    ordering is content-based (§11.5), the capability sets are sorted, and nothing
    run-local survives normalization.
    """
    effective_canon = canon or CanonBlock()
    trajectory_planes = frozenset(effective_canon.traj_planes)

    ordered = anchor_events(list(actions), normalized_target=lambda a: _target(a, context))

    steps: list[StepSignature] = []
    t1: set[str] = set()
    t2: set[str] = set()
    t3: set[str] = set()

    for action in ordered:
        capability = capability_for(action, context)
        if _in_trajectory(action, trajectory_planes):
            # The step sequence is *how* the skill worked, over the planes §11.6 admits.
            # A plane observed only for its capabilities (filesystem at overlay-diff) is
            # excluded here but still feeds the capability sets below.
            tool = action.action.get("tool")
            steps.append((action.kind, tool if isinstance(tool, str) else None, _t1(capability)))

        if capability is None:
            continue
        if capability.tier3 is not None and capability.tier3 in platform_baseline_t3:
            # Absorbed as infrastructure: out of the capability sets, still in the
            # sequence. §12.6: scope evaluation runs against observed − baseline.
            continue
        t1.add(capability.tier1)
        if capability.tier2 is not None:
            t2.add(capability.tier2)
        if capability.tier3 is not None:
            t3.add(capability.tier3)

    hits = tuple(
        sorted(
            entry
            for entry in t2
            if _directory_of(entry) is not None and _directory_of(entry) in sensitive_directories
        )
    )

    return CanonicalTrace(
        step_sequence=tuple(steps),
        caps_t1=tuple(sorted(t1)),
        caps_t2=tuple(sorted(t2)),
        caps_t3=tuple(sorted(t3)),
        sensitive_hits=hits,
        canon=effective_canon,
    )


def capability_for(action: Action, context: NormalizationContext) -> Capability | None:
    """Compute the §4.1 capability of one action, at all three tiers.

    This is the normalizer's half of the §10.2/§11.2 split: capture records what
    happened; the tiers are computed here, where declared-scope context lives.

    Returns None for events that map to no capability (model turns, skill offers,
    results, final output) — they appear in the step sequence but not in any set.
    """
    kind = action.kind
    payload = action.action

    if kind == "tool_call":
        tool = payload.get("tool")
        tool_input = payload.get("input") or {}
        if tool in ("read", "write") and isinstance(tool_input.get("path"), str):
            return _filesystem_capability(
                _tool_zone_path(tool_input["path"], context),
                write=tool == "write",
                deleted=False,
                context=context,
            )
        if isinstance(tool, str):
            target = _tool_target(tool_input)
            return Capability(tier1=f"tool:{tool}", tier2=f"tool:{tool}", tier3=target)
        return None

    if kind in ("file_write", "file_delete"):
        zone = payload.get("zone")
        path = payload.get("path")
        if not isinstance(path, str) or not isinstance(zone, str):
            return None
        if zone == "harness_state" and action.correlation.anchor_seq is None:
            # §10.2: harness state enters the capability set only where written by a
            # tool call. An uncorrelated write there is the harness's own state
            # churn — recorded, surfaced as its own finding kind, never a capability.
            return None
        relative = payload.get("zone_relative")
        return _filesystem_capability(
            (zone, path, relative if isinstance(relative, str) else None),
            write=True,
            deleted=kind == "file_delete",
            context=context,
        )

    if kind == "canary_read":
        target = payload.get("path")
        normalized = context.normalize_path(target) if isinstance(target, str) else None
        return Capability(tier1="canary_read", tier2="canary_read", tier3=normalized)

    if kind == "egress_request":
        host = payload.get("host")
        url = payload.get("url")
        if isinstance(host, str):
            return Capability(
                tier1=f"egress:{host}",
                tier2=f"egress:{host}",
                tier3=url if isinstance(url, str) else None,
            )
        return None

    if kind == "egress_blocked":
        host = payload.get("host")
        if isinstance(host, str):
            return Capability(tier1=f"egress_blocked:{host}", tier2=f"egress_blocked:{host}")
        return None

    if kind == "dns_query":
        # A resolved (in-allowlist) lookup: permitted infrastructure, floor-weighted. §13.5's
        # only DNS weight class is "dns_query outside allowlist" (10) — an in-allowlist
        # resolution is not that, so it stays at the floor, present for trajectory/completeness.
        name = payload.get("name")
        if isinstance(name, str):
            return Capability(tier1=f"dns:{name}", tier2=f"dns:{name}")
        return None

    if kind == "dns_blocked":
        # A name the resolver refused (outside the allowlist, NXDOMAIN) — the label-encoded
        # covert channel Plane E exists to catch (§10.6). This is §13.5's "dns_query outside
        # allowlist" weight-10 class, whose base class is `dns_query`; the tier1 is therefore
        # dns_query:<name>, NOT dns_blocked:<name> (which has no weight entry and would fall to
        # the floor, under-weighting the exact reach the gate must catch). §11.4 does not
        # enumerate a DNS tier-1 class; this fills that gap — see docs/spec-notes.md.
        name = payload.get("name")
        if isinstance(name, str):
            return Capability(tier1=f"dns_query:{name}", tier2=f"dns_query:{name}")
        return None

    if kind == "process_exec":
        argv = payload.get("argv")
        if isinstance(argv, list) and argv and isinstance(argv[0], str):
            argv0 = PurePosixPath(argv[0]).name
            return Capability(
                tier1=f"process:{argv0}",
                tier2=f"process:{argv0}",
                tier3=" ".join(str(part) for part in argv),
            )
        return None

    if kind == "subagent_spawn":
        return Capability(tier1="subagent_spawn", tier2="subagent_spawn")

    return None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _t1(capability: Capability | None) -> str | None:
    return capability.tier1 if capability is not None else None


def _tool_zone_path(path: str, context: NormalizationContext) -> tuple[str, str, str | None]:
    """Zone-classify a tool-call path the way the filesystem plane would have.

    Tool paths are container paths; relative ones resolve against the workspace root
    (that is the exec working directory, and the tool descriptions say so).
    """
    absolute = path if path.startswith("/") else f"{context.workspace_root.rstrip('/')}/{path}"
    zoned = ZoneMap(
        workspace=PurePosixPath(context.workspace_root),
        harness_state=PurePosixPath(f"{context.home}/.claude"),
        scratch=PurePosixPath(context.tmp),
    ).classify(absolute)
    return (zoned.zone, str(zoned.absolute), str(zoned.relative))


def _filesystem_capability(
    zone_path: tuple[str, str, str | None],
    *,
    write: bool,
    deleted: bool,
    context: NormalizationContext,
) -> Capability:
    """The §4.1 filesystem classes, with §10.2's zone rules applied.

    Scratch is coarsened to tier 2: a temp file's exact name is noise, but which
    directory a skill scribbles in is not.
    """
    zone, absolute, relative = zone_path
    normalized = context.normalize_path(absolute)

    if zone == "workspace":
        if deleted:  # noqa: SIM108 — three states read better stacked than ternaried
            tier1 = "workspace_delete"
        else:
            tier1 = "workspace_write" if write else "workspace_read"
        tier2 = f"{tier1}:{_first_segment(relative)}"
        return Capability(tier1=tier1, tier2=tier2, tier3=normalized)

    tier1 = "outside_workspace_write" if (write or deleted) else "outside_workspace_read"
    tier2 = f"{tier1}:{_top_level(normalized)}"
    rules = ZONE_RULES.get(cast(Zone, zone))
    if rules is not None and rules.coarsen_to_tier2:
        return Capability(tier1=tier1, tier2=tier2)
    return Capability(tier1=tier1, tier2=tier2, tier3=normalized)


def _first_segment(relative: str | None) -> str:
    """Tier 2 inside the workspace: the first path segment, with a trailing slash for
    directories-of, or the bare filename for root-level files.

    The workspace root *itself* — a read or write of ``.``, or the absolute
    ``/work/<slug>`` — normalises to a path with no segments (``PurePosixPath(".").parts``
    is empty). That is a real thing a skill can do, benignly (``ls .``) or adversarially
    (``read {path: "."}`` to crash the analyser), so it must classify, not raise. It maps
    to the empty first segment: tier 2 ``workspace_read:``, the root of the workspace.
    """
    if not relative or relative == ".":
        return ""
    parts = PurePosixPath(relative).parts
    if not parts:
        return ""
    if len(parts) > 1:
        return parts[0] + "/"
    return parts[0]


def _top_level(normalized: str) -> str:
    """Tier 2 outside the workspace: the top-level directory, placeholder-aware.

    ``${HOME}/.aws/credentials`` → ``${HOME}/.aws/``; a file directly under a
    placeholder root — ``${HOME}/.bashrc`` — classifies as the root itself,
    ``${HOME}``, which is how "reads the home root" stays visible to the sensitive
    list (§13.5.4 puts the home root itself on it).
    """
    parts = PurePosixPath(normalized).parts
    if not parts:
        return normalized
    if parts[0] in ("${HOME}", "${TMP}", "${WORKSPACE}"):
        if len(parts) <= 2:
            return parts[0]
        return f"{parts[0]}/{parts[1]}/"
    if parts[0] == "/" and len(parts) > 1:
        return f"/{parts[1]}/"
    return normalized


def _directory_of(tier2: str) -> str | None:
    """The bare directory name a tier-2 entry names, for the sensitive list.

    ``workspace_read:.git/`` → ``.git/``; ``outside_workspace_read:${HOME}/.aws/`` →
    ``.aws/``; ``outside_workspace_read:${HOME}`` → ``~`` (the home root itself is on
    the list).
    """
    _, _, target = tier2.partition(":")
    if not target:
        return None
    if target == "${HOME}":
        return "~"
    name = PurePosixPath(target).name or target
    trailing = "/" if target.endswith("/") else ""
    if name.startswith("${") and name.endswith("}"):
        return None
    return name + trailing if not name.endswith("/") else name


def _tool_target(tool_input: dict[str, object]) -> str | None:
    """Tier 3 for a generic tool call: the most identifying input it has."""
    for key in ("url", "command", "name", "path"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
    return None


def _target(action: Action, context: NormalizationContext) -> str:
    """The normalized target used by within-epoch ordering (§11.5 step 4)."""
    capability = capability_for(action, context)
    if capability is not None:
        return capability.tier3 or capability.tier2 or capability.tier1
    payload = action.action
    for key in ("path", "url", "host", "tool", "skill"):
        value = payload.get(key)
        if isinstance(value, str):
            return context.normalize_path(value)
    return ""
