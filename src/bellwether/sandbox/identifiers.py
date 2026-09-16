"""Randomised sandbox identifiers (§3.5, §9.2).

A skill that can tell it is being evaluated can pass evaluation and misbehave in
production. Environment tells — a container named ``bellwether-run-3``, a workspace at
``/work/fixture-python-repo``, a hostname that says ``sandbox`` — are the cheapest such
signal, so the identifiers a skill can read are drawn per run from the evaluation seed.

**Perfect concealment is not achievable and is not claimed.** A determined skill can
still detect a container. These mitigations raise cost and produce evidence: any process
inspecting container metadata is recorded as an ``instrumentation_probe`` finding.

Randomised *across* runs, constant *within* one: a hostname that changed mid-run would
make any tool deriving an identifier from it produce varying output, which is exactly the
noise §9.2 pins the timezone, locale and machine-id to remove.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from bellwether.determinism import SeededRng

__all__ = ["STABLE_SINK_CONTAINER_PATH", "SandboxIdentifiers", "derive_identifiers"]

#: The container path the host-owned event-sink FIFO (§10.1) is bound at when randomisation is
#: **off** — greppable, so an operator debugging a run can find it. Under randomisation the path is
#: drawn per run (see :func:`derive_identifiers`), because a *fixed* FIFO path is an instrumentation
#: tell of exactly the kind §3.5 removes: a skill that checks for ``/dev/bellwether-events`` learns
#: it is being evaluated. The harness hook writes to this path; the executor mounts the FIFO there.
STABLE_SINK_CONTAINER_PATH = PurePosixPath("/dev/bellwether-events")

#: Hostname stems that look like ordinary build infrastructure. A skill grepping its own
#: hostname for "sandbox" or "bellwether" learns nothing from these.
_HOSTNAME_STEMS = (
    "build",
    "runner",
    "worker",
    "ci",
    "agent",
    "node",
)

_HEX = "0123456789abcdef"


@dataclass(frozen=True)
class SandboxIdentifiers:
    """The identifiers one run presents to whatever is inside it."""

    workspace_root: PurePosixPath
    hostname: str
    container_name: str
    #: The container path the host-owned event-sink FIFO is mounted at (§10.1). Randomised per run
    #: like the other identifiers, because a *fixed* sink path is a §3.5 tell — a skill that greps
    #: for it learns it is being evaluated. The harness hook and the executor mount both read it
    #: from here, so the two never disagree.
    event_sink_path: PurePosixPath = STABLE_SINK_CONTAINER_PATH
    #: False where randomisation was turned off, so the report can say the concealment
    #: mitigations of §3.5 were not in force rather than implying they were.
    randomized: bool = True


def derive_identifiers(
    rng: SeededRng,
    *,
    workspace_base: str | PurePosixPath = "/work",
    randomize: bool = True,
    run_ordinal: int | None = None,
) -> SandboxIdentifiers:
    """Draw the identifiers for one run.

    Args:
        rng: A per-run stream. Two runs of the same evaluation must not share one, or
            every container in the matrix gets the same name and the second fails to start.
        workspace_base: Zone root the workspace sits under.
        randomize: When false, produce stable, greppable identifiers instead. Findable
            containers help an operator debugging a run; they also hand a skill a reliable
            tell, so the choice is recorded in the trace rather than assumed.
        run_ordinal: Used only when ``randomize`` is false, to keep names unique.
    """
    base = PurePosixPath(workspace_base)

    if not randomize:
        suffix = "" if run_ordinal is None else f"-{run_ordinal}"
        return SandboxIdentifiers(
            workspace_root=base / f"workspace{suffix}",
            hostname=f"bellwether{suffix}",
            container_name=f"bellwether-sandbox{suffix}",
            event_sink_path=STABLE_SINK_CONTAINER_PATH,
            randomized=False,
        )

    slug = rng.token(6, alphabet=_HEX)
    stem = rng.choice(_HOSTNAME_STEMS)
    hostname = f"{stem}-{rng.token(4, alphabet=_HEX)}"
    # A fresh token, not the workspace slug: a skill that can read the workspace path must not be
    # able to derive the sink path from it. A bare hex leaf under /dev carries no project name (the
    # `bellwether-events` leaf was itself a tell), and the mount point stays under /dev where the
    # bind is proven to work.
    sink_leaf = rng.token(8, alphabet=_HEX)
    return SandboxIdentifiers(
        workspace_root=base / slug,
        hostname=hostname,
        # No project prefix: a container named `bw-*` is a tell that survives every other
        # mitigation here. The trade-off against operator findability is why
        # `randomize_identifiers: false` exists.
        container_name=f"{stem}-{slug}",
        event_sink_path=PurePosixPath("/dev") / sink_leaf,
        randomized=True,
    )
