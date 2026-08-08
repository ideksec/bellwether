"""Planning where a run's canaries are planted in the sandbox (§10.4).

Minting a canary (:func:`bellwether.capture.canary.mint_canaries`) decides its *value*; this decides
where that value goes inside the container so a thieving skill can find it: an env-var canary becomes
an environment variable, a file canary becomes a small file at its slot path (``~/.aws/credentials``,
``.env``, …). The executor injects the env and stages the files, then records only the **by-reference**
:class:`PlantedSlot`s in the trace — the marker itself never reaches an artifact (§10.4.3), which is
the whole point: a trace that leaked the canary would be the leak.

The planner is pure and offline-tested; it holds no I/O. The layering runs ``capture -> trace``, so
this produces capture-native slots and the ``cli`` executor turns them into the trace's
``PlantedCanary`` references — a capture module importing trace models would invert the stack.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from bellwether.capture.canary import Canary

__all__ = ["CanaryPlanting", "PlantedSlot", "plan_canary_planting"]

#: The pool kind that plants into the environment rather than the filesystem. Its ``path`` is the
#: env-var *name* (``INTERNAL_API_TOKEN``), not a file path.
_ENVVAR_KIND = "envvar"


@dataclass(frozen=True)
class PlantedSlot:
    """One planted canary, by reference — id, kind, and where it was planted. **No marker.**

    This is what the trace records (§10.4.3): a reviewer can see *that* a canary lived at
    ``~/.aws/credentials`` without the artifact carrying its value.
    """

    id: str
    kind: str
    path: str


@dataclass(frozen=True)
class CanaryPlanting:
    """The plan for planting one run's canaries into its sandbox.

    ``env`` and ``files`` carry the markers (they go *into* the container); ``slots`` is the
    marker-free record for the trace. The two are kept apart deliberately so it is structurally
    impossible to record a marker: nothing in ``slots`` holds a value.
    """

    #: Env-var canaries: variable name → marker. Injected into the container's environment.
    env: dict[str, str]
    #: File canaries: (slot path, marker). Staged as small files inside the container.
    files: tuple[tuple[str, str], ...]
    #: The by-reference records for the trace — id, kind, path, never the marker.
    slots: tuple[PlantedSlot, ...]


def plan_canary_planting(canaries: Iterable[Canary]) -> CanaryPlanting:
    """Decide where each minted canary is planted, without doing any I/O (§10.4).

    An ``envvar`` canary becomes an environment variable (its slot path is the variable name);
    every other kind becomes a file at its slot path. The returned :class:`CanaryPlanting` gives the
    executor the env to inject, the files to stage, and the marker-free slots to record — sorted, so
    two identical runs plant and record byte-identically (§24).
    """
    env: dict[str, str] = {}
    files: list[tuple[str, str]] = []
    slots: list[PlantedSlot] = []
    for canary in sorted(canaries, key=lambda c: c.id):
        slots.append(PlantedSlot(id=canary.id, kind=canary.kind, path=canary.path))
        if canary.kind == _ENVVAR_KIND:
            env[canary.path] = canary.marker
        else:
            files.append((canary.path, canary.marker))
    return CanaryPlanting(env=env, files=tuple(files), slots=tuple(slots))
