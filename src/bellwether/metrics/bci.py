"""The Behavioural Consistency Index (§13.7).

One 0–100 number, because people need one number, plus the full breakdown, because one
number is never enough. Named *Consistency* rather than *Stability* deliberately:
stability reads as quality, and a skill can be consistently wrong — the outcome component
returns 1.0 at ``p̂ = 0`` (a skill that fails every run is perfectly consistent). So the
BCI must never be rendered without the pass rate adjacent, and carries a "consistently
failing" annotation wherever ``p̂ < 0.5``.

**Renormalisation is mandatory.** The default weights sum to 1.00 only when every
component is available, and the common case is that they are not — output dispersion is
disabled without an embedding provider, trigger is ``not_evaluable`` on a harness that
does not expose activation. Without renormalising, the maximum achievable BCI silently
becomes 95 and ``min_bci: 85`` effectively becomes 89.5 — a discrepancy nobody would
notice and everybody would blame on the skill. Dividing by the sum of *available* weights
fixes it, and ``components_used`` / ``components_excluded`` record exactly which
contributed.

The capability component is the **weighted** Jaccard, weighted high because it is the
security-relevant dimension — but §13.5.1.1 stands: the capability *component* is a smooth
signal, not the mechanism that catches a rare high-risk capability. A high BCI is not
evidence that no rare capability appeared; the frequency-independent gates say that, and
no rendering may let the composite imply otherwise.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from bellwether.determinism import round6

__all__ = ["BCI", "DEFAULT_BCI_WEIGHTS", "BCIComponent", "compute_bci"]

#: Default component weights (§13.7). They need not sum to 1.0 — they are renormalised
#: over available components — but a set summing to something wildly different indicates a
#: mistake and the config loader (§16.1) must warn. A component weight of 0 is a
#: configuration error, not a way to disable a component; use ``components_excluded``.
DEFAULT_BCI_WEIGHTS: Mapping[str, float] = {
    "outcome": 0.30,
    "trigger": 0.20,
    "trajectory": 0.15,
    "capability": 0.30,
    "output": 0.05,
}


@dataclass(frozen=True)
class BCIComponent:
    name: str
    value: float
    weight: float


@dataclass(frozen=True)
class BCI:
    """The composite and its breakdown."""

    score: float
    components_used: tuple[BCIComponent, ...]
    components_excluded: tuple[tuple[str, str], ...]
    consistently_failing: bool

    def render_guard(self) -> str:
        """The annotation every surface must carry where the skill is consistently failing."""
        return "consistently failing" if self.consistently_failing else ""


def compute_bci(
    components: Mapping[str, float | None],
    *,
    weights: Mapping[str, float] | None = None,
    pass_rate: float | None = None,
) -> BCI:
    """Combine the available components into the 0–100 composite (§13.7).

    Args:
        components: Component name → value in ``[0, 1]``, or ``None`` where the component
            is ``not_evaluable`` / disabled (trigger on a harness without activation,
            output without an embedding provider). ``None`` components are excluded and
            recorded with a reason; the weights renormalise over what remains.
        weights: Component weights, defaulting to the §13.7 table.
        pass_rate: The set's ``p̂``, for the consistently-failing annotation. A BCI is
            never rendered without it, so it travels inside the result.

    A component present in ``weights`` but absent from ``components`` is excluded as
    "not supplied"; a component whose value is outside ``[0, 1]`` is a programming error
    and raises, because a silently clamped component would corrupt the composite.
    """
    resolved = dict(weights) if weights is not None else dict(DEFAULT_BCI_WEIGHTS)

    used: list[BCIComponent] = []
    excluded: list[tuple[str, str]] = []
    for name, weight in resolved.items():
        value = components.get(name)
        if value is None:
            excluded.append((name, "not_evaluable or disabled for this run"))
            continue
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"BCI component {name!r} must be in [0, 1], got {value}")
        used.append(BCIComponent(name=name, value=value, weight=weight))

    total_weight = sum(component.weight for component in used)
    # Nothing to compose → surface 0 with everything excluded rather than dividing by zero.
    if total_weight <= 0:  # noqa: SIM108 — the zero-guard reads clearer stacked than ternaried
        score = 0.0
    else:
        score = 100 * sum(c.value * c.weight for c in used) / total_weight

    return BCI(
        score=round6(score),
        components_used=tuple(used),
        components_excluded=tuple(excluded),
        consistently_failing=pass_rate is not None and pass_rate < 0.5,
    )
