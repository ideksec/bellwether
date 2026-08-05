"""Interval statistics for small, clustered samples (§13.1, §13.3).

The pass rate is a proportion estimated from a handful of Bernoulli trials, and revision
1's twin mistakes — fixing N at 5 and gating on the point estimate — are the reason this
module exists. Two corrections, coupled:

- **Gate on the interval, not the point.** Functional gates read the **Wilson score
  lower bound**. More runs tighten the interval and make the gate *easier* to clear, so
  the incentive points toward more evidence rather than less — the opposite of a
  point-estimate gate.
- **The normal approximation is never used.** N is small by design; the Wald interval
  misbehaves near 0 and 1 exactly where skills live.

The Pocock boundary that corrects for the three pre-registered looks is a **constant**
(``constants.POCOCK_BOUNDARY_Z``), not a computation — the looks are fixed in advance,
which is what makes a constant boundary valid. This module takes ``z`` as a parameter so
the caller passes the nominal 1.96 (labelled nominal) or the Pocock 2.289 (the gate
decision) explicitly, and neither is hard-coded here.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from bellwether.determinism import round6

__all__ = ["WilsonInterval", "min_runs_for_confidence", "wilson_interval"]

#: The nominal two-sided 95% z. Labelled *nominal* wherever it is reported, because a
#: nominal 95% interval is not 95% once the data is peeked at three times (§13.1).
NOMINAL_Z = 1.96


@dataclass(frozen=True)
class WilsonInterval:
    """A Wilson score interval on a proportion, at a stated ``z``.

    ``lower`` is the gate-relevant end under lower-bound gating. Both ends are rounded at
    construction to the shared six-place grid, so two runs that observed the same counts
    produce byte-identical intervals (§24).
    """

    point: float
    lower: float
    upper: float
    z: float
    n: int

    @property
    def half_width(self) -> float:
        return round6((self.upper - self.lower) / 2)


def wilson_interval(successes: int, n: int, *, z: float) -> WilsonInterval:
    """The Wilson score interval for ``successes`` out of ``n`` at confidence ``z``.

    At ``n == 0`` the proportion is undefined; the interval is the whole ``[0, 1]`` and
    the point is reported as ``0.0`` by convention — the caller gates on
    ``n_evaluable`` separately (§13.2), so a zero-evidence set never reaches a gate as a
    real number.

    The closed form (rather than a root-find) keeps this deterministic across platforms:
    given the same integers it returns the same floats everywhere.
    """
    if n < 0 or successes < 0 or successes > n:
        raise ValueError(f"invalid counts: {successes} successes out of {n}")
    if n == 0:
        return WilsonInterval(point=0.0, lower=0.0, upper=1.0, z=z, n=0)

    p_hat = successes / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p_hat + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p_hat * (1 - p_hat) / n + z2 / (4 * n * n))

    lower = max(0.0, centre - margin)
    upper = min(1.0, centre + margin)
    return WilsonInterval(point=round6(p_hat), lower=round6(lower), upper=round6(upper), z=z, n=n)


def min_runs_for_confidence(
    p_hat: float, *, half_width: float = 0.1, z: float = NOMINAL_Z, cap: int = 10_000
) -> int:
    """Smallest ``N`` whose Wilson interval at ``p_hat`` has a half-width ≤ ``half_width``.

    The answers are deliberately sobering — roughly 34 runs at ``p̂ = 0.9``, roughly 93
    at ``p̂ = 0.5`` (§13.3) — and the point of surfacing them is §2's honesty stance: a
    ``p̂`` from six runs is a weak claim, and the report must not let a reader mistake it
    for a strong one.

    Computed by search rather than a closed inversion because the Wilson half-width is
    not monotone-invertible in closed form for a fixed observed ``p̂``; the search is
    deterministic and bounded by ``cap`` (returned as a saturation signal, never an
    infinite loop). ``successes`` is taken as ``round(p̂·N)`` at each N, the honest
    reading of "if this rate held".
    """
    if not 0.0 <= p_hat <= 1.0:
        raise ValueError(f"p_hat must be in [0, 1], got {p_hat}")
    for n in range(1, cap + 1):
        successes = round(p_hat * n)
        if wilson_interval(successes, n, z=z).half_width <= half_width:
            return n
    return cap
