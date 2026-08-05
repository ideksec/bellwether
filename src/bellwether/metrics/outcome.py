"""Outcome stability and the denominators the whole report rests on (§13.2, §13.3).

Revision 1 wrote ``p̂ = passes / N`` without saying what happens when a run produced no
usable evidence, and that silence is exactly where a tool launders a broken evaluation
into a clean number. The denominators here are mandatory and never collapsed: a
``not_evaluable`` run (degraded plane coverage), an ``excluded_quality`` run (allowlist
too tight), and a genuine infrastructure error have different causes and different
remedies, so they are counted separately and every rate travels with ``n_evaluable``
and ``n_planned``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from bellwether.assertions import RunOutcome
from bellwether.determinism import round6
from bellwether.metrics.stats import (
    NOMINAL_Z,
    WilsonInterval,
    min_runs_for_confidence,
    wilson_interval,
)

__all__ = ["Denominators", "OutcomeStability", "outcome_consistency", "summarise_outcomes"]


@dataclass(frozen=True)
class Denominators:
    """The §13.2 counts, reported alongside every rate and never merged.

    ``n_evaluable`` is the denominator of ``p̂``; ``n_planned`` is what the sequential
    design asked for at this look. Their gap is where dropped and degraded runs live.
    """

    n_planned: int
    n_completed: int
    n_evaluable: int
    n_not_evaluable: int
    n_excluded_quality: int
    passes: int
    fails: int

    @property
    def n_errored(self) -> int:
        """§13.2: ``n_planned − n_evaluable`` — everything that failed to become evidence."""
        return self.n_planned - self.n_evaluable

    @property
    def evaluable_fraction(self) -> float:
        """Feeds the ``min_evaluable_fraction`` gate (§13.2). 0.0 where nothing planned."""
        if self.n_planned == 0:
            return 0.0
        return round6(self.n_evaluable / self.n_planned)


@dataclass(frozen=True)
class OutcomeStability:
    """The §13.3 outcome figures for one repetition set."""

    denominators: Denominators
    #: ``None`` where ``n_evaluable == 0`` — a rate over no evidence is not a number, and
    #: forcing one is the laundering §13.2 forbids.
    pass_rate: float | None
    nominal_interval: WilsonInterval | None
    pocock_interval: WilsonInterval | None
    outcome_consistency: float | None
    flake: bool
    consistently_failing: bool
    #: N required for a ±0.1 half-width at the observed rate (§13.3). ``None`` with no rate.
    min_runs_for_confidence: int | None


def outcome_consistency(p_hat: float) -> float:
    """§13.3: ``1 − 2·min(p̂, 1−p̂)`` — exact, symmetric about 0.5, rounding-independent.

    This replaces revision 1's ``1 − 2·|p̂ − round(p̂)|``, which depended on the
    language's rounding mode (Python's banker's rounding makes ``round(0.5) == 0`` but
    ``round(1.5) == 2``, so the old form was asymmetric about 0.5). At ``p̂ = 0`` this
    returns 1.0 — a skill that fails every run *is* perfectly consistent — which is why
    §13.3 mandates the "consistently failing" annotation and adjacency of the pass rate
    wherever a BCI is shown.
    """
    if not 0.0 <= p_hat <= 1.0:
        raise ValueError(f"p_hat must be in [0, 1], got {p_hat}")
    return round6(1 - 2 * min(p_hat, 1 - p_hat))


def summarise_outcomes(
    outcomes: Sequence[RunOutcome], *, n_planned: int | None = None
) -> OutcomeStability:
    """Aggregate one repetition set's run outcomes into the §13.3 figures.

    ``n_planned`` defaults to ``len(outcomes)`` — the runs actually executed — but the
    caller passes the design's planned count where a slot was dropped after exhausting
    its retries (§13.2), so ``n_errored`` reflects the drop.
    """
    passes = sum(1 for o in outcomes if o == "pass")
    fails = sum(1 for o in outcomes if o == "fail")
    n_not_evaluable = sum(1 for o in outcomes if o == "not_evaluable")
    n_excluded = sum(1 for o in outcomes if o == "excluded_quality")
    n_evaluable = passes + fails
    denominators = Denominators(
        n_planned=n_planned if n_planned is not None else len(outcomes),
        n_completed=len(outcomes),
        n_evaluable=n_evaluable,
        n_not_evaluable=n_not_evaluable,
        n_excluded_quality=n_excluded,
        passes=passes,
        fails=fails,
    )

    if n_evaluable == 0:
        return OutcomeStability(
            denominators=denominators,
            pass_rate=None,
            nominal_interval=None,
            pocock_interval=None,
            outcome_consistency=None,
            flake=False,
            consistently_failing=False,
            min_runs_for_confidence=None,
        )

    from bellwether.constants import POCOCK_BOUNDARY_Z

    p_hat = passes / n_evaluable
    pocock_z = POCOCK_BOUNDARY_Z[3]
    return OutcomeStability(
        denominators=denominators,
        pass_rate=round6(p_hat),
        nominal_interval=wilson_interval(passes, n_evaluable, z=NOMINAL_Z),
        pocock_interval=wilson_interval(passes, n_evaluable, z=pocock_z),
        outcome_consistency=outcome_consistency(p_hat),
        flake=0 < p_hat < 1,
        consistently_failing=p_hat < 0.5,
        min_runs_for_confidence=min_runs_for_confidence(p_hat),
    )
