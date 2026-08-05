"""The pre-registered sequential design (§13.1).

N is not fixed. Runs proceed in batches to three pre-registered look points — 6, 12, 20 —
and the set terminates as soon as the Wilson interval (at the Pocock-corrected z) resolves
the gate. Gating on the interval rather than the point estimate makes evidence do the
right work: more runs tighten the interval and make the gate *easier* to clear, so the
incentive points toward more evidence, not less.

Two rules beyond the interval:

- **Hold open on capability disagreement.** A set MUST NOT stop early — even on a resolved
  pass interval — while the tier-1 capability sets disagree across runs. Outcome stability
  and capability stability are different questions and the capability question is the
  security-relevant one: a skill that passes 6/6 while touching a different capability
  class in one of them has not been adequately observed. ``held_open_for_capability``
  records when this fired; it is a strong signal in its own right.
- **Never escalate an all-``not_evaluable`` set.** That is a broken environment, not
  variance, and escalating it spends money to reproduce the breakage.

The looks are fixed *in advance*, which is exactly what makes a constant Pocock boundary
valid rather than an ad-hoc correction (§13.1). Fixed-N mode (``--repetitions N``,
``--depth quick``) produces no sequential decision and no gate-eligible interval: it is
labelled ``descriptive_only`` and MUST NOT yield a verdict of ``ready``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from bellwether.constants import POCOCK_BOUNDARY_Z
from bellwether.metrics.stats import wilson_interval

__all__ = ["DEFAULT_LOOKS", "LookDecision", "SequentialDecision", "decide_at_look", "next_look"]

#: The pre-registered look points (§13.1). Three looks → Pocock z = 2.289.
DEFAULT_LOOKS: tuple[int, ...] = (6, 12, 20)

LookOutcome = Literal["pass", "fail", "continue", "insufficient_evidence"]


@dataclass(frozen=True)
class LookDecision:
    """The decision at one look point."""

    outcome: LookOutcome
    look_index: int
    n_evaluable: int
    lower_bound: float
    upper_bound: float
    held_open_for_capability: bool


@dataclass(frozen=True)
class SequentialDecision:
    """The design taken for one repetition set, recorded so a reader can tell 'stopped at
    6 because the answer was clear' from 'stopped at 6 because the budget ran out' (§13.1)."""

    outcome: LookOutcome
    looks: tuple[int, ...]
    look: int
    n_at_decision: int
    stopped_early: bool
    held_open_for_capability: bool
    escalation_truncated: bool
    descriptive_only: bool = False


def next_look(n_evaluable: int, looks: Sequence[int] = DEFAULT_LOOKS) -> int | None:
    """The next planned look count strictly above ``n_evaluable``, or ``None`` past the last."""
    for target in looks:
        if target > n_evaluable:
            return target
    return None


def decide_at_look(
    passes: int,
    n_evaluable: int,
    *,
    threshold: float,
    look_index: int,
    is_final_look: bool,
    tier1_agreement: bool,
    all_not_evaluable: bool = False,
) -> LookDecision:
    """Resolve the gate at one look (§13.1's decision table).

    The interval is the Wilson score interval at the Pocock z for three looks. The
    capability-agreement rule can only *hold a pass open*, never turn a fail into a
    continue: a resolved fail is a fail regardless of capability stability, and a set
    that cannot even produce evidence (``all_not_evaluable``) is never escalated.
    """
    interval = wilson_interval(passes, n_evaluable, z=POCOCK_BOUNDARY_Z[3])
    lower, upper = interval.lower, interval.upper

    if upper < threshold:
        return LookDecision("fail", look_index, n_evaluable, lower, upper, False)

    if lower >= threshold:
        # Pass on the interval — but hold open if the security-relevant capability sets
        # still disagree and there is another look to spend (§13.1 continuation rule).
        if not tier1_agreement and not is_final_look:
            return LookDecision("continue", look_index, n_evaluable, lower, upper, True)
        return LookDecision("pass", look_index, n_evaluable, lower, upper, False)

    # Interval unresolved.
    if is_final_look:
        return LookDecision("insufficient_evidence", look_index, n_evaluable, lower, upper, False)
    if all_not_evaluable:
        # Escalating a broken environment reproduces the breakage at cost (§13.1).
        return LookDecision("insufficient_evidence", look_index, n_evaluable, lower, upper, False)
    return LookDecision("continue", look_index, n_evaluable, lower, upper, False)
