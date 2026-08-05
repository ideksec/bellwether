"""Trigger consistency: does the skill activate predictably? (§13.4, §13.7).

A skill that activates on every run of a scenario and one that activates half the time
are materially different, and the trigger component of the BCI measures that
predictability — not correctness. Whether activation was the *right* call is a separate
question (the pass rate answers it); this is only "was the activation decision stable?".

``ambiguous`` scenarios are excluded entirely (§13.7): there is no correct answer to
score them against, so their activation variance is not the skill's inconsistency.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from bellwether.determinism import round6

__all__ = ["trigger_consistency", "trigger_entropy"]


def trigger_entropy(activations: Sequence[bool]) -> float | None:
    """Normalised binary entropy of the activation decision across a scenario's runs.

    ``None`` at ``N ≤ 1`` — one run has no variance to measure (§11.4). Otherwise in
    ``[0, 1]``: 0 where the skill made the same activation decision every run, 1 where it
    split evenly. ``0·log₂0 = 0`` by the §11.4 convention.
    """
    n = len(activations)
    if n <= 1:
        return None
    a = sum(1 for x in activations if x) / n
    if a in (0.0, 1.0):
        return 0.0
    entropy = -(a * math.log2(a) + (1 - a) * math.log2(1 - a))
    return round6(entropy)  # log₂2 == 1, so binary entropy is already normalised


def trigger_consistency(activations: Sequence[bool]) -> float | None:
    """The BCI trigger component ``1 − H_trigger`` (§13.7). ``None`` at ``N ≤ 1``."""
    h = trigger_entropy(activations)
    return None if h is None else round6(1 - h)
