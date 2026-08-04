"""Nondeterminism and divergence math (§13, §14).

Responsibility
    Wilson intervals parameterised by z, the Pocock-corrected sequential design of
    §13.1, denominators and retry accounting (§13.2), outcome stability, trajectory
    clustering, capability variance at three tiers (plain and risk-weighted tier-1
    Jaccard), output variance, and the Behavioural Consistency Index with mandatory
    renormalisation.

MUST NOT
    Know about policy. Metrics produce numbers; :mod:`bellwether.verdict` decides what
    they mean. In particular ``metrics`` MUST NOT import ``verdict`` — enforced by
    ``.importlinter``.

Built by WP-10. Property-based tests here are mandatory, not optional: bounds, identity,
monotonicity, the §11.4 edge cases, renormalisation, rounding-independence of
``outcome_consistency``, and ``J_weighted == J_plain`` when all weights are equal. The
property tests are the specification. ``mypy --strict`` from the first commit.
"""

from __future__ import annotations

__all__: list[str] = []
