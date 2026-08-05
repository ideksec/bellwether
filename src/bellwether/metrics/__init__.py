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
``outcome_consistency``, and ``J_weighted == J_plain`` when all weights are equal.
"""

from __future__ import annotations

from bellwether.metrics.bci import BCI, DEFAULT_BCI_WEIGHTS, BCIComponent, compute_bci
from bellwether.metrics.capability import (
    CapabilityMetrics,
    PeripheralCapability,
    RareCapabilityFinding,
    capability_weight,
    jaccard_pair,
    summarise_capability,
    weighted_jaccard_pair,
    weights_digest,
)
from bellwether.metrics.outcome import (
    Denominators,
    OutcomeStability,
    outcome_consistency,
    summarise_outcomes,
)
from bellwether.metrics.sequential import (
    DEFAULT_LOOKS,
    LookDecision,
    SequentialDecision,
    decide_at_look,
    next_look,
)
from bellwether.metrics.stats import (
    NOMINAL_Z,
    WilsonInterval,
    min_runs_for_confidence,
    wilson_interval,
)
from bellwether.metrics.trajectory import (
    TrajectoryCluster,
    TrajectoryMetrics,
    normalised_edit_distance,
    summarise_trajectory,
)
from bellwether.metrics.trigger import trigger_consistency, trigger_entropy

__all__ = [
    "BCI",
    "DEFAULT_BCI_WEIGHTS",
    "DEFAULT_LOOKS",
    "NOMINAL_Z",
    "BCIComponent",
    "CapabilityMetrics",
    "Denominators",
    "LookDecision",
    "OutcomeStability",
    "PeripheralCapability",
    "RareCapabilityFinding",
    "SequentialDecision",
    "TrajectoryCluster",
    "TrajectoryMetrics",
    "WilsonInterval",
    "capability_weight",
    "compute_bci",
    "decide_at_look",
    "jaccard_pair",
    "min_runs_for_confidence",
    "next_look",
    "normalised_edit_distance",
    "outcome_consistency",
    "summarise_capability",
    "summarise_outcomes",
    "summarise_trajectory",
    "trigger_consistency",
    "trigger_entropy",
    "weighted_jaccard_pair",
    "weights_digest",
    "wilson_interval",
]
