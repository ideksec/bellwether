"""Cross-document validation that policy and manifest only make sense together (§16.1).

Two checks the policy document cannot make on its own, because they involve the manifest
or a judgement about the whole weight set:

- **A class on a manifest ``deny`` list must not be assignable weight 0.** Weight 0 would
  erase a denied capability from the risk-weighted Jaccard — the one figure that feeds the
  BCI — so a skill could be denied ``egress`` by policy and still post a clean consistency
  score while doing it. Validated where the two documents meet, not at policy load, because
  policy alone does not know the deny list.
- **A weight set summing wildly off its default indicates a mistake.** Weights are
  renormalised, so they need not sum to any particular value, but a set that sums to
  something far from expectation is almost always a typo, and a silent one corrupts every
  BCI. This warns, naming the file and key, rather than failing — the spec calls for a
  warning, not a hard error.

These raise :class:`~bellwether.errors.ConfigurationError` (the deny-weight-0 case, which
is a real error) or return warnings (the sum case). The caller — the orchestrator, when it
lands — surfaces them before any run.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path

from bellwether.errors import ConfigurationError, UserFacingProblem

__all__ = ["WeightWarning", "validate_bci_weights", "validate_capability_weights"]


class WeightWarning(str):
    """A non-fatal weight problem, carried as its message. A ``str`` subclass so it drops
    straight into a warnings list without a wrapper."""


def validate_capability_weights(
    weights: Mapping[str, float],
    deny_classes: Iterable[str],
    *,
    source: Path | str = "policy.yaml",
) -> None:
    """Refuse a weight of 0 on any capability class the manifest denies (§16.1, §13.5.1).

    ``deny_classes`` are the tier-1 class names a manifest ``deny`` list forbids — tool
    names as ``tool:<name>``, or bare classes. A denied class weighted 0 is the failure
    this exists to prevent, and it is an error, not a warning: it silently defeats the
    gate the deny list is meant to inform.
    """
    denied = set(deny_classes)
    offenders = sorted(
        cls
        for cls, weight in weights.items()
        if weight == 0 and (cls in denied or f"tool:{cls}" in denied)
    )
    if offenders:
        raise ConfigurationError(
            source,
            [
                UserFacingProblem(
                    f"metrics.capability_risk_weights.{cls}",
                    "is 0 for a class the manifest denies; weight 0 erases a denied "
                    "capability from the risk-weighted Jaccard, defeating the gate the "
                    "deny list informs",
                )
                for cls in offenders
            ],
        )


def validate_bci_weights(
    weights: Mapping[str, float],
    *,
    expected_sum: float = 1.0,
    tolerance: float = 0.5,
    source: Path | str = "policy.yaml",
) -> list[WeightWarning]:
    """Warn — never fail — where BCI weights sum far from expectation, or a weight is 0.

    The weights are renormalised over available components, so they need not sum to 1.0;
    but a component weight of 0 is a configuration error dressed as a weight (§13.7 says to
    use ``components_excluded`` to disable a component, not a zero weight), and a total far
    from ``expected_sum`` is almost always a typo. Both warn, naming the key.
    """
    warnings: list[WeightWarning] = []
    for name, weight in sorted(weights.items()):
        if weight == 0:
            warnings.append(
                WeightWarning(
                    f"{source}: BCI component weight '{name}' is 0 — a zero weight does not "
                    "disable a component (use components_excluded); it silently drops it "
                    "from the composite"
                )
            )
    total = sum(weights.values())
    if abs(total - expected_sum) > tolerance:
        warnings.append(
            WeightWarning(
                f"{source}: BCI component weights sum to {total:.3f}, far from the expected "
                f"{expected_sum:.2f}; they are renormalised so this is not fatal, but it is "
                "usually a typo"
            )
        )
    return warnings
