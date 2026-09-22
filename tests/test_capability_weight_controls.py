"""A capability weight does what it says, or the policy is refused (§13.5.1, §16.1).

Four ways a weight looked configured and was not, each reproduced before the fix:

* the "never weight a denied class 0" check asked about the policy's *spelling* — ``bash`` —
  while a denied ``tool:bash`` takes the weight of its base class ``tool``, set as ``tool_call``;
  so ``tool_call: 0`` (or ``0.4``) erased every denied tool and passed;
* weights were ``round``-ed to the integers the metric keys on, so ``0.4`` and — banker's
  rounding — ``0.5`` became ``0``: a canary read and an egress in one run of six produced no
  rare-capability finding and a perfect weighted Jaccard;
* a key that reaches no capability — a typo, or ``egress:evil.com``, which the base-class lookup
  never consults — was accepted and ignored;
* every class weighted ``0`` divided by zero.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from bellwether.config.models.policy import PolicyMetrics
from bellwether.errors import ConfigurationError
from bellwether.metrics import resolve_capability_weights, summarise_capability
from bellwether.verdict import validate_capability_weights


@pytest.mark.parametrize("weights", [{"tool_call": 0.0}, {"tool": 0.0}])
def test_a_denied_tool_cannot_be_erased_by_any_spelling_of_its_weight(
    weights: dict[str, float],
) -> None:
    with pytest.raises(ConfigurationError, match="resolves to weight 0"):
        validate_capability_weights(weights, deny_classes={"tool:bash"})


def test_a_zero_weight_on_an_undenied_class_is_still_allowed() -> None:
    """Weight 0 is a legitimate choice for a class the manifest does not deny."""
    validate_capability_weights({"workspace_read": 0.0}, deny_classes={"tool:bash"})


@pytest.mark.parametrize("weight", [0.4, 0.5, 2.5])
def test_a_fractional_weight_is_refused_not_rounded(weight: float) -> None:
    with pytest.raises(ValidationError, match="whole numbers"):
        PolicyMetrics.model_validate({"capability_risk_weights": {"canary_read": weight}})


@pytest.mark.parametrize("key", ["canary_reads", "egress:evil.com", "tool:bash", "bash"])
def test_a_key_that_reaches_no_capability_is_refused(key: str) -> None:
    with pytest.raises(ValidationError, match="reach no capability"):
        PolicyMetrics.model_validate({"capability_risk_weights": {key: 10}})


def test_every_shipped_key_and_every_base_class_is_weightable() -> None:
    from bellwether.constants import DEFAULT_CAPABILITY_WEIGHTS

    PolicyMetrics()  # the shipped defaults validate
    PolicyMetrics.model_validate(
        {"capability_risk_weights": dict.fromkeys(DEFAULT_CAPABILITY_WEIGHTS, 1)}
    )


def test_a_rare_canary_read_and_egress_stay_findings_under_small_whole_weights() -> None:
    """The erasure, stated as behaviour: the smallest weights the schema now admits still count."""
    weights = resolve_capability_weights({"canary_read": 1, "egress_non_model": 1})
    runs = [{"workspace_read"}] * 5 + [{"workspace_read", "canary_read", "egress:evil.com"}]
    metrics = summarise_capability(
        [frozenset(run) for run in runs], weights=weights, rare_capability_weight_threshold=1
    )
    assert {finding.tier1 for finding in metrics.rare_findings} >= {
        "canary_read",
        "egress:evil.com",
    }
    assert metrics.jaccard_weighted < 1.0


def test_all_zero_weights_fall_back_to_the_unweighted_figure_instead_of_crashing() -> None:
    weights = resolve_capability_weights({"tool_call": 0})
    metrics = summarise_capability(
        [frozenset({"tool:bash"}), frozenset({"tool:read"})], weights=weights
    )
    assert metrics.jaccard_weighted == metrics.jaccard_plain == 0.0
