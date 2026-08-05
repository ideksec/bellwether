"""Policy evaluation and the release verdict (§16).

Responsibility
    Gate evaluation — **per target, taking the worst result** — the ``ready`` /
    ``conditional`` / ``not_ready`` computation of §16.2, the §16.4 precondition check
    that refuses unsatisfiable policy/target combinations before any run executes, and
    the §16.1 cross-document weight validation that policy alone cannot perform.

MUST NOT
    Compute metrics. It consumes them.

Built by WP-11. Rules that are easy to lose: ``not_evaluable`` on a required gate blocks
and carries the coverage reason; a ``stale`` review attestation is ``not_evaluable``; a
``descriptive_only`` evaluation can never be ``ready``.
"""

from __future__ import annotations

from bellwether.verdict.engine import build_gate, compose_verdict, worst_status
from bellwether.verdict.models import (
    GateResult,
    GateStatus,
    TargetGateResult,
    Verdict,
    VerdictResult,
)
from bellwether.verdict.precondition import (
    PreconditionFailure,
    TargetDeclaration,
    check_preconditions,
)
from bellwether.verdict.validation import (
    WeightWarning,
    validate_bci_weights,
    validate_capability_weights,
)

__all__ = [
    "GateResult",
    "GateStatus",
    "PreconditionFailure",
    "TargetDeclaration",
    "TargetGateResult",
    "Verdict",
    "VerdictResult",
    "WeightWarning",
    "build_gate",
    "check_preconditions",
    "compose_verdict",
    "validate_bci_weights",
    "validate_capability_weights",
    "worst_status",
]
