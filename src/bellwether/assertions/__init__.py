"""Assertion evaluation over traces (§12).

Responsibility
    The deterministic catalogue of §12.2, judged assertions (§12.3), custom assertions
    (§12.4), assertions auto-derived from ``declared_scope`` (§12.5), the platform
    baseline (§12.6), and run-outcome composition (§12.7).

MUST NOT
    Mutate traces. An assertion reads a trace and returns a result.

Built by WP-9. Every assertion returns ``pass`` / ``fail`` / ``not_evaluable`` with a
reason string and an evidence ``seq`` list — a result with no traceable evidence is a
bug. Note the deliberate split in §12.7: ``timeout`` / ``oom`` / ``pids_limit`` are
failures, while ``budget_exceeded`` / ``cancelled`` are ``not_evaluable``.
"""

from __future__ import annotations

from bellwether.assertions.baseline import (
    BaselineApplication,
    NearMiss,
    ObservedPath,
    ObservedProcess,
    ProcessAttribution,
    apply_path_baseline,
    attribute_process,
    glob_to_regex,
)
from bellwether.assertions.derive import (
    ScopeEntry,
    ScopeTable,
    derive_assertions,
    evaluate_scope,
)
from bellwether.assertions.engine import evaluate, evaluate_all
from bellwether.assertions.evidence import EvidenceIndex, ToolCallEvidence, WriteEvidence
from bellwether.assertions.results import (
    AssertionResult,
    AssertionStatus,
    RunOutcome,
    run_outcome,
)

__all__ = [
    "AssertionResult",
    "AssertionStatus",
    "BaselineApplication",
    "EvidenceIndex",
    "NearMiss",
    "ObservedPath",
    "ObservedProcess",
    "ProcessAttribution",
    "RunOutcome",
    "ScopeEntry",
    "ScopeTable",
    "ToolCallEvidence",
    "WriteEvidence",
    "apply_path_baseline",
    "attribute_process",
    "derive_assertions",
    "evaluate",
    "evaluate_all",
    "evaluate_scope",
    "glob_to_regex",
    "run_outcome",
]
