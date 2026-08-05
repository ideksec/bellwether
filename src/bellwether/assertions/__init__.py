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

__all__ = [
    "BaselineApplication",
    "NearMiss",
    "ObservedPath",
    "ObservedProcess",
    "ProcessAttribution",
    "apply_path_baseline",
    "attribute_process",
    "glob_to_regex",
]
