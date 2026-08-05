"""The verdict vocabulary and the shapes a gate produces (§16.2, §16.3).

The verdict words are chosen to not imply proof — a bellwether signals movement, it does
not vouch — and ``tools/language_lint.py`` fails the build on the vocabulary of
assurance (its word list is the authority) anywhere in user-facing strings. The three
words here are the whole permitted vocabulary:

- ``ready`` — met the configured gates on the evidence collected;
- ``conditional`` — met the blocking gates; see warnings;
- ``not_ready`` — failed one or more blocking gates.

Every gate result carries the evidence that produced it — the run IDs and action ``seq``
numbers — because a verdict with no traceable evidence is a bug (§16.2 step 8).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

__all__ = [
    "GateResult",
    "GateStatus",
    "TargetGateResult",
    "Verdict",
    "VerdictResult",
]

#: One gate's disposition on the evidence. ``not_evaluable`` on a *required* gate is
#: treated as ``block`` by the composition, but it is kept distinct here so the report can
#: say "blocked because unevaluable" rather than "failed".
GateStatus = Literal["pass", "warn", "block", "not_evaluable"]

#: The three-word verdict vocabulary (§16.3). Nothing else may be emitted.
Verdict = Literal["ready", "conditional", "not_ready"]


@dataclass(frozen=True)
class TargetGateResult:
    """One gate's result on one target — the granularity that must not be averaged away."""

    target: str
    status: GateStatus
    observed: str
    threshold: str
    reason: str
    #: ``(n_evaluable, look)`` behind the observation, where the gate reads a repetition
    #: set. ``None`` for gates that do not (static scan, budget).
    n_and_look: tuple[int, int] | None = None
    #: Run IDs and ``seq`` numbers the reader can follow to the evidence.
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class GateResult:
    """A gate's overall result, which is the **worst** of its per-target results (§16.2).

    A skill that passes on ``frontier`` and fails on ``small`` does not average into a
    pass — losing that by aggregating first defeats the whole point of the multi-model
    matrix.
    """

    name: str
    status: GateStatus
    per_target: tuple[TargetGateResult, ...]
    #: Whether a ``not_evaluable`` here blocks. Required gates block; advisory gates
    #: (a ``warn`` disposition) surface the reason without blocking.
    required: bool = True

    @property
    def worst_reason(self) -> str:
        """The reason from the target that set the overall status — what to show first."""
        for result in self.per_target:
            if result.status == self.status:
                return f"{result.target}: {result.reason}"
        return ""


@dataclass(frozen=True)
class VerdictResult:
    """The composed release decision and its full, ordered breakdown."""

    verdict: Verdict
    gates: tuple[GateResult, ...]
    #: Set where the evaluation was fixed-N (§13.1): it can never be ``ready``, and the
    #: report must say why the ceiling is ``conditional``.
    descriptive_only: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    def blocking(self) -> tuple[GateResult, ...]:
        return tuple(
            g
            for g in self.gates
            if g.status == "block" or (g.required and g.status == "not_evaluable")
        )

    def warnings(self) -> tuple[GateResult, ...]:
        return tuple(g for g in self.gates if g.status == "warn")
