"""Assertion results and run-outcome composition (§12.1, §12.7).

Every assertion returns ``pass`` / ``fail`` / ``not_evaluable`` with a reason string and
the evidence — the action ``seq`` numbers that produced the result. A result with no
traceable evidence is a bug in the assertion, not a stylistic choice: findings cite
sequence numbers, and an uncited claim cannot be audited.

The arithmetic from assertion results to a run outcome is specified here because §12.7
warns exactly what happens otherwise: implemented ad hoc in three places, it comes out
inconsistent, and the inconsistencies are invisible until a gate disagrees with a
report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast

from bellwether.constants import EXIT_REASONS
from bellwether.trace import ExitReason

__all__ = ["AssertionResult", "AssertionStatus", "RunOutcome", "run_outcome"]

AssertionStatus = Literal["pass", "fail", "not_evaluable"]

#: ``excluded_quality`` is §10.5.0's correlation outcome: a run with both assertion
#: failures and blocked egress is excluded from quality metrics and retained in full
#: for security metrics, where the blocked attempt is precisely the point.
RunOutcome = Literal["pass", "fail", "not_evaluable", "excluded_quality"]


@dataclass(frozen=True)
class AssertionResult:
    """One assertion's verdict on one run."""

    name: str
    status: AssertionStatus
    #: Why — mandatory for ``fail`` and ``not_evaluable``, and good manners for
    #: ``pass``. For a degraded plane this carries the §10.7 coverage reason verbatim.
    reason: str
    #: The ``seq`` numbers of the actions that produced this result. Empty is legitimate
    #: only where the evidence is an absence ("no matching event exists").
    evidence: tuple[int, ...] = ()
    params: Any = None
    #: A ``record_only`` assertion is evaluated and reported but never fails a run
    #: (§12.2); the outcome function skips it entirely.
    record_only: bool = False


#: §12.7's exit-reason split, DERIVED from ``constants.EXIT_REASONS`` so the two cannot
#: drift (an earlier hand-copied version had: it mapped ``sandbox_error`` to not_evaluable
#: and omitted ``harness_error`` entirely — see the test that now asserts the agreement).
#: The left set is attributable to the skill and fails the run; the right set is a decision
#: Bellwether made, which is not the skill's fault.
#: (The keys of ``EXIT_REASONS`` are exit reasons by construction, hence the cast.)
_FAILING_EXITS: frozenset[ExitReason] = frozenset(
    cast("ExitReason", reason) for reason, kind in EXIT_REASONS.items() if kind == "fail"
)
_NOT_EVALUABLE_EXITS: frozenset[ExitReason] = frozenset(
    cast("ExitReason", reason) for reason, kind in EXIT_REASONS.items() if kind == "not_evaluable"
)


def run_outcome(
    results: list[AssertionResult],
    *,
    exit_reason: ExitReason | None,
    trace_complete: bool,
    egress_induced_failure: bool = False,
) -> RunOutcome:
    """Compose one run's outcome from its assertion results (§12.7, exactly).

    The order of the checks is the table's order, and the table's order is meaningful:
    an incomplete trace is ``not_evaluable`` even if every assertion that could run
    passed, and a failing exit reason is a failure even where no assertion noticed.

    ``egress_induced_failure`` is the §10.5.0 correlation: the caller sets it where the
    run has both assertion failures and ``egress_blocked`` events. It wins over a plain
    ``fail`` because scoring that run against quality would attribute an
    infrastructure-shaped failure to the skill — while for security metrics the run is
    retained in full.
    """
    considered = [result for result in results if not result.record_only]
    if not trace_complete:
        return "not_evaluable"
    if exit_reason is not None and exit_reason in _NOT_EVALUABLE_EXITS:
        return "not_evaluable"

    any_fail = any(result.status == "fail" for result in considered)
    if egress_induced_failure and (any_fail or exit_reason in _FAILING_EXITS):
        return "excluded_quality"
    if any_fail:
        return "fail"
    if exit_reason is not None and exit_reason in _FAILING_EXITS:
        return "fail"
    if any(result.status == "not_evaluable" for result in considered):
        return "not_evaluable"
    return "pass"
