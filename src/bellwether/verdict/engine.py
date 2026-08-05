"""Verdict computation: deterministic, explainable, ordered (§16.2).

The rules that are easy to lose, and are therefore enforced here rather than trusted to
callers:

- **A gate evaluates per target and takes the worst result.** A skill that passes on
  ``frontier`` and fails on ``small`` does not average into a pass.
- **``not_evaluable`` on a required gate blocks**, carrying the §10.7 coverage reason, so
  the report says "required evidence unavailable: <why>" rather than a bare fail.
- **A ``descriptive_only`` evaluation can never be ``ready``** (fixed-N mode, §13.1); its
  ceiling is ``conditional``.
- **Every gate result carries traceable evidence** — a verdict with none is a bug.

This module composes results; it does not compute metrics (that is :mod:`bellwether.metrics`)
and it does not decide what a finding *is* (that is :mod:`bellwether.assertions`). It reads
a policy profile and the per-target evidence and produces the ``ready`` / ``conditional`` /
``not_ready`` decision.
"""

from __future__ import annotations

from collections.abc import Sequence

from bellwether.verdict.models import (
    GateResult,
    GateStatus,
    TargetGateResult,
    Verdict,
    VerdictResult,
)

__all__ = ["build_gate", "compose_verdict", "worst_status"]

#: Severity ordering for "worst wins" — later is worse.
_ORDER: dict[GateStatus, int] = {"pass": 0, "warn": 1, "not_evaluable": 2, "block": 3}


def worst_status(statuses: Sequence[GateStatus]) -> GateStatus:
    """The worst of a set of per-target statuses (§16.2 step 2). Empty → ``not_evaluable``:
    a gate with no target to evaluate on has produced no evidence, which blocks a required
    gate rather than silently passing."""
    if not statuses:
        return "not_evaluable"
    return max(statuses, key=lambda s: _ORDER[s])


def build_gate(
    name: str, per_target: Sequence[TargetGateResult], *, required: bool = True
) -> GateResult:
    """Assemble one gate from its per-target results, taking the worst (§16.2)."""
    status = worst_status([result.status for result in per_target])
    return GateResult(name=name, status=status, per_target=tuple(per_target), required=required)


def compose_verdict(
    gates: Sequence[GateResult], *, descriptive_only: bool = False, notes: Sequence[str] = ()
) -> VerdictResult:
    """Compose the release verdict from evaluated gates (§16.2 steps 3, 6, 7).

    - any ``block``, or any required ``not_evaluable``, ⇒ ``not_ready``;
    - otherwise, any ``warn`` (or a required ``not_evaluable`` that was somehow advisory,
      which cannot happen but is handled) ⇒ ``conditional``;
    - otherwise ⇒ ``ready`` — unless the run was ``descriptive_only``, whose ceiling is
      ``conditional`` no matter how clean the gates are.
    """
    blocks = any(
        gate.status == "block" or (gate.required and gate.status == "not_evaluable")
        for gate in gates
    )
    warns = any(
        gate.status == "warn" or (not gate.required and gate.status == "not_evaluable")
        for gate in gates
    )

    verdict: Verdict
    if blocks:
        verdict = "not_ready"
    elif warns or descriptive_only:
        verdict = "conditional"
    else:
        verdict = "ready"

    extra = tuple(notes)
    if descriptive_only and verdict != "not_ready":
        extra = (
            "descriptive_only: fixed-N mode produces no sequential decision, so the "
            "ceiling is 'conditional' regardless of the gates (§13.1)",
            *extra,
        )

    return VerdictResult(
        verdict=verdict, gates=tuple(gates), descriptive_only=descriptive_only, notes=extra
    )
