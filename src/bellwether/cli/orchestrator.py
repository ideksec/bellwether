"""The analysis orchestrator: traces in, verdict and artifact tree out (§13–§17).

Every stage below this line already exists as a tested library — capture → trace →
assertions → metrics → verdict → report. What was missing is the thing that *assembles*
them into an evaluation, and that is this module. It does not execute runs itself: a
:class:`RunExecutor` (the sandbox + harness half, built separately) hands it the trace for
each repetition, and from there everything is deterministic and offline.

The flow, per repetition set (one scenario on one target):

1. :func:`analyse_run` turns each trace into a per-run reading — the §12.7 run outcome, the
   canonical capability sets, and the trajectory step sequence;
2. :func:`aggregate` rolls the set up through the §13 metrics — sequential pass-rate design
   (§13.1), risk-weighted capability Jaccard (§13.5), trajectory clustering (§13.4), and
   the BCI (§13.7);
3. the gate builders turn each reading into a per-target gate disposition against the
   policy (§16.2), taking the **worst** target per gate;
4. :func:`compose_verdict` renders the three-word verdict, and the summary and PR comment
   are assembled and written to the §17.1 artifact tree.

The security-runtime gates whose capture plane does not exist yet (egress, DNS) resolve to
``not_evaluable`` carrying the coverage reason, and are marked *required* only where the
policy disposition is ``block`` — so a profile that sets them to ``warn`` (the first-light
configuration) surfaces the gap without blocking, exactly as §25 prescribes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from bellwether.assertions import (
    EvidenceIndex,
    RunOutcome,
    derive_assertions,
    evaluate_all,
    evaluate_scope,
    run_outcome,
)
from bellwether.cli.artifacts import ArtifactTree, RunKey, target_slug, write_artifact_tree
from bellwether.config.models.manifest import DeclaredScope
from bellwether.config.models.policy import ProfileSpec
from bellwether.config.models.scenarios import AssertionSpec, Scenario
from bellwether.determinism import canonical_json, round6
from bellwether.errors import BellwetherError
from bellwether.metrics import (
    compute_bci,
    decide_at_look,
    summarise_capability,
    summarise_outcomes,
    summarise_trajectory,
)
from bellwether.report import (
    CapabilityProfileSummary,
    ConsistencySummary,
    Figures,
    FunctionalSummary,
    GateSummary,
    MatrixSummary,
    PolicyRef,
    SecuritySummary,
    SkillRef,
    StripCell,
    Summary,
    VerdictSummary,
    default_limitations,
    render_pr_comment,
    render_summary_json,
)
from bellwether.trace import (
    NormalizationContext,
    StepSignature,
    Trace,
    canonicalize,
)
from bellwether.verdict import (
    GateResult,
    TargetGateResult,
    VerdictResult,
    build_gate,
    compose_verdict,
)

__all__ = [
    "AnalysedRun",
    "EvalResult",
    "ExecutedRun",
    "RunExecutor",
    "RunPlan",
    "SetReading",
    "TargetInfo",
    "aggregate",
    "analyse_run",
    "drive_evaluation",
    "orchestrate",
    "plan_matrix",
]


@dataclass(frozen=True)
class TargetInfo:
    """One matrix target, flattened to what the orchestrator and artifact paths need."""

    harness: str
    provider: str
    model_alias: str

    @property
    def slug(self) -> str:
        return target_slug(self.harness, self.provider, self.model_alias)


@dataclass(frozen=True)
class RunPlan:
    """One repetition to execute: a scenario on a target, at an index within the set."""

    scenario: Scenario
    target: TargetInfo
    repetition: int


@dataclass(frozen=True)
class ExecutedRun:
    """What a :class:`RunExecutor` returns: the trace and the context it was captured in.

    The executor owns the sandbox, so it also owns the :class:`NormalizationContext` (the
    workspace/home/tmp roots the canonicaliser normalises against). ``trace_jsonl`` is the
    already-serialised ARF, carried so the artifact tree writes the exact bytes captured.
    """

    trace: Trace
    context: NormalizationContext
    trace_jsonl: str


class RunExecutor(Protocol):
    """The execution half of a run — the sandbox and harness, built separately.

    Kept a Protocol so the analysis path can be exercised offline with a fake executor
    that replays fixture traces, while the real container-backed executor plugs in
    unchanged.
    """

    def execute(self, plan: RunPlan) -> ExecutedRun: ...


@dataclass(frozen=True)
class AnalysedRun:
    """One repetition, read into the quantities the metrics layer aggregates."""

    key: RunKey
    outcome: RunOutcome
    caps_t1: frozenset[str]
    caps_t2: frozenset[str]
    caps_t3: frozenset[str]
    sensitive_hits: tuple[str, ...]
    steps: tuple[StepSignature, ...]
    tier3_by_class: Mapping[str, frozenset[str]]
    scope_exceeded: tuple[str, ...]
    trace_jsonl: str
    canonical_json: str


def plan_matrix(
    scenarios: Sequence[Scenario],
    targets: Sequence[TargetInfo],
    *,
    repetitions: int,
) -> list[RunPlan]:
    """Expand the (scenario × target × repetition) matrix into ordered run plans (§4).

    The order is fixed — scenario, then target, then repetition index — so the plan list, and
    the artifact tree it produces, never depend on dict iteration or scheduling. Fewer than two
    runs is refused outright: repetition is mandatory, and a single-run "set" is an anecdote, not a
    distribution (§13.2). A real evaluation runs the profile's ``n_max`` and its sequential design
    decides where to stop; :func:`drive_evaluation` enforces the design's own floor (the first
    look) against the runs it actually aggregates.
    """
    if repetitions < 2:
        raise BellwetherError(
            f"a repetition set needs at least two runs (repetition is mandatory; a single run is an "
            f"anecdote, §13.2), got repetitions={repetitions}"
        )
    return [
        RunPlan(scenario=scenario, target=target, repetition=rep)
        for scenario in scenarios
        for target in targets
        for rep in range(1, repetitions + 1)
    ]


def drive_evaluation(
    plans: Sequence[RunPlan],
    executor: RunExecutor,
    *,
    profile: ProfileSpec,
    scope: DeclaredScope | None = None,
    platform_baseline_t3: frozenset[str] = frozenset(),
    weights: Mapping[str, int] | None = None,
) -> list[SetReading]:
    """Run every plan through the executor and roll each repetition set into a reading.

    The execution-to-analysis bridge the CLI ``run`` sits on: execute each plan, analyse it,
    group by ``(scenario, target)``, and aggregate each group through the §13 metrics into one
    :class:`SetReading`. The executor is injected — the container-backed
    :class:`~bellwether.cli.execution.SandboxRunExecutor` in a real run, a replay executor in a
    test — so the whole driver is exercised offline, the same seam the analysis path already uses.

    Readings come back in first-seen ``(scenario, target)`` order, matching :func:`plan_matrix`, so
    the verdict and the artifact tree are deterministic regardless of how the plans interleave.

    Each set must reach the profile's **first look** before it is aggregated. A set with fewer runs
    than the earliest pre-registered decision point (§13.1) has no boundary to stop at and would
    yield a figure the sequential design does not license — so it is refused rather than quietly
    reported, the same reflex as the rest of the pipeline.
    """
    first_look = profile.matrix.looks[0] if profile.matrix.looks else 1
    analysed_by_set: dict[tuple[str, str], list[AnalysedRun]] = {}
    order: list[tuple[str, str, TargetInfo]] = []
    for plan in plans:
        set_key = (plan.scenario.id, plan.target.slug)
        if set_key not in analysed_by_set:
            analysed_by_set[set_key] = []
            order.append((plan.scenario.id, plan.target.slug, plan.target))
        executed = executor.execute(plan)
        analysed_by_set[set_key].append(
            analyse_run(plan, executed, scope=scope, platform_baseline_t3=platform_baseline_t3)
        )
    for scenario_id, slug, _target in order:
        count = len(analysed_by_set[(scenario_id, slug)])
        if count < first_look:
            raise BellwetherError(
                f"repetition set {scenario_id!r} on {slug!r} has {count} run(s), below the profile's "
                f"first look of {first_look} (§13.1); a set that never reaches its earliest decision "
                "point cannot be aggregated into a licensed figure"
            )
    return [
        aggregate(
            scenario_id,
            target,
            analysed_by_set[(scenario_id, slug)],
            profile=profile,
            weights=weights,
        )
        for scenario_id, slug, target in order
    ]


def _verify_trace_matches_plan(trace: Trace, plan: RunPlan) -> None:
    """Reject a trace whose recorded identity does not match the plan it is being analysed under.

    The executor builds the trace header from the plan, so in a correct run these agree by
    construction. But a cached, stale, or misrouted trace would otherwise be labelled — and its
    capabilities and outcome scored — under the wrong scenario or target, quietly corrupting that
    target's verdict. This is cheap and the failure is a controlled one; the header carries exactly
    the fields the plan does.
    """
    header = trace.header
    mismatches: list[str] = []
    if header.scenario_id != plan.scenario.id:
        mismatches.append(f"scenario {header.scenario_id!r} != planned {plan.scenario.id!r}")
    if header.repetition != plan.repetition:
        mismatches.append(f"repetition {header.repetition} != planned {plan.repetition}")
    if header.target.harness != plan.target.harness:
        mismatches.append(f"harness {header.target.harness!r} != planned {plan.target.harness!r}")
    if header.target.provider != plan.target.provider:
        mismatches.append(
            f"provider {header.target.provider!r} != planned {plan.target.provider!r}"
        )
    if header.target.model_alias != plan.target.model_alias:
        mismatches.append(
            f"model {header.target.model_alias!r} != planned {plan.target.model_alias!r}"
        )
    if mismatches:
        raise BellwetherError(
            "trace does not match the run plan it was returned for, so it cannot be attributed "
            "to this target (a stale or misrouted trace): " + "; ".join(mismatches)
        )


def analyse_run(
    plan: RunPlan,
    executed: ExecutedRun,
    *,
    scope: DeclaredScope | None,
    platform_baseline_t3: frozenset[str] = frozenset(),
) -> AnalysedRun:
    """Turn one executed run into its per-run reading (§12.7 outcome + §11.4 canonical)."""
    _verify_trace_matches_plan(executed.trace, plan)
    trace = executed.trace
    context = executed.context
    index = EvidenceIndex.from_trace(trace, context, workspace=Path(context.workspace_root))

    specs: list[AssertionSpec] = list(plan.scenario.assertions)
    if scope is not None:
        specs = specs + derive_assertions(scope)
    results = evaluate_all(specs, index)
    outcome = run_outcome(results, exit_reason=trace.exit_reason, trace_complete=trace.is_complete)

    canon = canonicalize(trace.actions, context, platform_baseline_t3=platform_baseline_t3)
    tier3_by_class = _tier3_by_class(canon.caps_t3)

    scope_exceeded: tuple[str, ...] = ()
    if scope is not None:
        table = evaluate_scope(scope, index)
        scope_exceeded = tuple(sorted(entry.subject for entry in table.exceeded()))

    key = RunKey(plan.scenario.id, plan.target.slug, plan.repetition)
    canonical_json = canonical_json_of(
        canon.caps_t1, canon.caps_t2, canon.caps_t3, canon.step_sequence
    )
    return AnalysedRun(
        key=key,
        outcome=outcome,
        caps_t1=frozenset(canon.caps_t1),
        caps_t2=frozenset(canon.caps_t2),
        caps_t3=frozenset(canon.caps_t3),
        sensitive_hits=tuple(sorted(canon.sensitive_hits)),
        steps=tuple(canon.step_sequence),
        tier3_by_class=tier3_by_class,
        scope_exceeded=scope_exceeded,
        trace_jsonl=executed.trace_jsonl,
        canonical_json=canonical_json,
    )


def _tier3_by_class(caps_t3: Sequence[str]) -> dict[str, frozenset[str]]:
    """Group tier-3 capabilities under their tier-1 class prefix (best-effort).

    A tier-3 capability is spelled ``<tier1>:<detail>`` where it carries one; those without
    a prefix are grouped under ``"other"`` so the heatmap still shows them.
    """
    grouped: dict[str, set[str]] = {}
    for cap in caps_t3:
        head = cap.split(":", 1)[0] if ":" in cap else "other"
        grouped.setdefault(head, set()).add(cap)
    return {key: frozenset(value) for key, value in grouped.items()}


def canonical_json_of(
    caps_t1: Sequence[str],
    caps_t2: Sequence[str],
    caps_t3: Sequence[str],
    steps: Sequence[StepSignature],
) -> str:
    """Serialise a run's canonical reading for the ``canonical/`` artifact (§17.1)."""
    return (
        canonical_json(
            {
                "caps_t1": sorted(caps_t1),
                "caps_t2": sorted(caps_t2),
                "caps_t3": sorted(caps_t3),
                "step_sequence": [str(step) for step in steps],
            },
            indent=2,
        )
        + "\n"
    )


@dataclass(frozen=True)
class SetReading:
    """The aggregated reading for one repetition set (one scenario on one target)."""

    scenario_id: str
    target: TargetInfo
    n_completed: int
    n_evaluable: int
    pass_rate: float
    lower_bound: float
    functional_threshold: float
    look: int
    look_outcome: str
    bci: float
    consistently_failing: bool
    jaccard_weighted: float | None
    jaccard_plain: float | None
    modal_trajectory_share: float
    rare_capability_risk: str
    tier1_agreement: bool
    scope_exceeded: tuple[str, ...]
    weights_digest: str
    runs: tuple[AnalysedRun, ...]


#: Severity ordering for the rare-capability risk gate (§13.5.2).
_RISK_ORDER: Mapping[str, int] = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def aggregate(
    scenario_id: str,
    target: TargetInfo,
    runs: Sequence[AnalysedRun],
    *,
    profile: ProfileSpec,
    weights: Mapping[str, int] | None = None,
    looks: Sequence[int] = (6, 12, 20),
) -> SetReading:
    """Roll a repetition set up through the §13 metrics into one reading."""
    outcomes: list[RunOutcome] = [run.outcome for run in runs]
    stability = summarise_outcomes(outcomes, n_planned=len(runs))

    tier3_union: dict[str, set[str]] = {}
    for run in runs:
        for cls, caps in run.tier3_by_class.items():
            tier3_union.setdefault(cls, set()).update(caps)
    sensitive = sorted({hit for run in runs for hit in run.sensitive_hits})
    capability = summarise_capability(
        [run.caps_t1 for run in runs],
        tier3_by_class=tier3_union,
        tier2_sets=[run.caps_t2 for run in runs],
        sensitive_hits=sensitive,
        weights=weights,
    )

    trajectory = summarise_trajectory([run.steps for run in runs])

    components: dict[str, float | None] = {
        "outcome": stability.outcome_consistency,
        "capability": capability.jaccard_weighted,
        "trajectory": trajectory.modal_cluster_share,
        "trigger": None,
        "output": None,
    }
    bci = compute_bci(components, pass_rate=stability.pass_rate)

    look = _look_reached(stability.denominators.n_evaluable, looks)
    decision = decide_at_look(
        stability.denominators.passes,
        stability.denominators.n_evaluable,
        threshold=profile.gates.functional.min_pass_rate_lower_bound,
        look_index=looks.index(look) + 1 if look in looks else len(looks),
        is_final_look=(look >= looks[-1] if looks else True),
        tier1_agreement=capability.tier1_agreement,
        all_not_evaluable=stability.denominators.n_evaluable == 0,
    )

    scope_exceeded = tuple(sorted({cap for run in runs for cap in run.scope_exceeded}))
    return SetReading(
        scenario_id=scenario_id,
        target=target,
        n_completed=stability.denominators.n_completed,
        n_evaluable=stability.denominators.n_evaluable,
        pass_rate=round6(stability.pass_rate or 0.0),
        lower_bound=round6(decision.lower_bound),
        functional_threshold=profile.gates.functional.min_pass_rate_lower_bound,
        look=look,
        look_outcome=decision.outcome,
        bci=round6(bci.score),
        consistently_failing=bci.consistently_failing,
        jaccard_weighted=_opt_round(capability.jaccard_weighted),
        jaccard_plain=_opt_round(capability.jaccard_plain),
        modal_trajectory_share=round6(trajectory.modal_cluster_share or 0.0),
        rare_capability_risk=_rare_risk(capability.rare_findings),
        tier1_agreement=capability.tier1_agreement,
        scope_exceeded=scope_exceeded,
        weights_digest=capability.weights_digest,
        runs=tuple(runs),
    )


def _opt_round(value: float | None) -> float | None:
    return None if value is None else round6(value)


def _look_reached(n_evaluable: int, looks: Sequence[int]) -> int:
    reached = [look for look in looks if n_evaluable >= look]
    return reached[-1] if reached else (looks[0] if looks else n_evaluable)


def _rare_risk(rare_findings: Sequence[object]) -> str:
    """The worst risk band among rare high-risk capabilities (§13.5.2)."""
    if not rare_findings:
        return "none"
    worst = 0
    for finding in rare_findings:
        weight = getattr(finding, "weight", 0)
        band = "high" if weight >= 10 else "medium" if weight >= 5 else "low"
        worst = max(worst, _RISK_ORDER[band])
    for band, rank in _RISK_ORDER.items():
        if rank == worst:
            return band
    return "none"


# ---------------------------------------------------------------------------
# Gate population (§16.2): a reading vs the policy, per target, worst target wins
# ---------------------------------------------------------------------------


def _tgr(
    target: TargetInfo,
    status: str,
    observed: object,
    threshold: object,
    reason: str,
    *,
    n_and_look: tuple[int, int] | None = None,
) -> TargetGateResult:
    return TargetGateResult(
        target=target.slug,
        status=status,  # type: ignore[arg-type]
        observed=str(observed),
        threshold=str(threshold),
        reason=reason,
        n_and_look=n_and_look,
    )


def _functional_result(reading: SetReading, profile: ProfileSpec) -> TargetGateResult:
    threshold = profile.gates.functional.min_pass_rate_lower_bound
    status = {"pass": "pass", "fail": "block"}.get(reading.look_outcome, "warn")
    reason = f"pass-rate lower bound {reading.lower_bound} vs {threshold} ({reading.look_outcome})"
    return _tgr(
        reading.target,
        status,
        reading.lower_bound,
        threshold,
        reason,
        n_and_look=(reading.n_evaluable, reading.look),
    )


def _evidence_result(reading: SetReading, profile: ProfileSpec) -> TargetGateResult:
    minimum = profile.gates.evidence.min_evaluable_fraction
    fraction = reading.n_evaluable / reading.n_completed if reading.n_completed else 0.0
    status = "pass" if fraction >= minimum else "block"
    return _tgr(
        reading.target,
        status,
        round6(fraction),
        minimum,
        f"{reading.n_evaluable}/{reading.n_completed} runs evaluable",
        n_and_look=(reading.n_evaluable, reading.look),
    )


def _consistency_result(reading: SetReading, profile: ProfileSpec) -> TargetGateResult:
    gates = profile.gates.consistency
    problems: list[str] = []
    status = "pass"
    if reading.bci < gates.min_bci:
        status = "warn"
        problems.append(f"BCI {reading.bci} < {gates.min_bci}")
    jw = reading.jaccard_weighted
    if jw is not None and jw < gates.min_capability_jaccard_weighted:
        status = "warn"
        problems.append(f"weighted Jaccard {jw} < {gates.min_capability_jaccard_weighted}")
    if _RISK_ORDER[reading.rare_capability_risk] > _RISK_ORDER[gates.max_rare_capability_risk]:
        status = "block"
        problems.append(
            f"rare capability risk {reading.rare_capability_risk} > {gates.max_rare_capability_risk}"
        )
    reason = (
        "; ".join(problems) if problems else f"BCI {reading.bci}, pass rate {reading.pass_rate}"
    )
    return _tgr(
        reading.target,
        status,
        reading.bci,
        gates.min_bci,
        reason,
        n_and_look=(reading.n_evaluable, reading.look),
    )


def _scope_result(reading: SetReading, profile: ProfileSpec) -> TargetGateResult:
    block_on = set(profile.gates.scope.block_on)
    if reading.scope_exceeded and "exceeded" in block_on:
        return _tgr(
            reading.target,
            "block",
            ", ".join(reading.scope_exceeded),
            "declared scope",
            f"capabilities observed outside declared scope: {', '.join(reading.scope_exceeded)}",
        )
    status = "warn" if reading.scope_exceeded else "pass"
    observed = ", ".join(reading.scope_exceeded) if reading.scope_exceeded else "within scope"
    return _tgr(reading.target, status, observed, "declared scope", "declared vs observed")


#: The egress/DNS security-runtime checks whose capture plane is not built yet. Under a
#: profile that sets them to ``block`` this is a *required* not_evaluable — which §16.4's
#: precondition check refuses before the run — so the first-light configuration sets them
#: to ``warn`` and they surface here as an advisory not_evaluable with the reason.
_PLANE_DEPENDENT_CHECKS: Mapping[str, str] = {
    "egress_outside_allowlist": "egress",
    "dns_outside_allowlist": "dns",
    "credential_read_undeclared": "credentials",
}


def _security_runtime_result(reading: SetReading, profile: ProfileSpec) -> TargetGateResult:
    """The one plane-dependent gate that first-light exercises: egress, not yet observable.

    Reported ``not_evaluable`` with the coverage reason, required only where the policy
    disposition is ``block`` — so a ``warn`` disposition (first-light) does not block.
    """
    gates = profile.gates.security_runtime
    disposition = gates.egress_outside_allowlist
    reason = (
        "egress capture plane not available in this build (recording proxy lands in WP-13); "
        "no egress gate can be evaluated"
    )
    if disposition == "block":
        # A blocking egress gate on an egress-blind build is exactly what §16.4 refuses
        # before the run; if we reach here the caller ran anyway, so surface it honestly.
        return _tgr(reading.target, "not_evaluable", "unobserved", disposition, reason)
    return _tgr(reading.target, "not_evaluable", "unobserved", disposition, reason)


@dataclass(frozen=True)
class EvalResult:
    """The finished evaluation: the verdict, the summary object, and where it was written."""

    verdict: VerdictResult
    summary: Summary
    artifacts: ArtifactTree
    exit_code: int


def _gate(
    name: str,
    results: Sequence[TargetGateResult],
    *,
    required: bool,
) -> GateResult:
    return build_gate(name, list(results), required=required)


def _gate_summaries(gates: Sequence[GateResult]) -> tuple[GateSummary, ...]:
    return tuple(
        GateSummary(
            name=gate.name,
            status=gate.status,
            observed=gate.per_target[0].observed if gate.per_target else "",
            threshold=gate.per_target[0].threshold if gate.per_target else "",
            reason=gate.worst_reason,
            required=gate.required,
        )
        for gate in gates
    )


def orchestrate(
    *,
    skill_name: str,
    package_digest: str,
    payload_digest: str,
    criticality: str,
    profile_name: str,
    profile: ProfileSpec,
    policy_digest: str,
    readings: Sequence[SetReading],
    eval_id: str,
    created_at: str,
    bellwether_version: str,
    out_dir: Path,
    descriptive_only: bool = False,
) -> EvalResult:
    """Compose the verdict from the set readings, render, and write the artifact tree."""
    gates: list[GateResult] = []
    gates.append(_gate("evidence", [_evidence_result(r, profile) for r in readings], required=True))
    gates.append(
        _gate("functional", [_functional_result(r, profile) for r in readings], required=True)
    )
    gates.append(
        _gate("consistency", [_consistency_result(r, profile) for r in readings], required=True)
    )
    gates.append(_gate("scope", [_scope_result(r, profile) for r in readings], required=True))
    egress_required = profile.gates.security_runtime.egress_outside_allowlist == "block"
    gates.append(
        _gate(
            "security_runtime.egress",
            [_security_runtime_result(r, profile) for r in readings],
            required=egress_required,
        )
    )

    verdict = compose_verdict(tuple(gates), descriptive_only=descriptive_only)

    summary = _build_summary(
        skill_name=skill_name,
        package_digest=package_digest,
        payload_digest=payload_digest,
        criticality=criticality,
        profile_name=profile_name,
        policy_digest=policy_digest,
        readings=readings,
        verdict=verdict,
        gates=gates,
        eval_id=eval_id,
        created_at=created_at,
        bellwether_version=bellwether_version,
        descriptive_only=descriptive_only,
    )

    artifacts = write_artifact_tree(
        out_dir,
        eval_id,
        summary_json=render_summary_json(summary),
        verdict_json=_verdict_json(verdict),
        pr_comment=render_pr_comment(summary, _figures(readings)),
        traces={run.key: run.trace_jsonl for r in readings for run in r.runs},
        canonicals={run.key: run.canonical_json for r in readings for run in r.runs},
    )

    return EvalResult(
        verdict=verdict,
        summary=summary,
        artifacts=artifacts,
        exit_code=_exit_code(verdict),
    )


def _exit_code(verdict: VerdictResult) -> int:
    return 2 if verdict.verdict == "not_ready" else 0


def _verdict_json(verdict: VerdictResult) -> str:
    payload = {
        "verdict": verdict.verdict,
        "descriptive_only": verdict.descriptive_only,
        "notes": list(verdict.notes),
        "gates": [
            {
                "name": gate.name,
                "status": gate.status,
                "required": gate.required,
                "reason": gate.worst_reason,
            }
            for gate in verdict.gates
        ],
    }
    return canonical_json(payload, indent=2) + "\n"


def _primary(readings: Sequence[SetReading]) -> SetReading:
    return readings[0]


def _build_summary(
    *,
    skill_name: str,
    package_digest: str,
    payload_digest: str,
    criticality: str,
    profile_name: str,
    policy_digest: str,
    readings: Sequence[SetReading],
    verdict: VerdictResult,
    gates: Sequence[GateResult],
    eval_id: str,
    created_at: str,
    bellwether_version: str,
    descriptive_only: bool,
) -> Summary:
    primary = _primary(readings)
    targets = sorted({r.target.slug for r in readings})
    scenarios = sorted({r.scenario_id for r in readings})
    n_evaluable = sum(r.n_evaluable for r in readings)
    n_completed = sum(r.n_completed for r in readings)

    matrix = MatrixSummary(
        scenarios=len(scenarios),
        targets=len(targets),
        runs_planned=n_completed,
        runs_completed=n_completed,
        runs_evaluable=n_evaluable,
        design="sequential",
        looks=(6, 12, 20),
        descriptive_only=descriptive_only,
    )
    functional = FunctionalSummary(
        pass_rate=primary.pass_rate,
        n_evaluable=primary.n_evaluable,
        lower_bound=primary.lower_bound,
        threshold=primary.functional_threshold,
        decision={"pass": "pass", "fail": "block"}.get(primary.look_outcome, "warn"),  # type: ignore[arg-type]
        stopped_at_look=primary.look,
    )
    annotation = "consistently failing" if primary.consistently_failing else None
    consistency = ConsistencySummary(
        bci=primary.bci,
        pass_rate=primary.pass_rate,
        annotation=annotation,
        capability_jaccard_weighted=primary.jaccard_weighted,
        capability_jaccard_plain=primary.jaccard_plain,
        weights_digest=primary.weights_digest,
        components_used=("outcome", "capability", "trajectory"),
    )
    capability_profile = CapabilityProfileSummary(
        tier1={
            "core": sorted({cap for r in readings for run in r.runs for cap in run.caps_t1}),
        }
    )
    return Summary(
        eval_id=eval_id,
        created_at=created_at,
        bellwether_version=bellwether_version,
        skill=SkillRef(
            name=skill_name,
            package_digest=package_digest,
            payload_digest=payload_digest,
            criticality=criticality,  # type: ignore[arg-type]
        ),
        policy=PolicyRef(profile=profile_name, digest=policy_digest),
        matrix=matrix,
        verdict=VerdictSummary(status=verdict.verdict, gates=_gate_summaries(gates)),
        functional=functional,
        consistency=consistency,
        capability_profile=capability_profile,
        security=SecuritySummary(),
        limitations=default_limitations(),
    )


def _figures(readings: Sequence[SetReading]) -> Figures:
    """Assemble the PR-comment figures from the readings (§13.8)."""
    from bellwether.report import CapabilityRow, StripRow, TrajectoryCluster

    strip: list[StripRow] = []
    heatmap: list[CapabilityRow] = []
    clusters: list[TrajectoryCluster] = []
    run_labels: tuple[str, ...] = ()

    for reading in readings:
        cells: tuple[StripCell, ...] = tuple(_outcome_cell(run.outcome) for run in reading.runs)
        strip.append(
            StripRow(
                label=f"{reading.scenario_id}/{reading.target.model_alias}",
                cells=cells,
                n_evaluable=reading.n_evaluable,
                stopped_at_look=reading.look,
                lower_bound=reading.lower_bound,
            )
        )

    primary = readings[0]
    run_labels = tuple(f"r{i + 1}" for i in range(len(primary.runs)))
    caps_seen: dict[tuple[str, str], list[bool]] = {}
    for index, run in enumerate(primary.runs):
        for cap in run.caps_t1:
            key = ("core", cap)
            caps_seen.setdefault(key, [False] * len(primary.runs))
            caps_seen[key][index] = True
    for (tier1, cap), hits in caps_seen.items():
        heatmap.append(CapabilityRow(tier1_class=tier1, capability=cap, exercised=tuple(hits)))

    return Figures(
        strip=tuple(strip),
        clusters=tuple(clusters),
        heatmap=tuple(heatmap),
        run_labels=run_labels,
    )


#: §12.7 run outcomes map straight onto four of the five strip-chart cells; the fifth
#: (``timeout``) is a distinct exit reason the aggregate does not carry separately yet.
_CELL: Mapping[RunOutcome, StripCell] = {
    "pass": "pass",
    "fail": "fail",
    "not_evaluable": "not_evaluable",
    "excluded_quality": "excluded_quality",
}


def _outcome_cell(outcome: RunOutcome) -> StripCell:
    return _CELL.get(outcome, "not_evaluable")
