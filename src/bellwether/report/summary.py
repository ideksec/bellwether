"""The schema-versioned ``summary.json`` — the single machine-readable rollup (§17.2).

Downstream users build on ``summary.json``; the spec says so, and it means breaking its
shape is a breaking change. So the schema is a set of ``extra='forbid'`` pydantic models —
a typo in a producer becomes a named validation error rather than a silently ignored key —
and it carries an explicit :data:`SCHEMA_VERSION`.

This module renders; it does not compute (the package rule). Every number here was decided
upstream in ``metrics`` and ``verdict``; :class:`Summary` is the serialisation target they
fill, and :func:`render_summary_json` is the one function that turns it into bytes. Those
bytes go through :func:`bellwether.determinism.canonical_json`, so keys are sorted, floats
are rounded once at this boundary, and two runs over the same evaluation produce the same
file — the WP-12 done-when.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from bellwether.constants import REPORT_LIMITATIONS
from bellwether.determinism import canonical_json

__all__ = [
    "SCHEMA_VERSION",
    "CapabilityProfileSummary",
    "ComponentExclusion",
    "ConsistencySummary",
    "CostSummary",
    "CrossModelSummary",
    "FunctionalSummary",
    "GateSummary",
    "MatrixSummary",
    "NoiseFloor",
    "PolicyRef",
    "RegressionSummary",
    "SecuritySummary",
    "SkillRef",
    "Summary",
    "VerdictSummary",
    "default_limitations",
    "render_summary_json",
    "summary_json_schema",
]

#: The ``summary.json`` schema version. Bumped on any change to the shape below. A minor
#: bump adds optional keys; a major bump is a break. Producers stamp it; consumers read it
#: before trusting anything else in the file.
SCHEMA_VERSION = "1.0"


class ReportModel(BaseModel):
    """Base for every ``summary.json`` fragment.

    ``extra='forbid'`` so a producer that invents a key is caught, not silently dropped;
    ``frozen=True`` so a rendered summary cannot be edited into disagreeing with the
    verdict it was built from.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, protected_namespaces=())


class SkillRef(ReportModel):
    name: str
    package_digest: str
    payload_digest: str
    criticality: Literal["low", "medium", "high"]


class PolicyRef(ReportModel):
    profile: str
    digest: str


class MatrixSummary(ReportModel):
    """The shape of the run matrix and the sequential design it took (§13.1, §17.2).

    ``sets_stopped_at_look`` and ``sets_held_open_for_capability`` are what let a reader
    see *why* N is what it is — a set that stopped at look 1 carries a weaker claim than
    one that ran to look 3, and the report must never let the two read alike.
    """

    scenarios: int
    targets: int
    runs_planned: int
    runs_completed: int
    runs_evaluable: int
    runs_not_evaluable: int = 0
    runs_excluded_quality: int = 0
    runs_errored: int = 0
    #: Runs whose exit reason was ``timeout``. §12.7 scores a timeout as a failed run, but
    #: §24 requires it counted as a *distinct* state — a skill that never finished is not a
    #: skill that finished wrong — so it is never blended into the assertion-failure count.
    runs_timed_out: int = 0
    design: Literal["sequential", "fixed"] = "sequential"
    looks: tuple[int, ...] = ()
    boundary_z: float | None = None
    #: Look index (1-based) → number of repetition sets that stopped there.
    sets_stopped_at_look: Mapping[str, int] = Field(default_factory=dict)
    sets_held_open_for_capability: int = 0
    escalation_truncated: bool = False
    descriptive_only: bool = False


class GateSummary(ReportModel):
    """One gate as the verdict recorded it (§16.2). Mirrors ``verdict.GateResult`` in the
    flat form a consumer wants — the worst status, the observed value and threshold that
    set it, and the reason — without importing the verdict dataclasses into the schema."""

    name: str
    status: Literal["pass", "warn", "block", "not_evaluable"]
    observed: str = ""
    threshold: str = ""
    reason: str = ""
    required: bool = True


class VerdictSummary(ReportModel):
    status: Literal["ready", "conditional", "not_ready"]
    gates: tuple[GateSummary, ...] = ()
    notes: tuple[str, ...] = ()


class FunctionalSummary(ReportModel):
    """The pass-rate gate reading (§13.1). The gate is the Wilson **lower bound**, never
    the point estimate — both travel so the report can render them adjacent and a reader
    cannot mistake ``0.86`` for the number that cleared the threshold."""

    pass_rate: float
    n_evaluable: int
    lower_bound: float
    threshold: float
    decision: Literal["pass", "warn", "block", "not_evaluable"]
    ci_nominal: tuple[float, float] | None = None
    ci_boundary: tuple[float, float] | None = None
    #: Which look the set stopped at, so ``n_evaluable`` is legible as strong or weak.
    stopped_at_look: int | None = None
    per_target: Mapping[str, object] = Field(default_factory=dict)


class ComponentExclusion(ReportModel):
    name: str
    reason: str


class ConsistencySummary(ReportModel):
    """The BCI and its breakdown (§13.7). ``annotation`` carries "consistently failing"
    wherever the pass rate is below 0.5 — the composite must never be read as quality when
    it is measuring the consistency of *failure* — and ``pass_rate`` travels with it so no
    surface can render the BCI alone (§13.3)."""

    bci: float
    pass_rate: float
    annotation: str | None = None
    components: Mapping[str, float] = Field(default_factory=dict)
    capability_jaccard_weighted: float | None = None
    capability_jaccard_plain: float | None = None
    weights_digest: str = ""
    components_used: tuple[str, ...] = ()
    components_excluded: tuple[ComponentExclusion, ...] = ()
    weights_normalised_over: float | None = None
    per_scenario: Mapping[str, object] = Field(default_factory=dict)
    #: §13.4: mean pairwise trajectory edit distance — present **only** when it is above
    #: the calibrated §24 noise floor. At or below the floor the number is withheld here
    #: (``None``) and ``trajectory_at_noise_floor`` is set instead: the instrument produces
    #: that dispersion on identical input, so rendering it as a measurement of the skill
    #: would be a fabrication. Encoding the rule in the data keeps every surface honest at
    #: once — a renderer cannot print a number the summary does not carry.
    trajectory_dispersion: float | None = None
    trajectory_at_noise_floor: bool = False
    #: The number of §13.4 trajectory clusters in the primary set — "many clusters, stable
    #: tier-1 capabilities" is the §24 signature of a benign-but-chaotic skill.
    trajectory_clusters: int = 0


class CapabilityProfileSummary(ReportModel):
    """All three tiers (§13.5). ``rare_high_risk`` is the frequency-independent gate's
    output and is never averaged into the smooth capability component — a single rare
    high-risk capability blocks regardless of how few runs exercised it."""

    tier1: Mapping[str, object] = Field(default_factory=dict)
    tier2: Mapping[str, object] = Field(default_factory=dict)
    tier3: Mapping[str, object] = Field(default_factory=dict)
    rare_high_risk: tuple[Mapping[str, object], ...] = ()


class CrossModelSummary(ReportModel):
    """§14. ``planes_intersected`` records the coverage-class restriction: divergence is
    computed only over planes active in **both** targets, so a smaller capability set on a
    less-instrumented target is not misreported as a portability finding."""

    divergence: Mapping[str, object] = Field(default_factory=dict)
    portability_findings: tuple[Mapping[str, object], ...] = ()
    planes_intersected: tuple[str, ...] = ()


class SecuritySummary(ReportModel):
    static: Mapping[str, object] = Field(default_factory=dict)
    runtime: Mapping[str, object] = Field(default_factory=dict)
    canary_leaks: tuple[Mapping[str, object], ...] = ()


class RegressionSummary(ReportModel):
    baseline_digest: str = ""
    deltas: Mapping[str, object] = Field(default_factory=dict)


class CostSummary(ReportModel):
    usd: float = 0.0
    tokens: Mapping[str, int] = Field(default_factory=dict)
    cache_read_tokens: int = 0
    wall_clock_s: float = 0.0


class NoiseFloor(ReportModel):
    trajectory: float
    calibrated_at: str


class Summary(ReportModel):
    """The top-level ``summary.json`` (§17.2).

    ``limitations`` is required and rendered verbatim from :data:`REPORT_LIMITATIONS`; a
    summary that ships without the §2 footer oversells by omission.
    """

    eval_id: str
    created_at: str
    bellwether_version: str
    skill: SkillRef
    policy: PolicyRef
    matrix: MatrixSummary
    verdict: VerdictSummary
    functional: FunctionalSummary
    consistency: ConsistencySummary
    capability_profile: CapabilityProfileSummary
    security: SecuritySummary
    limitations: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION
    canon_version: str = "1"
    platform_baseline_version: str = ""
    noise_floor: NoiseFloor | None = None
    crossmodel: CrossModelSummary | None = None
    regression: RegressionSummary | None = None
    cost: CostSummary | None = None


def render_summary_json(summary: Summary) -> str:
    """Serialise a :class:`Summary` to the canonical ``summary.json`` bytes.

    Goes through :func:`canonical_json`, so keys are sorted, floats are rounded once here,
    and the output is byte-identical across runs over the same evaluation. A trailing
    newline keeps the file POSIX-clean and its git diffs stable.
    """
    payload = summary.model_dump(mode="json")
    return canonical_json(payload, indent=2) + "\n"


def summary_json_schema() -> dict[str, object]:
    """The JSON Schema for ``summary.json``, for downstream consumers in other languages.

    Derived from the pydantic model so it cannot drift from what is actually emitted.
    """
    schema: dict[str, object] = Summary.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = f"Bellwether summary.json (schema {SCHEMA_VERSION})"
    return schema


def default_limitations() -> tuple[str, ...]:
    """The §2 limitations every summary must carry (§17.2). Exposed so a producer fills
    ``Summary.limitations`` from one authority rather than retyping the footer."""
    return REPORT_LIMITATIONS
