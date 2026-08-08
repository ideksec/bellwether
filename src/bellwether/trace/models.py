"""ARF — the Agent Run Format (§11.1–11.3).

One JSONL file per run. One JSON object per line. Append-only, streamable, diffable.
Line 0 is a ``run_header``; the last line, where the run finished, is a ``run_footer``;
everything between is an ``action``.

The format is deliberately vendor-neutral rather than named after the tool: v0.4 publishes
the schema separately so other tools can emit it.

**These models allow unknown fields, and that is deliberate.** It is the opposite of the
rule for configuration documents, where an unknown key is a typo and is rejected. ARF is a
wire format that other producers are meant to write; a reader that rejects a field it does
not recognise cannot read a trace from a newer writer, and dropping the field silently
would make round-tripping lossy. Unknown fields are preserved and re-emitted.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from bellwether import ARF_VERSION, CANON_VERSION
from bellwether.constants import CAPTURE_PLANES

__all__ = [
    "ARF_VERSION",
    "Action",
    "CanonBlock",
    "Capability",
    "Correlation",
    "Coverage",
    "ExitReason",
    "Instant",
    "PlaneCoverage",
    "RunFooter",
    "RunHeader",
    "ScopeBlock",
    "TokenTotals",
]

#: How a run ended (§11.1).
#:
#: ``cancelled`` is distinct from ``budget_exceeded``: the former is an abort mid-run, the
#: latter a limit detected at a turn boundary. ``pids_limit`` and ``oom`` are broken out
#: from ``sandbox_error`` because both are attributable to skill behaviour and MUST NOT be
#: retried (§13.2).
ExitReason = Literal[
    "completed",
    "timeout",
    "budget_exceeded",
    "cancelled",
    "harness_error",
    "sandbox_error",
    "pids_limit",
    "oom",
]

#: Which capture plane observed an event (§11.2).
Plane = Literal[
    "harness",
    "filesystem",
    "credentials",
    "egress",
    "dns",
    "process",
    "proxy_inferred",
    "normalizer",
]

#: Fidelity of one plane on this run (§10.7).
Fidelity = Literal["full", "partial", "overlay_diff", "unavailable", "none_offered", "disabled"]


class ArfModel(BaseModel):
    """Base for every ARF structure.

    ``extra="allow"`` keeps a trace from a newer or third-party writer readable and
    round-trippable. ``populate_by_name`` lets Python call a field what it should be
    called while the wire keeps its own spelling.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True, protected_namespaces=())


def _as_utc(value: dt.datetime) -> dt.datetime:
    """Require an instant, not a wall-clock reading, and store it in UTC.

    A naive datetime serialises with no offset, so two traces from differently-configured
    runners silently stop being comparable — and epoch anchoring (§11.5) reads these
    timestamps to assign events to epochs. Refusing the ambiguity at the boundary is
    cheaper than discovering it as jitter in the noise floor.
    """
    if value.tzinfo is None:
        raise ValueError(
            "timestamp must carry a timezone; a naive datetime is a wall-clock reading, "
            "not an instant, and traces from two runners could not be compared"
        )
    return value.astimezone(dt.UTC)


#: An instant, normalised to UTC on the way in.
Instant = Annotated[dt.datetime, AfterValidator(_as_utc)]


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


class SkillRef(ArfModel):
    """Which skill ran, and exactly which bytes of it."""

    name: str
    package_digest: str
    payload_digest: str
    source: str
    #: Every installed file with its hash. A trace that cannot say what it ran is not
    #: evidence about anything.
    files: list[dict[str, Any]] = Field(default_factory=list)


class Sampling(ArfModel):
    """Recorded, never silently set (§9.3).

    A ``temperature: 0`` run understates real variance, so Bellwether records the
    provider's own defaults rather than imposing its own.
    """

    temperature: float | None = None
    top_p: float | None = None
    seed: int | None = None


class TargetRef(ArfModel):
    """The ``(harness, provider, model)`` combination this run used."""

    harness: str
    harness_version: str | None = None
    provider: str
    model_alias: str
    #: What Bellwether asked for, and what the provider said it served. A silent model
    #: update is a primary cause of "the skill changed but the code didn't" (§9.3).
    model_id_requested: str | None = None
    model_id_reported: str | None = None
    sampling: Sampling = Field(default_factory=Sampling)
    #: Set where sampling was pinned for a low-variance comparison. Results collected this
    #: way are marked distinctly in output because they are not the realistic condition.
    deterministic_sampling: bool = False
    #: The adapter's §9.4 capabilities declaration, verbatim. Recorded so a missing
    #: signal stays distinguishable from an absent behaviour — and so the
    #: ``harness-specific: not portable`` label on trigger metrics is derivable from the
    #: trace alone.
    harness_capabilities: dict[str, Any] | None = None


class SandboxRef(ArfModel):
    image: str
    isolation: str = "docker"
    fixture: str | None = None
    #: Canary content is excluded from this digest (§9.3) — otherwise per-evaluation
    #: marker randomisation would miss the run cache on every evaluation.
    fixture_digest: str | None = None
    workspace_root: str | None = None


class PlantedCanary(ArfModel):
    """A planted canary, by reference. The value itself never appears in an artifact."""

    id: str
    path: str
    kind: str


class IdentityBlock(ArfModel):
    """What the sandbox looked like from inside, and what was planted in it."""

    uid: int | None = None
    #: Names only. A credential *value* in a trace would defeat the point of the tool.
    env_credential_names: list[str] = Field(default_factory=list)
    #: Recorded so an evaluation is reproducible from its own artifacts (§9.3).
    canary_seed: str | None = None
    canaries_planted: list[PlantedCanary] = Field(default_factory=list)
    egress_allowlist: list[str] = Field(default_factory=list)


class CanonBlock(ArfModel):
    """Canonicalization parameters, recorded because changing them invalidates analysis.

    ``traj_planes`` and ``weights_digest`` are versioned *separately* from
    ``canon_version`` (§11.4, §11.6) so that a change to either invalidates only the
    component it affects rather than every baseline in the repository. The step sequence's
    composition changes as capture planes come online; that must not wholesale-invalidate
    capability sets, pass rates, findings, and scope tables, which is where most of the
    regression value lives.
    """

    canon_version: str = CANON_VERSION
    #: Which planes contribute ordering. At overlay-diff filesystem fidelity, Plane B
    #: contributes none, so this is ``[A, C, D, E]``.
    traj_planes: list[str] = Field(default_factory=lambda: ["A", "C", "D", "E"])
    trajectory_cluster_threshold: float = 0.2
    #: Digest of the capability risk weights the BCI used (§13.5).
    weights_digest: str | None = None


class PlaneCoverage(ArfModel):
    """One plane's fidelity, and — where degraded — why.

    The reason string is not decoration. Degraded coverage is the normal condition on
    managed CI runners, and an enum alone gives a user nothing to act on.
    """

    fidelity: Fidelity
    reason: str | None = None

    def is_usable(self) -> bool:
        """Usable for a *presence* claim: the plane observed at least part of its domain,
        so a thing it did see is real evidence (§10.8)."""
        return self.fidelity in {"full", "partial", "overlay_diff"}

    def is_usable_for_absence(self) -> bool:
        """Usable for an *absence* claim, which is stricter (§10.8).

        "Nothing happened" is only meaningful at a fidelity that would have seen the
        thing had it happened. ``partial`` coverage observed only part of its domain — a
        zone it never watched could hide exactly the write or read the assertion denies —
        so it supports presence but not absence. Only ``full`` and ``overlay_diff``
        (which reads the whole post-run upper directory) can carry an absence claim.
        """
        return self.fidelity in {"full", "overlay_diff"}


class Coverage(ArfModel):
    """Which planes were active, at what fidelity (§10.7).

    Assertions that depend on an unavailable plane return ``not_evaluable``, and the
    verdict engine treats a policy requirement that cannot be evaluated as a failed gate
    rather than a passed one.
    """

    harness_events: PlaneCoverage | None = None
    filesystem_writes: PlaneCoverage | None = None
    filesystem_reads: PlaneCoverage | None = None
    credentials: PlaneCoverage | None = None
    egress: PlaneCoverage | None = None
    dns: PlaneCoverage | None = None
    process: PlaneCoverage | None = None
    server_side_tools: PlaneCoverage | None = None

    def unavailable(self) -> dict[str, str]:
        """Planes that cannot support an assertion, mapped to their reason."""
        out: dict[str, str] = {}
        for name in (*CAPTURE_PLANES, "server_side_tools"):
            plane: PlaneCoverage | None = getattr(self, name, None)
            if plane is not None and not plane.is_usable():
                out[name] = plane.reason or f"{plane.fidelity} (no reason recorded)"
        return out


class RunHeader(ArfModel):
    """Line 0 of every trace."""

    type: Literal["run_header"] = "run_header"
    arf_version: str = ARF_VERSION

    run_id: str
    eval_id: str
    scenario_id: str
    #: Cache keys use scenario *content*, not the id, so renaming a scenario does not
    #: invalidate its cached runs (§19).
    scenario_digest: str | None = None
    repetition: Annotated[int, Field(ge=1)]
    #: Which pre-registered look this repetition belongs to (§13.1).
    look: Annotated[int, Field(ge=1)] | None = None
    #: Set where this run replaces one that failed for an infrastructure reason (§13.2).
    retry_of: str | None = None
    attempt: Annotated[int, Field(ge=1)] = 1

    skill: SkillRef
    target: TargetRef
    sandbox: SandboxRef
    identity: IdentityBlock = Field(default_factory=IdentityBlock)
    platform_baseline_version: str | None = None
    canon: CanonBlock = Field(default_factory=CanonBlock)
    coverage: Coverage = Field(default_factory=Coverage)
    started_at: Instant


# ---------------------------------------------------------------------------
# Action records
# ---------------------------------------------------------------------------


class Actor(ArfModel):
    role: str | None = None
    turn: int | None = None
    agent: str | None = None


class Capability(ArfModel):
    """All three tiers, stored inline (§4.1, §11.2).

    Computed by the normalizer, not by the capture plane. Storing every tier means the
    metrics layer never re-derives them and the canonicalizer stays cheap.
    """

    tier1: str
    tier2: str | None = None
    tier3: str | None = None


class ScopeBlock(ArfModel):
    """How this action relates to the declared scope and the platform baseline."""

    declared: bool | None = None
    matched_rule: str | None = None
    #: True where the platform baseline absorbed this action (§12.6). A near-miss is
    #: flagged rather than absorbed, so this being false is meaningful.
    platform_baseline: bool = False
    canary: str | None = None


class Correlation(ArfModel):
    """Cross-plane links.

    ``anchor_seq`` is set only where a causal link is *known* rather than inferred — the
    sequence number of the Plane A tool call that caused this event (§11.5 step 3). Where
    it is set, epoch assignment uses it and ignores the timestamp entirely.
    """

    pid: int | None = None
    plane_b_event_ids: list[str] = Field(default_factory=list)
    anchor_seq: int | None = None


class Action(ArfModel):
    """One event in a trace."""

    type: Literal["action"] = "action"
    seq: Annotated[int, Field(ge=0)]
    ts: Instant
    plane: Plane
    kind: str
    actor: Actor | None = None
    #: Plane-specific payload: tool name and input, path, URL, argv. Free-form by design —
    #: the planes observe different things and forcing them into one shape would lose the
    #: detail that makes a finding actionable.
    action: dict[str, Any] = Field(default_factory=dict)
    capability: Capability | None = None
    scope: ScopeBlock | None = None
    correlation: Correlation = Field(default_factory=Correlation)


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------


class TokenTotals(ArfModel):
    """Token accounting, with cache reads and writes as separate line items (§9.3).

    Repetition 1 of a new skill is a cache miss and repetitions 2+ may not be, which makes
    totals non-comparable *within* a repetition set and makes any cost estimate built on a
    naive mean systematically wrong.
    """

    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write: int = 0

    @property
    def total(self) -> int:
        return self.input + self.output + self.cache_read + self.cache_write


class RunFooter(ArfModel):
    """The last line of a completed trace.

    Its **absence** is the signal that a run crashed: a trace whose last line is not a
    footer is incomplete, and incomplete traces are ``not_evaluable`` for every assertion
    (§11.1). This is how "append-only and streamable" and "the last line is a footer"
    coexist.
    """

    type: Literal["run_footer"] = "run_footer"
    ended_at: Instant
    wall_clock_ms: Annotated[int, Field(ge=0)]
    exit_reason: ExitReason
    tokens: TokenTotals = Field(default_factory=TokenTotals)
    estimated_cost_usd: float | None = None
    #: Both redaction passes are recorded: at capture (§10.4.3) and at teardown
    #: (§9.1 step 11), with the count and the rule that matched.
    redaction: dict[str, Any] = Field(default_factory=dict)
