"""``skills/<name>/evals/manifest.yaml`` — the declared scope manifest (§6.2).

This is the file that makes "declared vs observed" verification possible. It is optional
but strongly encouraged; policy may require it. Every entry in ``declared_scope`` compiles
to an assertion applied to every scenario (§12.5).

All Bellwether machinery lives under ``evals/`` so that the install-time exclusion
required by §3.5 is a single directory exclusion rather than a growing list of filenames.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from bellwether.config.models.common import Criticality, Document, StrictModel, Target

__all__ = ["DeclaredScope", "LastHumanReview", "SkillManifest"]

_DIGEST_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")


class LastHumanReview(StrictModel):
    """A review is bound to the digest it was performed against (§6.3).

    Where the current ``package_digest`` differs from the one recorded, the review gate
    evaluates to ``stale`` — which the verdict engine treats as ``not_evaluable``, which
    blocks a required gate. Editing a skill after review does not carry the approval
    forward.

    The ``reviewers`` list is documentation for humans reading the repository. Separation
    of duties is evaluated against the GitHub API, never against this file.
    """

    date: dt.date
    package_digest: str
    reviewers: list[str] = Field(default_factory=list)

    @field_validator("package_digest")
    @classmethod
    def _digest_shape(cls, value: str) -> str:
        if not value.startswith("sha256:"):
            raise ValueError(
                f"expected a digest of the form 'sha256:<64 hex chars>', got {value!r}"
            )
        return value

    def is_wellformed(self) -> bool:
        """False for a placeholder or truncated digest.

        A malformed digest is not a load error — it simply never matches, so the review
        gate evaluates to ``stale``. Failing to load here would make an unreviewed
        manifest easier to ship than a badly-typed one.
        """
        return bool(_DIGEST_RE.match(self.package_digest))

    def age_days(self, today: dt.date) -> int:
        return (today - self.date).days


class Review(StrictModel):
    last_human_review: LastHumanReview | None = None


class Metadata(StrictModel):
    owner: str
    #: Selects the policy profile via ``selection.by_criticality`` (§16.1).
    criticality: Criticality = "medium"
    review: Review | None = None


class ToolScope(StrictModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _no_contradiction(self) -> ToolScope:
        both = sorted(set(self.allow) & set(self.deny))
        if both:
            raise ValueError(f"tool(s) both allowed and denied: {', '.join(both)}")
        return self


class FilesystemScope(StrictModel):
    """Globs over exact paths, so declared-vs-observed is evaluated at tier 3 (§4.1).

    ``${WORKSPACE}`` expands to the randomised workspace root at run time; a literal
    absolute path here would not survive the randomisation of §3.5.
    """

    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)
    deny_read: list[str] = Field(default_factory=list)


class NetworkScope(StrictModel):
    #: An empty list means: this skill should make no network calls. That is a
    #: declaration, not an absence of one, and it compiles to ``no_egress`` (§12.5).
    egress_allow: list[str] = Field(default_factory=list)


class ProcessScope(StrictModel):
    allow: list[str] = Field(default_factory=list)


class CredentialScope(StrictModel):
    """Named credentials the skill legitimately needs.

    Declaring one is what separates ``legit-credential-reader`` from ``canary-thief``:
    reading a declared credential and sending nothing outward is ``canary_in_context``
    at info severity, not a leak (§10.4.1).
    """

    expects: list[str] = Field(default_factory=list)


class DeclaredScope(StrictModel):
    tools: ToolScope = Field(default_factory=ToolScope)
    filesystem: FilesystemScope = Field(default_factory=FilesystemScope)
    network: NetworkScope = Field(default_factory=NetworkScope)
    processes: ProcessScope = Field(default_factory=ProcessScope)
    credentials: CredentialScope = Field(default_factory=CredentialScope)


class Expectations(StrictModel):
    """Per-skill overrides of global policy thresholds."""

    min_pass_rate_lower_bound: Annotated[float, Field(ge=0, le=1)] | None = None
    min_capability_jaccard_weighted: Annotated[float, Field(ge=0, le=1)] | None = None
    min_bci: Annotated[float, Field(ge=0, le=100)] | None = None


class MatrixOverride(StrictModel):
    """Per-skill overrides of the global target matrix."""

    looks: list[Annotated[int, Field(ge=1)]] | None = None
    n_max: Annotated[int, Field(ge=1)] | None = None
    targets: list[Target] = Field(default_factory=list)

    @model_validator(mode="after")
    def _looks_consistent(self) -> MatrixOverride:
        if self.looks is not None:
            if sorted(set(self.looks)) != self.looks:
                raise ValueError(f"looks must be strictly increasing and unique, got {self.looks}")
            if self.n_max is not None and self.looks[-1] != self.n_max:
                raise ValueError(
                    f"the last look ({self.looks[-1]}) must equal n_max ({self.n_max})"
                )
        return self


class SkillManifest(Document):
    kind: Literal["SkillManifest"]

    metadata: Metadata
    declared_scope: DeclaredScope = Field(default_factory=DeclaredScope)
    expectations: Expectations | None = None
    matrix: MatrixOverride | None = None
