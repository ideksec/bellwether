"""Shared building blocks for every Bellwether document type."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AliasChoices, BaseModel, BeforeValidator, ConfigDict, Field, field_validator

__all__ = [
    "API_VERSION",
    "Criticality",
    "Document",
    "Severity",
    "StrictModel",
    "Target",
    "YamlWord",
]


def _yaml_bool_to_word(value: object) -> object:
    """Undo YAML 1.1's reading of ``off``/``no``/``on``/``yes`` as booleans.

    ``dns: {mode: off}`` is what a user writes and what this specification prints, but
    YAML parses the bare word as ``False``. Rejecting it with "must be one of
    'controlled_resolver' or 'off' (got False)" is a true error message that helps
    nobody. Applied to every enumeration whose members include such a word.
    """
    if value is False:
        return "off"
    if value is True:
        return "on"
    return value


#: An enumeration member that YAML 1.1 would otherwise turn into a boolean.
YamlWord = BeforeValidator(_yaml_bool_to_word)

#: The only ``apiVersion`` this build understands. A document declaring a different one
#: is rejected by name rather than by a field-by-field mismatch further down.
API_VERSION = "bellwether/v1"

Severity = Literal["low", "medium", "high", "critical"]
Criticality = Literal["low", "medium", "high"]


class StrictModel(BaseModel):
    """Base for every configuration model.

    ``extra="forbid"`` turns a typo into a named error instead of a silently ignored
    setting — which for a document like ``policy.yaml`` is the difference between a gate
    being enforced and a gate quietly not existing.

    ``frozen=True`` keeps loaded documents immutable, so no downstream module can edit a
    threshold and produce a verdict that its own recorded policy does not explain.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        protected_namespaces=(),
    )


class Document(StrictModel):
    """A top-level YAML document with an ``apiVersion`` and a ``kind``."""

    api_version: str = Field(
        validation_alias=AliasChoices("apiVersion", "api_version"),
        serialization_alias="apiVersion",
    )

    @field_validator("api_version")
    @classmethod
    def _known_api_version(cls, value: str) -> str:
        if value != API_VERSION:
            raise ValueError(f"unsupported apiVersion; this build understands {API_VERSION!r}")
        return value


class Target(StrictModel):
    """One ``(harness, provider, model)`` combination the matrix runs against (§4).

    ``model_alias`` is an alias — ``frontier``, ``mid``, ``small`` — resolved through
    ``providers`` in ``config.yaml`` (§9.5). A literal model identifier here is a bug:
    model names change, and a stale hard-coded string is the most likely source of a
    confusing first-run failure. ``policy.yaml`` spells the key ``model_alias`` and
    ``evals/manifest.yaml`` spells it ``model``; both are accepted.
    """

    harness: str
    provider: str
    model_alias: Annotated[
        str,
        Field(
            validation_alias=AliasChoices("model_alias", "model"),
            serialization_alias="model_alias",
        ),
    ]

    def label(self) -> str:
        """A stable, sortable identifier used in output and evidence links."""
        return f"{self.harness}/{self.provider}/{self.model_alias}"

    def __lt__(self, other: Target) -> bool:
        return self.label() < other.label()
