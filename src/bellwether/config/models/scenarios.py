"""``skills/<name>/evals/scenarios.yaml`` — scenario and assertion definitions (§7)."""

from __future__ import annotations

import difflib
import re
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from bellwether.config.models.common import Document, StrictModel
from bellwether.constants import ASSERTION_CATALOGUE

__all__ = ["AssertionSpec", "Scenario", "ScenarioSuite"]

Expectation = Literal["should_trigger", "should_not_trigger", "ambiguous"]

#: Scenario ids are keys across runs and across baselines. Renaming one breaks baseline
#: continuity, so the shape is constrained and renames are warned about at diff time.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class AssertionSpec(StrictModel):
    """One assertion, written in YAML as a single-key mapping.

    ``- no_egress: true`` and ``- tool_called: {name: Read, min: 1}`` are both this.
    Parameters are kept as loaded and validated by :mod:`bellwether.assertions`, which
    owns their semantics; what is checked here is that the assertion *exists*, so a typo
    fails at load rather than silently never firing.
    """

    name: str
    params: Any = None

    @model_validator(mode="before")
    @classmethod
    def _from_single_key_mapping(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            raise ValueError(
                "each assertion must be a mapping of one assertion name to its "
                f"parameters, e.g. '- no_egress: true'; got {type(value).__name__}"
            )
        if set(value) == {"name", "params"}:
            return value
        if len(value) != 1:
            raise ValueError(
                "each list entry must hold exactly one assertion; "
                f"got {len(value)} keys ({', '.join(sorted(map(str, value)))}). "
                "Write them as separate list entries."
            )
        name, params = next(iter(value.items()))
        return {"name": name, "params": params}

    @model_validator(mode="after")
    def _known_assertion(self) -> AssertionSpec:
        if self.name not in ASSERTION_CATALOGUE:
            close = difflib.get_close_matches(self.name, ASSERTION_CATALOGUE, n=3, cutoff=0.6)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            raise ValueError(
                f"unknown assertion {self.name!r}.{hint} "
                f"Known assertions: {', '.join(ASSERTION_CATALOGUE)}"
            )
        return self


class ScenarioDefaults(StrictModel):
    fixture: str | None = None
    timeout_seconds: Annotated[int, Field(ge=1)] = 900
    looks: list[Annotated[int, Field(ge=1)]] | None = None
    n_max: Annotated[int, Field(ge=1)] | None = None


class Scenario(StrictModel):
    """One test case: a task prompt, a starting workspace fixture, and assertions."""

    id: str
    expectation: Expectation
    #: A list of turns runs multi-turn with the harness session preserved (§7.3).
    prompt: str | list[str]
    fixture: str | None = None
    #: Other skills loaded alongside, for coexistence testing (§7.4).
    also_load_skills: list[str] = Field(default_factory=list)
    #: Environment variables set in the sandbox. Values may be canaries.
    env: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: Annotated[int, Field(ge=1)] | None = None
    looks: list[Annotated[int, Field(ge=1)]] | None = None
    n_max: Annotated[int, Field(ge=1)] | None = None
    #: Marks this scenario for use by the coexistence matrix (§7.4).
    probe: Literal["activation", "representative"] | None = None
    tags: list[str] = Field(default_factory=list)
    #: Adversarial content placement (§7.5, v0.3). Accepted and recorded now so suites
    #: written today still load once the feature lands.
    inject: dict[str, Any] | None = None
    assertions: Annotated[
        list[AssertionSpec],
        Field(validation_alias="assert", serialization_alias="assert"),
    ]

    @model_validator(mode="after")
    def _check(self) -> Scenario:
        if not _ID_RE.match(self.id):
            raise ValueError(
                f"scenario id {self.id!r} must be lower-case and start with a letter or "
                "digit, using only letters, digits, '.', '_' and '-'"
            )
        if isinstance(self.prompt, list) and not self.prompt:
            raise ValueError("a multi-turn prompt needs at least one turn")
        if not self.assertions:
            raise ValueError(
                "at least one assertion is required; a scenario that asserts nothing "
                "produces a run but no evidence. Use 'record_only' to observe without failing."
            )
        if self.expectation == "ambiguous":
            failing = [a.name for a in self.assertions if a.name != "record_only"]
            if failing:
                raise ValueError(
                    "an 'ambiguous' scenario must not carry failing assertions "
                    f"({', '.join(sorted(set(failing)))}); record the activation rate with "
                    "'record_only' instead of failing on either outcome"
                )
        return self


class ScenarioSuite(Document):
    kind: Literal["ScenarioSuite"]

    defaults: ScenarioDefaults = Field(default_factory=ScenarioDefaults)
    scenarios: list[Scenario]

    @model_validator(mode="after")
    def _unique_ids(self) -> ScenarioSuite:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for scenario in self.scenarios:
            if scenario.id in seen:
                duplicates.add(scenario.id)
            seen.add(scenario.id)
        if duplicates:
            raise ValueError(
                f"duplicate scenario id(s): {', '.join(sorted(duplicates))}; "
                "ids are keys across runs and baselines and must be unique in a suite"
            )
        if not self.scenarios:
            raise ValueError("a scenario suite with no scenarios produces no evidence")
        return self

    def by_id(self, scenario_id: str) -> Scenario:
        for scenario in self.scenarios:
            if scenario.id == scenario_id:
                return scenario
        known = ", ".join(sorted(s.id for s in self.scenarios))
        raise KeyError(f"no scenario with id {scenario_id!r}; this suite defines: {known}")
