"""Parsing ``SKILL.md`` frontmatter (§6.1).

Unknown frontmatter fields MUST be preserved and reported, not dropped — an unexpected
field is itself worth surfacing. This is the opposite of the rule for configuration
documents, where an unknown field is a typo and is rejected: a skill is written by
somebody else, possibly for a harness Bellwether does not model, and silently discarding
what it declares would hide exactly the thing a reviewer wants to see.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

import yaml
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
)

__all__ = [
    "Frontmatter",
    "ParsedSkillMarkdown",
    "normalize_description",
    "parse_skill_markdown",
]

#: A frontmatter block is the document's first line ``---`` through the next ``---``.
_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\r?\n(?P<body>.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)


def normalize_description(description: str) -> str:
    """Normalize a description before digesting it (§6.1).

    Unicode is normalised to NFC and runs of whitespace collapse to a single space, so a
    pure reflow of the same sentence does not change ``description_digest``. That digest
    scopes coexistence re-runs (§7.4), and the full-library trigger matrix is the most
    expensive thing Bellwether does; re-running it because someone rewrapped a paragraph
    is a cost with no signal behind it.
    """
    return " ".join(unicodedata.normalize("NFC", description).split())


class Frontmatter(BaseModel):
    """The frontmatter fields Bellwether reads, plus everything it does not.

    ``model_config`` allows extra fields deliberately: they are kept in
    :attr:`unknown_fields` and reported.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True, protected_namespaces=())

    #: Identity, and collision detection against the rest of the library.
    name: str | None = None
    #: The string that competes for activation. This is what trigger analysis measures.
    description: str | None = None
    #: Declared tool scope, compared against observed (§12.5).
    allowed_tools: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("allowed-tools", "allowed_tools", "allowedTools"),
        serialization_alias="allowed-tools",
    )
    #: A skill that pins a model interacts with the test matrix, so it is flagged.
    model: str | None = None
    #: Changes trigger semantics; scenarios must account for it.
    disable_model_invocation: bool | None = Field(
        default=None,
        validation_alias=AliasChoices("disable-model-invocation", "disable_model_invocation"),
        serialization_alias="disable-model-invocation",
    )

    @field_validator("allowed_tools", mode="before")
    @classmethod
    def _tools_may_be_a_string(cls, value: Any) -> Any:
        """Harnesses spell this both ways; accept a comma-separated string too."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def unknown_fields(self) -> dict[str, Any]:
        """Fields Bellwether does not model, preserved for reporting."""
        return dict(self.model_extra or {})

    @property
    def normalized_description(self) -> str:
        return normalize_description(self.description or "")


class ParsedSkillMarkdown(BaseModel):
    """The result of reading a ``SKILL.md``."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    frontmatter: Frontmatter | None
    body: str
    #: Problems worth reporting that are not fatal to parsing. A skill with no
    #: frontmatter still loads: recording the absence is more useful than refusing, since
    #: the absence is itself what a reviewer needs to know.
    problems: tuple[str, ...] = ()
    #: Known fields whose value was the wrong shape — ``allowed-tools: 5`` — kept by name
    #: and raw value so nothing is lost from the report. A third-party skill is
    #: attacker-influenced input, and refusing to load one is refusing to say anything
    #: about it.
    unusable_fields: dict[str, Any] = Field(default_factory=dict)

    @property
    def has_frontmatter(self) -> bool:
        return self.frontmatter is not None


def parse_skill_markdown(text: str) -> ParsedSkillMarkdown:
    """Split a ``SKILL.md`` into frontmatter and body."""
    match = _FRONTMATTER_RE.match(text)
    if match is None:
        return ParsedSkillMarkdown(
            frontmatter=None,
            body=text,
            problems=("no YAML frontmatter block; the harness has no description to trigger on",),
        )

    body = text[match.end() :]
    try:
        loaded = yaml.safe_load(match.group("body"))
    except yaml.YAMLError as exc:
        return ParsedSkillMarkdown(
            frontmatter=None,
            body=body,
            problems=(f"frontmatter is not valid YAML: {exc}",),
        )

    if loaded is None:
        return ParsedSkillMarkdown(
            frontmatter=Frontmatter(),
            body=body,
            problems=("frontmatter block is empty",),
        )
    if not isinstance(loaded, dict):
        return ParsedSkillMarkdown(
            frontmatter=None,
            body=body,
            problems=(f"frontmatter must be a mapping, not a {type(loaded).__name__}",),
        )

    frontmatter, unusable, problems = _validate_leniently(loaded)
    if not frontmatter.name:
        problems.append("frontmatter has no 'name'")
    if not frontmatter.description:
        problems.append("frontmatter has no 'description'; the skill has nothing to trigger on")
    if frontmatter.model:
        problems.append(
            f"frontmatter pins model {frontmatter.model!r}, which interacts with the test matrix"
        )
    return ParsedSkillMarkdown(
        frontmatter=frontmatter,
        body=body,
        problems=tuple(problems),
        unusable_fields=unusable,
    )


def _validate_leniently(loaded: dict[str, Any]) -> tuple[Frontmatter, dict[str, Any], list[str]]:
    """Validate frontmatter, setting aside fields whose value is the wrong shape.

    A skill is somebody else's file, and often a third party's. Letting a
    ``ValidationError`` out of here would both violate the rule that Bellwether reports
    problems as sentences rather than stack traces, and let a malformed package stop the
    loader before any sandbox exists — so a hostile skill could avoid being described at
    all by shipping ``allowed-tools: 5``.

    The offending fields are set aside by name with their raw value, so nothing is lost
    from the report; everything else still parses.
    """
    rejected: dict[str, str] = {}
    try:
        return Frontmatter.model_validate(loaded), {}, []
    except ValidationError as error:
        for detail in error.errors():
            if detail["loc"]:
                rejected[str(detail["loc"][0])] = detail["msg"]

    kept = {key: value for key, value in loaded.items() if key not in rejected}
    unusable = {key: loaded[key] for key in rejected if key in loaded}
    problems = [
        f"frontmatter field {key!r} is not usable and was ignored: {message}"
        for key, message in sorted(rejected.items())
    ]

    try:
        return Frontmatter.model_validate(kept), unusable, problems
    except ValidationError:
        # Nothing salvageable. Still not an exception: an unparseable frontmatter is a
        # finding about the skill, not a failure of the tool.
        problems.append("frontmatter could not be parsed and was ignored entirely")
        return Frontmatter(), dict(loaded), problems
