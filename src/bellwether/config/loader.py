"""Loading and validating Bellwether's four document types.

Every loader returns a validated model or raises
:class:`~bellwether.errors.ConfigurationError`, which renders as sentences naming the
file and the path within it. Nothing here touches the network (§8.1).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from bellwether.config.models.config import Config
from bellwether.config.models.manifest import SkillManifest
from bellwether.config.models.provider import is_placeholder_model_id
from bellwether.config.models.scenarios import ScenarioSuite
from bellwether.config.render import problems_from_validation_error
from bellwether.errors import ConfigurationError, UserFacingProblem

__all__ = [
    "POLICY_FILE",
    "load_config",
    "load_manifest",
    "load_scenarios",
    "load_yaml_mapping",
    "parse_config",
    "parse_manifest",
    "parse_scenarios",
    "resolve_model_id",
    "validate_document",
]

#: Default locations inside a skills repository (§5).
CONFIG_DIR = Path(".bellwether")
CONFIG_FILE = CONFIG_DIR / "config.yaml"
POLICY_FILE = CONFIG_DIR / "policy.yaml"
PLATFORM_BASELINE_FILE = CONFIG_DIR / "platform-baseline.yaml"


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    """Read a YAML document that must be a mapping.

    YAML syntax errors carry a line and column; pass them through rather than reducing
    them to "invalid YAML", which is the least useful true statement available.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigurationError(path, [UserFacingProblem("", "file not found")]) from None
    except OSError as exc:
        raise ConfigurationError(
            path, [UserFacingProblem("", f"could not be read: {exc.strerror or exc}")]
        ) from None

    try:
        data = yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        where = f"line {mark.line + 1}, column {mark.column + 1}" if mark else "unknown position"
        raise ConfigurationError(
            path,
            [UserFacingProblem("", f"is not valid YAML at {where}: {exc.problem or exc}")],
        ) from None
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            path, [UserFacingProblem("", f"is not valid YAML: {exc}")]
        ) from None

    if data is None:
        raise ConfigurationError(path, [UserFacingProblem("", "is empty")])
    if not isinstance(data, dict):
        raise ConfigurationError(
            path,
            [
                UserFacingProblem(
                    "",
                    f"must be a mapping at the top level, not a {type(data).__name__}",
                    "every Bellwether document starts with 'apiVersion' and 'kind'",
                )
            ],
        )
    return data


def validate_document[ModelT: BaseModel](
    model: type[ModelT], data: dict[str, Any], source: Path | str
) -> ModelT:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(source, problems_from_validation_error(exc, model)) from None


# ---------------------------------------------------------------------------
# config.yaml
# ---------------------------------------------------------------------------


def parse_config(data: dict[str, Any], source: Path | str = "config.yaml") -> Config:
    return validate_document(Config, data, source)


def load_config(path: Path = CONFIG_FILE) -> Config:
    return parse_config(load_yaml_mapping(path), path)


def resolve_model_id(
    config: Config,
    provider: str,
    alias: str,
    *,
    source: Path | str = CONFIG_FILE,
) -> str:
    """Resolve a ``(provider, alias)`` pair to a concrete model identifier (§9.5).

    This is the only place a model identifier enters the system. A literal model string
    anywhere else is a bug: model names change, and a stale hard-coded one is the single
    most likely source of a confusing first-run failure.
    """
    provider_config = config.providers.get(provider)
    if provider_config is None:
        known = ", ".join(sorted(config.providers)) or "none are configured"
        raise ConfigurationError(
            source,
            [
                UserFacingProblem(
                    f"providers.{provider}",
                    f"provider {provider!r} is referenced but not configured",
                    f"configured providers: {known}",
                )
            ],
        )
    model_id = provider_config.models.get(alias)
    if model_id is None:
        known = ", ".join(sorted(provider_config.models))
        raise ConfigurationError(
            source,
            [
                UserFacingProblem(
                    f"providers.{provider}.models.{alias}",
                    f"model alias {alias!r} is not defined for provider {provider!r}",
                    f"aliases defined for this provider: {known}",
                )
            ],
        )
    if is_placeholder_model_id(model_id):
        raise ConfigurationError(
            source,
            [
                UserFacingProblem(
                    f"providers.{provider}.models.{alias}",
                    f"is still the shipped placeholder {model_id!r}",
                    "fill in the current model id for this alias; "
                    "Bellwether ships no model identifiers of its own because they change",
                )
            ],
        )
    return model_id


# ---------------------------------------------------------------------------
# evals/manifest.yaml and evals/scenarios.yaml
# ---------------------------------------------------------------------------


def parse_manifest(data: dict[str, Any], source: Path | str = "manifest.yaml") -> SkillManifest:
    return validate_document(SkillManifest, data, source)


def load_manifest(path: Path) -> SkillManifest:
    return parse_manifest(load_yaml_mapping(path), path)


def parse_scenarios(data: dict[str, Any], source: Path | str = "scenarios.yaml") -> ScenarioSuite:
    return validate_document(ScenarioSuite, data, source)


def load_scenarios(path: Path) -> ScenarioSuite:
    return parse_scenarios(load_yaml_mapping(path), path)
