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
from bellwether.config.models.policy import Policy
from bellwether.config.models.provider import is_placeholder_model_id
from bellwether.config.models.scenarios import ScenarioSuite
from bellwether.config.render import problems_from_validation_error
from bellwether.errors import ConfigurationError, UserFacingProblem

__all__ = [
    "load_config",
    "load_manifest",
    "load_policy",
    "load_scenarios",
    "load_yaml_mapping",
    "parse_config",
    "parse_manifest",
    "parse_policy",
    "parse_scenarios",
    "resolve_model_id",
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


def _validate[ModelT: BaseModel](
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
    return _validate(Config, data, source)


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
# policy.yaml
# ---------------------------------------------------------------------------


def _deep_merge(base: Any, override: Any) -> Any:
    """Recursively merge ``override`` over ``base``. Lists replace, they do not append.

    A profile that raises one threshold must not silently drop every other gate. YAML's
    own merge key (``<<: *defaults``) is a *shallow* merge, so ``medium``'s two-key
    ``gates`` block would replace the whole default gate set — turning a profile that
    reads as "stricter" into one that enforces almost nothing. Applying the defaults
    again, deeply, is what makes the documented semantics true.

    Lists replace rather than concatenate because a profile narrowing ``block_on`` to a
    shorter list means the shorter list.
    """
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            merged[key] = _deep_merge(base.get(key), value) if key in base else value
        return merged
    return override


def parse_policy(data: dict[str, Any], source: Path | str = "policy.yaml") -> Policy:
    """Validate a policy document, resolving profile inheritance first."""
    raw = dict(data)
    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise ConfigurationError(
            source, [UserFacingProblem("defaults", "must be a mapping of profile settings")]
        )
    profiles = raw.get("profiles") or {}
    if profiles and not isinstance(profiles, dict):
        raise ConfigurationError(
            source, [UserFacingProblem("profiles", "must be a mapping of profile name to settings")]
        )
    resolved: dict[str, Any] = {}
    for name, profile in profiles.items():
        if profile is None:
            resolved[name] = dict(defaults)
        elif isinstance(profile, dict):
            resolved[name] = _deep_merge(defaults, profile)
        else:
            raise ConfigurationError(
                source,
                [UserFacingProblem(f"profiles.{name}", "must be a mapping of profile settings")],
            )
    if resolved:
        raw["profiles"] = resolved
    return _validate(Policy, raw, source)


def load_policy(path: Path = POLICY_FILE) -> Policy:
    return parse_policy(load_yaml_mapping(path), path)


# ---------------------------------------------------------------------------
# evals/manifest.yaml and evals/scenarios.yaml
# ---------------------------------------------------------------------------


def parse_manifest(data: dict[str, Any], source: Path | str = "manifest.yaml") -> SkillManifest:
    return _validate(SkillManifest, data, source)


def load_manifest(path: Path) -> SkillManifest:
    return parse_manifest(load_yaml_mapping(path), path)


def parse_scenarios(data: dict[str, Any], source: Path | str = "scenarios.yaml") -> ScenarioSuite:
    return _validate(ScenarioSuite, data, source)


def load_scenarios(path: Path) -> ScenarioSuite:
    return parse_scenarios(load_yaml_mapping(path), path)
