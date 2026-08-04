"""Loading ``.bellwether/config.yaml`` and resolving model aliases (§21, §9.5).

Separate from the other loaders because it is the only one that touches provider types,
and §8.1 forbids :mod:`bellwether.sandbox` from knowing about models. A shared loader
module would carry them there by transitive import — the sandbox could not *act* on them,
but the boundary would exist only in prose.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bellwether.config.document import CONFIG_FILE, load_yaml_mapping, validate_document
from bellwether.config.models.config import Config
from bellwether.config.models.provider import is_placeholder_model_id
from bellwether.errors import ConfigurationError, UserFacingProblem

__all__ = ["load_config", "parse_config", "resolve_model_id"]


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
