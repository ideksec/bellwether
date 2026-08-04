"""Reading and validating a Bellwether YAML document (§21).

The primitives every loader shares. Kept separate from the per-document loaders so that
those can be split by which layer consumes them: §8.1 forbids everything below
``verdict`` from importing policy types, and everything below ``harness`` from importing
provider types, and a single loader module carries both into every caller by transitive
import.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from bellwether.config.render import problems_from_validation_error
from bellwether.errors import ConfigurationError, UserFacingProblem

__all__ = [
    "CONFIG_DIR",
    "CONFIG_FILE",
    "PLATFORM_BASELINE_FILE",
    "POLICY_FILE",
    "load_yaml_mapping",
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
