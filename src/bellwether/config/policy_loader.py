"""Loading ``policy.yaml`` (§16.1).

Policy has its own loader module rather than living with the other three document types,
because it is the one document only the verdict layer consumes. §8.1 forbids every layer
below ``verdict`` from importing policy types, and a shared loader module would carry
them into ``skill``, ``sandbox`` and everything else by transitive import. The boundary is
visible in the file tree, not only in a lint configuration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bellwether.config.document import POLICY_FILE, load_yaml_mapping, validate_document
from bellwether.config.models.policy import Policy
from bellwether.errors import ConfigurationError, UserFacingProblem

__all__ = ["load_policy", "parse_policy"]


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
    return validate_document(Policy, raw, source)


def load_policy(path: Path = POLICY_FILE) -> Policy:
    return parse_policy(load_yaml_mapping(path), path)
