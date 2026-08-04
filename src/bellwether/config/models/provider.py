"""Provider configuration (§9.5).

Providers are configured, never hard-coded. Scenarios and policy refer to aliases —
``frontier``, ``mid``, ``small`` — and those aliases resolve here. This keeps test
definitions stable across model releases and is essential for the project's longevity.

This lives in its own module so ``.importlinter`` can forbid :mod:`bellwether.sandbox`
from importing it: the sandbox must not know about models (§8.1).
"""

from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from bellwether.config.models.common import StrictModel

__all__ = ["PLACEHOLDER_MARKERS", "ProviderConfig", "is_placeholder_model_id"]

#: Substrings that mark a model id the user has not filled in yet. The shipped config
#: template deliberately contains these so a first run fails with a sentence naming the
#: alias and the file, rather than with a provider 404.
PLACEHOLDER_MARKERS = ("<fill in", "<configured", "TODO", "CHANGEME")


def is_placeholder_model_id(model_id: str) -> bool:
    """True where a model id is still the shipped placeholder."""
    return any(marker.lower() in model_id.lower() for marker in PLACEHOLDER_MARKERS)


class ProviderConfig(StrictModel):
    """One configured model provider.

    Attributes:
        type: ``anthropic`` or ``openai_compatible``. Adding a provider means adding a
            type here and an implementation in :mod:`bellwether.harness`, not scattering
            endpoint knowledge through the codebase.
        base_url: Required for ``openai_compatible``; the whole point of that type is
            that the endpoint is not known in advance.
        api_key_env: Name of the environment variable holding the credential. The value
            itself never appears in configuration, and never reaches the sandbox — the
            recording proxy injects it (§3.3, critical invariant 1).
        models: Alias to model identifier. Aliases are what scenarios and policy name.
    """

    type: Literal["anthropic", "openai_compatible"]
    base_url: str | None = None
    api_key_env: str | None = None
    models: dict[str, str]

    @model_validator(mode="after")
    def _check(self) -> ProviderConfig:
        if self.type == "openai_compatible" and not self.base_url:
            raise ValueError("providers of type 'openai_compatible' require a 'base_url'")
        if not self.models:
            raise ValueError(
                "at least one model alias is required; "
                "scenarios and policy refer to aliases such as 'frontier', 'mid', 'small'"
            )
        return self

    def unfilled_aliases(self) -> list[str]:
        """Aliases still holding a placeholder identifier, sorted."""
        return sorted(alias for alias, mid in self.models.items() if is_placeholder_model_id(mid))
