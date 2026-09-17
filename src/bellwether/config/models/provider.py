"""Provider configuration (§9.5).

Providers are configured, never hard-coded. Scenarios and policy refer to aliases —
``frontier``, ``mid``, ``small`` — and those aliases resolve here. This keeps test
definitions stable across model releases and is essential for the project's longevity.

This lives in its own module so ``.importlinter`` can forbid :mod:`bellwether.sandbox`
from importing it: the sandbox must not know about models (§8.1).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import Field, model_validator

from bellwether.config.models.common import StrictModel

__all__ = ["PLACEHOLDER_MARKERS", "ModelPricing", "ProviderConfig", "is_placeholder_model_id"]

#: Substrings that mark a model id the user has not filled in yet. The shipped config
#: template deliberately contains these so a first run fails with a sentence naming the
#: alias and the file, rather than with a provider 404.
PLACEHOLDER_MARKERS = ("<fill in", "<configured", "TODO", "CHANGEME")


def is_placeholder_model_id(model_id: str) -> bool:
    """True where a model id is still the shipped placeholder."""
    return any(marker.lower() in model_id.lower() for marker in PLACEHOLDER_MARKERS)


class ModelPricing(StrictModel):
    """What one model alias costs, in USD per million tokens, by token kind (§9.3, §19.1).

    The four kinds are priced separately because a naive per-token mean misprices a matrix
    whose first run is a cache miss and whose remainder are hits. Pricing is configuration,
    never code: a literal price in the codebase would rot the moment a provider changed it,
    and the cost gate (§16.2) is composed only for targets whose alias is priced here — an
    unpriced target is *disclosed* as unpriced, never charged at a guessed rate.
    """

    input_usd_per_mtok: Annotated[float, Field(ge=0)]
    output_usd_per_mtok: Annotated[float, Field(ge=0)]
    cache_read_usd_per_mtok: Annotated[float, Field(ge=0)] = 0.0
    cache_write_usd_per_mtok: Annotated[float, Field(ge=0)] = 0.0

    def cost_usd(self, tokens: Mapping[str, int]) -> float:
        """The cost of a token total (``input``/``output``/``cache_read``/``cache_write``).

        A kind the mapping omits counts as zero. Unrounded: rounding happens once, at the
        serialisation boundary (§24).
        """
        return (
            tokens.get("input", 0) * self.input_usd_per_mtok
            + tokens.get("output", 0) * self.output_usd_per_mtok
            + tokens.get("cache_read", 0) * self.cache_read_usd_per_mtok
            + tokens.get("cache_write", 0) * self.cache_write_usd_per_mtok
        ) / 1_000_000


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
        pricing: Alias to :class:`ModelPricing`, optional per alias. What lets the §16.2
            cost gate turn reported token usage into dollars; an alias with no entry is
            reported as unpriced and the cost gate is not composed for it.
    """

    type: Literal["anthropic", "openai_compatible"]
    base_url: str | None = None
    api_key_env: str | None = None
    models: dict[str, str]
    pricing: dict[str, ModelPricing] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> ProviderConfig:
        if self.type == "openai_compatible" and not self.base_url:
            raise ValueError("providers of type 'openai_compatible' require a 'base_url'")
        if not self.models:
            raise ValueError(
                "at least one model alias is required; "
                "scenarios and policy refer to aliases such as 'frontier', 'mid', 'small'"
            )
        unknown = sorted(alias for alias in self.pricing if alias not in self.models)
        if unknown:
            raise ValueError(
                f"pricing names alias(es) not defined under models: {', '.join(unknown)}; "
                "a price for an alias no target can resolve is a misconfiguration, not a default"
            )
        return self

    def pricing_for(self, alias: str) -> ModelPricing | None:
        """The configured pricing for ``alias``, or ``None`` where it is unpriced."""
        return self.pricing.get(alias)

    def unfilled_aliases(self) -> list[str]:
        """Aliases still holding a placeholder identifier, sorted."""
        return sorted(alias for alias, mid in self.models.items() if is_placeholder_model_id(mid))
