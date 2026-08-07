"""Resolving a concrete run from config, policy, and a skill's manifest (§4, §9.5, §16.1).

`bellwether run` has to turn "this skill, this policy" into something executable: which
`(harness, provider, model)` targets to run, which policy profile governs them, how many
repetitions and at which look points, and — per target — the real model id and which environment
variable holds the credential. That resolution is here, pure and fully tested; the CLI command is
the thin glue that reads the environment, builds the container-backed executor, and drives it.

The order matters and the failures are deliberately loud. A skill's `criticality` selects the
profile (§16.1); the profile carries the matrix (`required_targets`, `looks`, `n_max`), which the
skill's manifest may override; each target must name a configured provider whose model alias
resolves to a real id (never a placeholder, §9.5) and whose key is actually present in the
environment. Every one of those is a first-run failure worth a clear sentence rather than a
downstream 404 or an empty result.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from bellwether.cli.orchestrator import TargetInfo
from bellwether.config.models.common import Criticality
from bellwether.config.models.config import Config
from bellwether.config.models.manifest import SkillManifest
from bellwether.config.models.policy import Policy, ProfileSpec
from bellwether.errors import BellwetherError
from bellwether.harness.provider import resolve_model

__all__ = ["ResolvedRun", "ResolvedTarget", "resolve_run"]


@dataclass(frozen=True)
class ResolvedTarget:
    """One matrix target, fully resolved and validated for a live run.

    ``api_key_env`` names the environment variable holding the credential — never the credential
    itself, which the CLI reads at execution time and hands to the broker, so no key sits in a
    resolution object that might be logged.
    """

    target: TargetInfo
    model_id: str
    api_key_env: str


@dataclass(frozen=True)
class ResolvedRun:
    """A run reduced to what the executor and orchestrator need, with everything validated."""

    profile_name: str
    profile: ProfileSpec
    targets: tuple[ResolvedTarget, ...]
    looks: tuple[int, ...]
    n_max: int


def resolve_run(
    config: Config,
    policy: Policy,
    manifest: SkillManifest | None,
    *,
    environ: Mapping[str, str],
    profile_override: str | None = None,
) -> ResolvedRun:
    """Resolve and validate a run, or raise :class:`BellwetherError` with a first-run-clear reason.

    ``profile_override`` is the CLI ``--profile`` flag; without it the skill's ``criticality`` selects
    the profile through ``policy.selection`` (§16.1). The matrix comes from the resolved profile,
    with the skill's manifest overriding the target list and the look schedule where it sets them.
    """
    criticality: Criticality = "medium"
    if manifest is not None:
        criticality = manifest.metadata.criticality

    profile_name = profile_override or policy.selection.by_criticality.get(criticality, criticality)
    try:
        profile = policy.profile(profile_name)
    except KeyError as error:
        raise BellwetherError(str(error).strip("\"'")) from None

    override = manifest.matrix if manifest is not None else None
    target_specs = (
        list(override.targets)
        if override is not None and override.targets
        else list(profile.matrix.required_targets)
    )
    if not target_specs:
        raise BellwetherError(
            f"no targets to run: policy profile '{profile_name}' declares no required_targets and "
            "the skill's manifest declares none either; a matrix needs at least one "
            "(harness, provider, model)"
        )

    looks = (
        list(override.looks)
        if override is not None and override.looks
        else list(profile.matrix.looks)
    )
    n_max = (
        override.n_max
        if override is not None and override.n_max is not None
        else profile.matrix.n_max
    )

    resolved: list[ResolvedTarget] = []
    for spec in target_specs:
        provider = config.providers.get(spec.provider)
        if provider is None:
            known = ", ".join(sorted(config.providers)) or "none"
            raise BellwetherError(
                f"target names provider '{spec.provider}', which config.yaml does not define "
                f"(configured providers: {known})"
            )
        # resolve_model raises on an unknown alias or an unfilled placeholder, with the alias named.
        model_id = resolve_model(provider, spec.model_alias, provider_name=spec.provider)
        env_name = provider.api_key_env
        if not env_name:
            raise BellwetherError(
                f"provider '{spec.provider}' sets no api_key_env; a live run needs the name of the "
                "environment variable holding its API key"
            )
        if not environ.get(env_name):
            raise BellwetherError(
                f"the API key for provider '{spec.provider}' is not available: environment variable "
                f"{env_name} is unset or empty. The key never enters config or the sandbox — the "
                "recording proxy injects it — but the host running Bellwether must hold it"
            )
        resolved.append(
            ResolvedTarget(
                target=TargetInfo(spec.harness, spec.provider, spec.model_alias),
                model_id=model_id,
                api_key_env=env_name,
            )
        )

    return ResolvedRun(
        profile_name=profile_name,
        profile=profile,
        targets=tuple(resolved),
        looks=tuple(looks),
        n_max=n_max,
    )
