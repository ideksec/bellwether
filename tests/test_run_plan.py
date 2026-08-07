"""Resolving a run from config, policy, and a manifest (§4, §9.5, §16.1).

Pure resolution: which targets, which profile, how many repetitions, and — per target — the real
model id and which env var holds the key. Every failure a first run could hit (unknown provider,
placeholder model, unset key, empty matrix) is asserted to raise a clear sentence rather than defer
to a downstream 404 or an empty result.
"""

from __future__ import annotations

import pytest

from bellwether.cli.run_plan import resolve_run
from bellwether.config.models.common import Target
from bellwether.config.models.config import Config, SandboxConfig
from bellwether.config.models.manifest import (
    MatrixOverride,
    Metadata,
    SkillManifest,
)
from bellwether.config.models.policy import MatrixSpec, Policy, ProfileSpec, Selection
from bellwether.config.models.provider import ProviderConfig
from bellwether.errors import BellwetherError

_IMAGE = "img@sha256:" + "d" * 64
_KEY_ENV = "ANTHROPIC_API_KEY"
_ENVIRON = {_KEY_ENV: "sk-real-value"}
_API = {"apiVersion": "bellwether/v1"}


def _config(**models: str) -> Config:
    return Config(
        **_API,
        kind="Config",
        providers={
            "anthropic": ProviderConfig(
                type="anthropic",
                api_key_env=_KEY_ENV,
                models=models or {"frontier": "a-real-model-id", "small": "another-real-id"},
            )
        },
        sandbox=SandboxConfig(image=_IMAGE),
    )


def _target(alias: str = "frontier") -> Target:
    return Target(harness="api-loop", provider="anthropic", model_alias=alias)


def _policy(*, targets: list[Target] | None = None, profiles: list[str] = ("low",)) -> Policy:
    matrix = MatrixSpec(required_targets=targets if targets is not None else [_target()])
    return Policy(
        **_API,
        kind="Policy",
        profiles={name: ProfileSpec(matrix=matrix) for name in profiles},
        selection=Selection(by_criticality={"low": "low", "medium": "low", "high": "low"}),
    )


def _manifest(*, criticality: str = "low", matrix: MatrixOverride | None = None) -> SkillManifest:
    return SkillManifest(
        **_API,
        kind="SkillManifest",
        metadata=Metadata(owner="team", criticality=criticality),  # type: ignore[arg-type]
        matrix=matrix,
    )


# ---------------------------------------------------------------------------
# the happy path
# ---------------------------------------------------------------------------


def test_a_valid_run_resolves_target_model_and_key_env() -> None:
    resolved = resolve_run(_config(), _policy(), _manifest(), environ=_ENVIRON)

    assert resolved.profile_name == "low"
    assert len(resolved.targets) == 1
    only = resolved.targets[0]
    assert only.target.slug  # a real slug
    assert only.model_id == "a-real-model-id"  # alias resolved through config
    assert only.api_key_env == _KEY_ENV  # the env var name, never the key itself
    assert resolved.looks == (6, 12, 20)
    assert resolved.n_max == 20


def test_criticality_selects_the_profile_and_an_override_wins() -> None:
    policy = _policy(profiles=["low", "high"])
    # criticality high → selection maps it to 'low' here, so 'low' is chosen...
    assert (
        resolve_run(_config(), policy, _manifest(criticality="high"), environ=_ENVIRON).profile_name
        == "low"
    )
    # ...unless --profile overrides it outright.
    over = resolve_run(_config(), policy, _manifest(), environ=_ENVIRON, profile_override="high")
    assert over.profile_name == "high"


# ---------------------------------------------------------------------------
# the manifest overrides the profile matrix
# ---------------------------------------------------------------------------


def test_a_manifest_target_list_overrides_the_profile_matrix() -> None:
    config = _config(frontier="a-real-model-id", small="another-real-id")
    manifest = _manifest(matrix=MatrixOverride(targets=[_target("small")]))
    resolved = resolve_run(
        config, _policy(targets=[_target("frontier")]), manifest, environ=_ENVIRON
    )
    assert [t.target.model_alias for t in resolved.targets] == ["small"]


def test_a_manifest_look_schedule_overrides_the_profile() -> None:
    manifest = _manifest(matrix=MatrixOverride(looks=[4, 8], n_max=8))
    resolved = resolve_run(_config(), _policy(), manifest, environ=_ENVIRON)
    assert resolved.looks == (4, 8)
    assert resolved.n_max == 8


# ---------------------------------------------------------------------------
# the loud first-run failures
# ---------------------------------------------------------------------------


def test_an_empty_matrix_is_refused() -> None:
    with pytest.raises(BellwetherError, match="no targets to run"):
        resolve_run(_config(), _policy(targets=[]), _manifest(), environ=_ENVIRON)


def test_a_target_naming_an_unconfigured_provider_is_refused() -> None:
    policy = _policy(
        targets=[Target(harness="api-loop", provider="mystery", model_alias="frontier")]
    )
    with pytest.raises(BellwetherError, match="does not define"):
        resolve_run(_config(), policy, _manifest(), environ=_ENVIRON)


def test_a_placeholder_model_is_refused_by_name() -> None:
    config = _config(frontier="<fill in a real model id>")
    with pytest.raises(BellwetherError, match="frontier"):
        resolve_run(config, _policy(), _manifest(), environ=_ENVIRON)


def test_an_unset_api_key_is_refused_naming_the_env_var() -> None:
    with pytest.raises(BellwetherError, match=_KEY_ENV):
        resolve_run(_config(), _policy(), _manifest(), environ={})  # key not present


def test_the_key_is_never_placed_in_the_resolution_object() -> None:
    """ResolvedTarget carries the env var name, not the secret — nothing to leak if it is logged."""
    resolved = resolve_run(_config(), _policy(), _manifest(), environ=_ENVIRON)
    assert "sk-real-value" not in repr(resolved)
