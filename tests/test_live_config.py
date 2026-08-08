"""The live smoke config resolves (§9.5, §16.1) — guarded so it cannot silently rot.

`examples/live/` holds the cheap config the live CI run uses: api-loop + Haiku, one look of
6, egress advisory. This does not call the model (that needs a key and a container); it pins
that the config and policy still load and resolve to exactly that one cheap target, so a schema
change breaks this test rather than a first live run that costs money to discover.
"""

from __future__ import annotations

from pathlib import Path

from bellwether.cli.run_plan import resolve_run
from bellwether.config import load_config, load_policy
from bellwether.skill import load_skill

_LIVE = Path("examples/live")


def test_the_live_config_resolves_to_one_cheap_haiku_target() -> None:
    config = load_config(_LIVE / "config.yaml")
    policy = load_policy(_LIVE / "policy.yaml")
    package = load_skill(Path("examples/skills/benign-note-taker"), load_evals=True)

    resolved = resolve_run(
        config, policy, package.manifest, environ={"ANTHROPIC_API_KEY": "sk-fake-not-used"}
    )

    assert resolved.profile_name == "low"
    assert resolved.n_max == 6
    assert resolved.looks == (6,)
    assert len(resolved.targets) == 1
    target = resolved.targets[0]
    assert (target.target.harness, target.target.provider, target.target.model_alias) == (
        "api-loop",
        "anthropic",
        "haiku",
    )
    # A real model id, never the shipped placeholder, and the key read by name only.
    assert target.model_id and "<" not in target.model_id
    assert target.api_key_env == "ANTHROPIC_API_KEY"


def test_the_live_config_turns_the_recording_proxy_on() -> None:
    """The whole point of the live smoke run now: egress is *observed*. `egress.image` is set, so
    `build_proxy_provider` yields a real provider — the sandbox is stood up behind the dual-homed
    sidecar and a clean benign run can reach `ready` instead of `conditional`. If this config rots
    back to proxy-off, this fails rather than a first live run quietly returning `conditional`."""
    from bellwether.cli.run import build_proxy_provider

    config = load_config(_LIVE / "config.yaml")
    assert config.egress.image, "the live config must set egress.image to observe egress"
    provider = build_proxy_provider(config)
    assert provider is not None
    # The api-loop model runs host-side, so the sandbox is handed no credential (§3.3 invariant 1).
    assert provider.broker.ready_providers() == []


def test_egress_stays_advisory_for_the_first_live_proof() -> None:
    """The proxy is wired now, so egress is observed — but the smoke policy keeps
    `egress_outside_allowlist` at `warn` rather than `block` for the first live proof: a benign
    run is clean either way (an observed-clean plane passes), and `warn` means a surprise flow in
    the shakeout does not turn the run red before the pipeline itself is trusted. Promoting to
    `block` is a deliberate follow-up once the benign run is confirmed clean (§25)."""
    policy = load_policy(_LIVE / "policy.yaml")
    profile = policy.profile("low")
    assert profile.gates.security_runtime.egress_outside_allowlist == "warn"
