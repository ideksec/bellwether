"""The live **claude-code** smoke config resolves (§9.5, §16.1, §3.3) — guarded so it cannot
silently rot.

`examples/live/config-claude-code.yaml` + `policy-claude-code.yaml` hold the cheap config the
live *claude-code* CI run uses: the real CLI inside the sandbox, one Haiku target at a single look
of 6, egress/DNS advisory. This does not call the model (that needs a key and a container); it
pins the two things a first paid run would otherwise discover the hard way:

- the config and policy still resolve to exactly that one cheap claude-code target, and
- unlike api-loop (whose model runs host-side, so the sandbox is handed no credential), the
  claude-code proxy provider *brokers a real key* into the sidecar — because the CLI's model
  calls originate inside the sandbox and have no route out but the proxy (§3.3 invariant 1).

A schema change breaks this test rather than a first live run that costs money to discover.
"""

from __future__ import annotations

from pathlib import Path

from bellwether.cli.run import build_proxy_provider, claude_code_providers
from bellwether.cli.run_plan import resolve_run
from bellwether.config import load_config, load_policy
from bellwether.skill import load_skill

_LIVE = Path("examples/live")
_SKILL = Path("examples/skills/claude-code-live-smoke")


def test_the_claude_code_live_config_resolves_to_one_cheap_haiku_target() -> None:
    config = load_config(_LIVE / "config-claude-code.yaml")
    policy = load_policy(_LIVE / "policy-claude-code.yaml")
    package = load_skill(_SKILL, load_evals=True)

    resolved = resolve_run(
        config, policy, package.manifest, environ={"ANTHROPIC_API_KEY": "sk-fake-not-used"}
    )

    assert resolved.profile_name == "low"
    assert resolved.n_max == 6
    assert resolved.looks == (6,)
    assert len(resolved.targets) == 1
    target = resolved.targets[0]
    assert (target.target.harness, target.target.provider, target.target.model_alias) == (
        "claude-code",
        "anthropic",
        "haiku",
    )
    # A real model id, never the shipped placeholder, and the key read by name only.
    assert target.model_id and "<" not in target.model_id
    assert target.api_key_env == "ANTHROPIC_API_KEY"


def test_the_proxy_brokers_a_real_key_into_the_claude_code_sandbox() -> None:
    """The load-bearing difference from the api-loop live config: the CLI runs *inside* the
    sandbox, so the proxy must inject a real key (as a scoped token) — the sandbox is not handed
    the raw key, but the broker must be *ready* to swap the scoped token for it (§3.3 invariant 1).
    If this config rots back to a harness whose model runs host-side, or drops `egress.image`, this
    fails rather than a first labelled live run discovering the CLI cannot reach any model."""
    config = load_config(_LIVE / "config-claude-code.yaml")
    policy = load_policy(_LIVE / "policy-claude-code.yaml")
    package = load_skill(_SKILL, load_evals=True)

    assert config.egress.image, "the claude-code live config must set egress.image (proxy required)"

    # The providers a claude-code target names are exactly the ones brokered a key.
    providers = claude_code_providers(policy, package.manifest)
    assert providers == frozenset({"anthropic"})

    provider = build_proxy_provider(
        config,
        environ={"ANTHROPIC_API_KEY": "sk-real-value"},
        brokered_providers=sorted(providers),
        rng_seed=0,
    )
    assert provider is not None
    assert provider.broker.ready_providers() == ["anthropic"]
    token = provider.broker.sandbox_token("anthropic")
    # The sandbox gets a scoped token, never the real key.
    assert token and token != "sk-real-value"
    # The CLI's default endpoint is what the proxy classifies as this provider's model_api.
    assert provider.provider_of_host == {"api.anthropic.com": "anthropic"}


def test_the_claude_code_live_config_observes_dns() -> None:
    """The DNS disposition is a scored gate, and an advisory `not_evaluable` gate caps the verdict
    at `conditional` — so the claude-code live smoke observes DNS to keep a benign run at `ready`.
    `dns.image` set means `build_resolver_provider` yields a real provider (§10.6)."""
    from bellwether.cli.run import build_resolver_provider

    config = load_config(_LIVE / "config-claude-code.yaml")
    assert config.dns.image, "the claude-code live config must set dns.image to observe DNS"
    assert build_resolver_provider(config) is not None


def test_egress_and_dns_gates_block_on_the_claude_code_live_config() -> None:
    """Both planes are observed on this harness (the proxy is mandatory, the resolver is on), so the
    §16.4 precondition is satisfied and default-deny is *enforced*. They were `warn` for the first
    live proof; now that the benign claude-code run is confirmed clean (PR #65), a surprise flow or
    an out-of-allowlist lookup reddens the run rather than only warning. If this config rots back to
    a gate at `warn`, this fails — the tightening must not silently regress (§25)."""
    policy = load_policy(_LIVE / "policy-claude-code.yaml")
    runtime = policy.profile("low").gates.security_runtime
    assert runtime.egress_outside_allowlist == "block"
    assert runtime.dns_outside_allowlist == "block"
