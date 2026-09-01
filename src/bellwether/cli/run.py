"""Driving a full evaluation end to end — the core of ``bellwether run`` (§20, §16).

The CLI command is thin glue; the work is here, and it is here because it is testable here. Given
a loaded config, a policy, and a parsed skill, this resolves the run (targets, profile, matrix, and
per-target model + key), builds the per-target model clients, plans the matrix, drives it through an
*injected* executor, and composes the verdict and artifact tree. The executor is injected — the
container-backed :class:`~bellwether.cli.execution.SandboxRunExecutor` in a real run, a replay
executor in a test — so the whole assembly runs offline, the same seam the rest of the pipeline uses.

The credential path stays explicit: :func:`~bellwether.cli.run_plan.resolve_run` validates that each
provider's key is present in the environment (and never puts it in a resolution object), and the key
is read here, at the last moment, into the per-target client. For the ``api-loop`` adapter the client
runs host-side, so :func:`~bellwether.harness.build_model_client` pins the endpoint to a trusted host
before it will send the real key (§3.3).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from bellwether.cli.execution import SandboxRunExecutor

if TYPE_CHECKING:
    from bellwether.sandbox import IsolationProfile, ZoneMap
from bellwether.cli.dns_run import DnsResolverProvider
from bellwether.cli.orchestrator import (
    EvalResult,
    RunExecutor,
    RunPlan,
    drive_evaluation,
    orchestrate,
    plan_matrix,
    resolve_capability_weights,
)
from bellwether.cli.preflight import refuse_on_preflight_failures
from bellwether.cli.proxy_run import SidecarProxyProvider
from bellwether.cli.run_plan import resolve_run
from bellwether.config.models.config import Config
from bellwether.config.models.manifest import SkillManifest
from bellwether.config.models.policy import Policy
from bellwether.determinism import stable_hash
from bellwether.errors import BellwetherError
from bellwether.harness import ModelClient, RunLimits, build_model_client
from bellwether.skill import SkillPackage

__all__ = [
    "ExecutorFactory",
    "build_proxy_provider",
    "build_resolver_provider",
    "claude_code_providers",
    "policy_digest",
    "run_evaluation",
]

#: How the caller supplies the execution half. The production factory builds a
#: :class:`SandboxRunExecutor` around a Docker backend; a test passes a replay executor. It receives
#: the skill, the workspace fixture, and the per-plan client factory the executor drives.
ExecutorFactory = Callable[
    [SkillPackage, Path, Callable[[RunPlan], tuple[ModelClient, str]]], RunExecutor
]


def policy_digest(policy: Policy) -> str:
    """A stable digest of the effective policy, for the report's ``policy`` reference (§16).

    Computed from the merged policy the run actually used, so the verdict records exactly which
    gates governed it — a policy edited between runs produces a different digest, and the diff is
    visible rather than silent.
    """
    return "sha256:" + stable_hash(policy.model_dump_json())


def run_evaluation(
    *,
    config: Config,
    policy: Policy,
    package: SkillPackage,
    fixture: Path,
    environ: Mapping[str, str],
    make_executor: ExecutorFactory,
    out_dir: Path,
    eval_id: str,
    created_at: str,
    bellwether_version: str,
    profile_override: str | None = None,
) -> EvalResult:
    """Resolve, plan, drive, and compose a full evaluation, or raise :class:`BellwetherError`.

    Everything up to the executor is validated first (§9.5, §16.1) so a misconfigured run fails
    before a single container starts. The scenarios come from the skill's ``evals/scenarios.yaml``;
    a skill with none is refused rather than silently producing an empty, clean-looking result.
    """
    resolved = resolve_run(
        config, policy, package.manifest, environ=environ, profile_override=profile_override
    )

    # §21 / THREAT_MODEL: the settings that bound residual-channel exfiltration and the
    # covert channels (model-API body scanning, the sidecar deployment, the controlled
    # resolver, canary redaction and marker randomisation) MUST NOT be disable-able without
    # a critical finding and a refusal to run above the 'low' profile. Detection lived only
    # in `doctor`; enforce it here so the guarantee holds on the path a real run takes.
    violations = config.enforced_setting_violations()
    if violations and resolved.profile_name != "low":
        rendered = "\n  - ".join(v.render() for v in violations)
        raise BellwetherError(
            f"refusing to run under profile '{resolved.profile_name}' with "
            f"{len(violations)} enforced setting(s) disabled (§21); a result collected this "
            f"way would not be earned. Correct them, or run under the 'low' profile:\n  - "
            f"{rendered}"
        )

    suite = package.scenarios
    if suite is None or not suite.scenarios:
        raise BellwetherError(
            f"skill '{package.name}' declares no scenarios (evals/scenarios.yaml), so there is "
            "nothing to run; a scenario suite with no scenarios produces no evidence"
        )
    scenarios = list(suite.scenarios)
    targets = [rt.target for rt in resolved.targets]

    # §16.4 / BW-51: refuse an unsatisfiable policy/target/composition combination *now*,
    # before the executor is built and a container is paid for. Observability is read from
    # the same config fields that wire the components (egress.image → proxy, dns.image →
    # resolver), so this refuses exactly the runs that would end not_evaluable-and-blocked
    # after the matrix — and no others.
    refuse_on_preflight_failures(
        config, resolved.profile, targets, profile_name=resolved.profile_name
    )

    model_id_by_slug = {rt.target.slug: rt.model_id for rt in resolved.targets}
    provider_by_slug = {rt.target.slug: rt.target.provider for rt in resolved.targets}
    key_by_slug = {rt.target.slug: environ[rt.api_key_env] for rt in resolved.targets}

    def client_factory(plan: RunPlan) -> tuple[ModelClient, str]:
        slug = plan.target.slug
        provider = config.providers[provider_by_slug[slug]]
        client = build_model_client(provider, api_key=key_by_slug[slug])
        return client, model_id_by_slug[slug]

    executor = make_executor(package, fixture, client_factory)
    plans = plan_matrix(scenarios, targets, repetitions=resolved.n_max)
    # Declared scope (§12.5) is applied as a *declared-vs-observed table*, not as outcome
    # assertions: `scope=None` keeps the scenario assertions deciding each run's outcome (the
    # scope's network/write *derivations* are still stubbed to not_evaluable — §10.5 — and would
    # otherwise drag a clean run there), while `declared_scope` feeds the manifest's scope into the
    # `scope` gate so a skill that reads or acts outside its manifest is caught and blocked. This is
    # the same split the demo uses; passing `scope=None` alone (the old first-light shortcut) left the
    # `scope` gate reporting a false "within scope" for every live run (BW-47).
    declared_scope = package.manifest.declared_scope if package.manifest is not None else None
    weights = resolve_capability_weights(resolved.profile.metrics.capability_risk_weights)
    readings = drive_evaluation(
        plans,
        executor,
        profile=resolved.profile,
        scope=None,
        declared_scope=declared_scope,
        weights=weights,
    )

    criticality = (
        package.manifest.metadata.criticality if package.manifest is not None else "medium"
    )
    return orchestrate(
        skill_name=package.name,
        package_digest=package.package_digest,
        payload_digest=package.payload_digest,
        criticality=criticality,
        profile_name=resolved.profile_name,
        profile=resolved.profile,
        policy_digest=policy_digest(policy),
        readings=readings,
        eval_id=eval_id,
        created_at=created_at,
        bellwether_version=bellwether_version,
        out_dir=out_dir,
    )


def sandbox_executor_factory(
    backend_image: str,
    run_root: Path,
    eval_id: str,
    limits: RunLimits | None = None,
    proxy: SidecarProxyProvider | None = None,
    *,
    resolver: DnsResolverProvider | None = None,
    isolation: IsolationProfile | None = None,
    zones: ZoneMap | None = None,
    randomize_identifiers: bool = True,
    plant_canaries: bool = False,
    provider_base_urls: Mapping[str, str | None] | None = None,
) -> ExecutorFactory:
    """The production executor factory: a :class:`SandboxRunExecutor` around a Docker backend.

    Kept here so the CLI command stays a few lines and the wiring is in one place. The backend is
    imported lazily inside so importing this module for :func:`run_evaluation` needs no daemon.
    ``limits`` bounds each repetition — most importantly ``max_total_tokens``, the hard ceiling on
    what one run can spend against a live provider; omitted, it takes the :class:`RunLimits`
    defaults.

    ``isolation`` / ``zones`` / ``randomize_identifiers`` carry the config-derived sandbox profile
    into the executor (``isolation_from_config`` / ``zone_map_from_config``); omitted, the executor's
    hardened defaults apply. Threading these is what makes ``sandbox.memory`` / ``pids_limit`` /
    ``timeout_seconds`` and the §3.5 identifier randomisation actually reach the container.

    ``proxy``, when supplied, stands a dual-homed recording-proxy sidecar up around each run so the
    egress plane is observed (§10.5). Omitted, the sandbox runs with no network, exactly as
    first-light — egress stays ``not_evaluable`` rather than being reported clean unobserved.

    ``plant_canaries`` turns on canary planting and the host-side Plane C scan (§10.4); the lead
    passes ``config.canaries.enabled``. Omitted, the credentials plane stays ``not_evaluable``.
    """
    run_limits = limits if limits is not None else RunLimits()

    def make(
        package: SkillPackage,
        fixture: Path,
        client_factory: Callable[[RunPlan], tuple[ModelClient, str]],
    ) -> RunExecutor:
        from bellwether.sandbox import DockerBackend, IsolationProfile, ZoneMap

        return SandboxRunExecutor(
            backend=DockerBackend(image=backend_image),
            package=package,
            fixture=fixture,
            client_factory=client_factory,
            eval_id=eval_id,
            run_root=run_root,
            limits=run_limits,
            proxy=proxy,
            resolver=resolver,
            isolation=isolation if isolation is not None else IsolationProfile(),
            zones=zones if zones is not None else ZoneMap(),
            randomize_identifiers=randomize_identifiers,
            plant_canaries=plant_canaries,
            provider_base_urls=dict(provider_base_urls or {}),
        )

    return make


def claude_code_providers(policy: Policy, manifest: SkillManifest | None) -> frozenset[str]:
    """The providers a ``claude-code`` target could name for this skill (§9.4, §3.3).

    The manifest's matrix override wins where it sets targets; otherwise every profile's
    required targets are considered, since the profile is selected later by criticality and
    the proxy is assembled before that. A slight over-approximation across profiles is the
    price of building the sidecar once per evaluation, and it errs toward brokering a key for
    a target that may not run — never toward running a claude-code target with no key.
    """
    if manifest is not None and manifest.matrix is not None and manifest.matrix.targets:
        specs = list(manifest.matrix.targets)
    else:
        specs = [
            spec
            for profile_name in sorted(policy.profiles)
            for spec in policy.profile(profile_name).matrix.required_targets
        ]
    return frozenset(spec.provider for spec in specs if spec.harness == "claude-code")


def build_proxy_provider(
    config: Config,
    *,
    environ: Mapping[str, str] | None = None,
    brokered_providers: Iterable[str] = (),
    rng_seed: int = 0,
) -> SidecarProxyProvider | None:
    """Assemble the recording-proxy provider from config, or ``None`` when it is unwired.

    The proxy is wired only when ``egress.image`` is set (§10.5); left empty — the shipped default —
    the sandbox runs with no network and egress stays ``not_evaluable``, exactly as first-light. A
    live config sets the digest-pinned sidecar image to turn it on.

    The allowlist is default-deny: the configured providers' hosts are ``model_api`` by
    construction, the claude-code adapter's declared telemetry hosts are ``harness_infrastructure``
    (§10.5.0 — so a stray telemetry call never reads as the skill's egress), and
    ``egress.allowlist`` entries are the operator's explicit additions.

    The broker holds a key only for ``brokered_providers`` — the providers a ``claude-code`` target
    names, whose CLI talks to the API from *inside* the sandbox and is handed a sandbox-scoped token
    the proxy swaps for the real key on the way out (§3.3 invariant 1, §10.5.1). For an
    ``api-loop``-only evaluation the broker stays **empty**: that model runs host-side with the real
    key, so the sandbox is handed no credential at all — nothing to steal.
    """
    egress = config.egress
    if not egress.image:
        return None

    from bellwether.capture import CredentialBroker, EgressAllowlist, provider_hosts
    from bellwether.determinism import SeededRng
    from bellwether.harness import CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS
    from bellwether.harness.live_client import DEFAULT_ANTHROPIC_BASE_URL
    from bellwether.sandbox import DockerBackend

    base_url_of = {
        name: provider.base_url or DEFAULT_ANTHROPIC_BASE_URL
        for name, provider in config.providers.items()
    }
    brokered = sorted(set(brokered_providers))
    allowlist = EgressAllowlist(
        provider_endpoints=provider_hosts(base_url_of.values()),
        infrastructure_endpoints=(
            frozenset(CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS) if brokered else frozenset()
        ),
        extra=frozenset(egress.allowlist),
    )
    broker = CredentialBroker({})
    provider_of_host: dict[str, str] = {}
    if brokered:
        api_key_env: dict[str, str] = {}
        for name in brokered:
            provider = config.providers.get(name)
            if provider is not None and provider.api_key_env:
                api_key_env[name] = provider.api_key_env
        broker = CredentialBroker.for_run(
            api_key_env, environ if environ is not None else {}, rng=SeededRng(rng_seed, "broker")
        )
        provider_of_host = {
            host: name
            for name in brokered
            if name in base_url_of
            for host in provider_hosts([base_url_of[name]])
        }
    return SidecarProxyProvider(
        backend=DockerBackend(image=config.sandbox.image),
        image=egress.image,
        allowlist=allowlist,
        max_requests=egress.per_run_caps.max_requests,
        max_request_bytes=egress.per_run_caps.max_request_bytes,
        broker=broker,
        provider_of_host=provider_of_host,
    )


def build_resolver_provider(config: Config) -> DnsResolverProvider | None:
    """Assemble the controlled-resolver provider from config, or ``None`` when it is unwired.

    Mirrors :func:`build_proxy_provider`: the resolver is wired only when ``dns.image`` is set
    (§10.6); left empty — the shipped default — DNS stays ``not_evaluable``. A live config sets the
    digest-pinned resolver image to turn it on.

    The allowlist is default-deny: the configured providers' hosts (the sandbox may legitimately
    resolve the model endpoint) plus the operator's explicit ``dns.allowlist`` additions. The
    proxy's own container name is *not* added here — it is known only at standup and is handed to
    the resolver per run by the executor.
    """
    dns = config.dns
    if not dns.image:
        return None

    from bellwether.capture import DnsAllowlist, provider_hosts
    from bellwether.harness.live_client import DEFAULT_ANTHROPIC_BASE_URL
    from bellwether.sandbox import DockerBackend

    base_urls = [
        provider.base_url or DEFAULT_ANTHROPIC_BASE_URL for provider in config.providers.values()
    ]
    allowlist = DnsAllowlist(allowed=provider_hosts(base_urls) | frozenset(dns.allowlist))
    return DnsResolverProvider(
        backend=DockerBackend(image=config.sandbox.image),
        image=dns.image,
        allowlist=allowlist,
    )
