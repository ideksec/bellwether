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

from collections.abc import Callable, Mapping
from pathlib import Path

from bellwether.cli.execution import SandboxRunExecutor
from bellwether.cli.orchestrator import (
    EvalResult,
    RunExecutor,
    RunPlan,
    drive_evaluation,
    orchestrate,
    plan_matrix,
)
from bellwether.cli.proxy_run import SidecarProxyProvider
from bellwether.cli.run_plan import resolve_run
from bellwether.config.models.config import Config
from bellwether.config.models.policy import Policy
from bellwether.determinism import stable_hash
from bellwether.errors import BellwetherError
from bellwether.harness import ModelClient, RunLimits, build_model_client
from bellwether.skill import SkillPackage

__all__ = ["ExecutorFactory", "build_proxy_provider", "policy_digest", "run_evaluation"]

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

    suite = package.scenarios
    if suite is None or not suite.scenarios:
        raise BellwetherError(
            f"skill '{package.name}' declares no scenarios (evals/scenarios.yaml), so there is "
            "nothing to run; a scenario suite with no scenarios produces no evidence"
        )
    scenarios = list(suite.scenarios)
    targets = [rt.target for rt in resolved.targets]

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
    # The declared scope is deliberately not applied yet. Its auto-derived assertions include egress
    # checks (§10.5, "no undeclared network"), which are *not_evaluable* until the recording proxy is
    # wired into the executor — and a not_evaluable derived assertion currently marks the whole run
    # not_evaluable, which would block the evidence gate for a benign skill. So the first-light driver
    # scores against the scenario assertions only, exactly as the checkpoint does; the declared scope
    # comes online with the egress plane in the executor.
    readings = drive_evaluation(plans, executor, profile=resolved.profile, scope=None)

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
) -> ExecutorFactory:
    """The production executor factory: a :class:`SandboxRunExecutor` around a Docker backend.

    Kept here so the CLI command stays a few lines and the wiring is in one place. The backend is
    imported lazily inside so importing this module for :func:`run_evaluation` needs no daemon.
    ``limits`` bounds each repetition — most importantly ``max_total_tokens``, the hard ceiling on
    what one run can spend against a live provider; omitted, it takes the :class:`RunLimits`
    defaults.

    ``proxy``, when supplied, stands a dual-homed recording-proxy sidecar up around each run so the
    egress plane is observed (§10.5). Omitted, the sandbox runs with no network, exactly as
    first-light — egress stays ``not_evaluable`` rather than being reported clean unobserved.
    """
    run_limits = limits if limits is not None else RunLimits()

    def make(
        package: SkillPackage,
        fixture: Path,
        client_factory: Callable[[RunPlan], tuple[ModelClient, str]],
    ) -> RunExecutor:
        from bellwether.sandbox import DockerBackend

        return SandboxRunExecutor(
            backend=DockerBackend(image=backend_image),
            package=package,
            fixture=fixture,
            client_factory=client_factory,
            eval_id=eval_id,
            run_root=run_root,
            limits=run_limits,
            proxy=proxy,
        )

    return make


def build_proxy_provider(config: Config) -> SidecarProxyProvider | None:
    """Assemble the recording-proxy provider from config, or ``None`` when it is unwired.

    The proxy is wired only when ``egress.image`` is set (§10.5); left empty — the shipped default —
    the sandbox runs with no network and egress stays ``not_evaluable``, exactly as first-light. A
    live config sets the digest-pinned sidecar image to turn it on.

    The allowlist is default-deny: the configured providers' hosts are ``model_api`` by
    construction, and ``egress.allowlist`` entries are the operator's explicit additions. The broker
    is **empty** — the ``api-loop`` model runs host-side with the real key, so the sandbox is handed
    no credential at all (§3.3 invariant 1 in its strongest form: nothing to steal). The proxy still
    records and allowlist-checks the skill's own traffic.
    """
    egress = config.egress
    if not egress.image:
        return None

    from bellwether.capture import CredentialBroker, EgressAllowlist, provider_hosts
    from bellwether.harness.live_client import DEFAULT_ANTHROPIC_BASE_URL
    from bellwether.sandbox import DockerBackend

    base_urls = [
        provider.base_url or DEFAULT_ANTHROPIC_BASE_URL for provider in config.providers.values()
    ]
    allowlist = EgressAllowlist(
        provider_endpoints=provider_hosts(base_urls),
        infrastructure_endpoints=frozenset(),
        extra=frozenset(egress.allowlist),
    )
    return SidecarProxyProvider(
        backend=DockerBackend(image=config.sandbox.image),
        image=egress.image,
        allowlist=allowlist,
        max_requests=egress.per_run_caps.max_requests,
        max_request_bytes=egress.per_run_caps.max_request_bytes,
        broker=CredentialBroker({}),
    )
