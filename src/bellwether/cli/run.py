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

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from bellwether.cli.execution import SandboxRunExecutor, run_limits_for

if TYPE_CHECKING:
    from bellwether.sandbox import IsolationProfile, ZoneMap
from bellwether import __version__
from bellwether.cli.baselines import BaselineRecord
from bellwether.cli.dns_run import DnsResolverProvider
from bellwether.cli.estimate import RunEstimate, estimate_run
from bellwether.cli.fixtures import ResolvedFixture
from bellwether.cli.orchestrator import (
    EvalResult,
    RunExecutor,
    RunPlan,
    TargetInfo,
    consistent_schedule,
    drive_evaluation,
    effective_schedule,
    orchestrate,
    plan_matrix,
    resolve_capability_weights,
)
from bellwether.cli.preflight import refuse_on_preflight_failures
from bellwether.cli.proxy_run import SidecarProxyProvider
from bellwether.cli.run_cache import (
    CacheKeyInputs,
    CachingExecutor,
    RunCache,
    cache_version_for,
    observability_key,
    render_sampling,
    scenario_content_digest,
)
from bellwether.cli.run_plan import ResolvedRun, resolve_run
from bellwether.config.models.baseline import PlatformBaseline
from bellwether.config.models.config import Config
from bellwether.config.models.manifest import SkillManifest
from bellwether.config.models.policy import Policy
from bellwether.config.models.provider import ModelPricing
from bellwether.config.models.scenarios import Scenario
from bellwether.determinism import stable_hash
from bellwether.errors import BellwetherError
from bellwether.harness import (
    TRUSTED_MODEL_HOSTS_ENV,
    ModelClient,
    RunLimits,
    SamplingSpec,
    build_model_client,
)
from bellwether.sandbox import fixture_digest, plugin_bundle_digest
from bellwether.skill import PluginBundle, SkillPackage
from bellwether.verdict import validate_capability_weights

__all__ = [
    "DEPTHS",
    "ExecutorFactory",
    "apply_budget_override",
    "apply_matrix_options",
    "build_proxy_provider",
    "build_resolver_provider",
    "claude_code_providers",
    "depth_options",
    "policy_digest",
    "run_evaluation",
    "select_scenarios",
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


def select_scenarios(
    scenarios: Sequence[Scenario], *, scenario_ids: Sequence[str] = (), tags: Sequence[str] = ()
) -> list[Scenario]:
    """Narrow a suite by ``--scenario ID`` and ``--tag TAG`` (§7.2, §20), or refuse.

    Ids select exactly those scenarios; tags select every scenario carrying *any* of them; both
    together intersect (an id selection narrowed by tags). Suite order is preserved so the plan
    list — and the artifact tree — stays deterministic. An id no scenario has, or a filter that
    selects nothing, refuses naming what exists: an empty selection run to completion would be a
    clean-looking verdict about no evidence at all.
    """
    if not scenario_ids and not tags:
        return list(scenarios)
    known = [scenario.id for scenario in scenarios]
    unknown = sorted(set(scenario_ids) - set(known))
    if unknown:
        raise BellwetherError(
            f"--scenario names {', '.join(unknown)}, which this suite does not define; it defines: "
            f"{', '.join(known)}"
        )
    wanted_ids = set(scenario_ids)
    wanted_tags = set(tags)
    selected = [
        scenario
        for scenario in scenarios
        if (not wanted_ids or scenario.id in wanted_ids)
        and (not wanted_tags or wanted_tags & set(scenario.tags))
    ]
    if not selected:
        available = sorted({tag for scenario in scenarios for tag in scenario.tags})
        raise BellwetherError(
            f"the filter selects no scenarios (--scenario {sorted(wanted_ids) or '-'}, --tag "
            f"{sorted(wanted_tags) or '-'}); the suite's tags are {available or 'none'} and its "
            f"scenarios are {known}"
        )
    return selected


class RunDeclinedError(BellwetherError):
    """The operator declined the §19.1 pre-flight estimate; nothing was executed.

    A distinct type because a decline is a *choice*, not a failure: the CLI gives it its own
    exit code rather than the infrastructure one, which would read as a broken environment in a
    script that only sees the status.
    """


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
    fixture_for: Callable[[Scenario], ResolvedFixture] | None = None,
    companions_for: Callable[[Scenario], tuple[SkillPackage, ...]] | None = None,
    scenario_ids: Sequence[str] = (),
    tags: Sequence[str] = (),
    target_aliases: Sequence[str] = (),
    n_max_override: int | None = None,
    looks_override: Sequence[int] | None = None,
    repetitions: int | None = None,
    budget_usd: float | None = None,
    baseline: BaselineRecord | None = None,
    depth: str | None = None,
    platform_baseline: PlatformBaseline | None = None,
    run_cache: RunCache | None = None,
    plugin: PluginBundle | None = None,
    deterministic_sampling: bool = False,
    max_tokens_per_run: int = 1_000_000,
    on_estimate: Callable[[RunEstimate], bool] | None = None,
) -> EvalResult:
    """Resolve, plan, drive, and compose a full evaluation, or raise :class:`BellwetherError`.

    Everything up to the executor is validated first (§9.5, §16.1) so a misconfigured run fails
    before a single container starts. The scenarios come from the skill's ``evals/scenarios.yaml``;
    a skill with none is refused rather than silently producing an empty, clean-looking result.

    The §20 matrix options: ``target_aliases`` keeps only the resolved targets whose model alias
    is listed (``--targets frontier,small``); ``n_max_override``/``looks_override`` replace the
    resolved schedule matrix-wide under the §13.1 consistency rule (``--n-max``/``--looks``); and
    ``repetitions`` forces **fixed mode** — exactly that many runs per set, a single look at N, and
    a ``descriptive_only`` verdict that can never be ``ready`` (§13.1, §16.2 rule 6), because a
    fixed-N run makes no sequential decision and licenses no gate-eligible interval.
    ``budget_usd`` (``--budget-usd``) overrides the profile's ``gates.budget.max_cost_usd`` for
    this evaluation; the cost gate it feeds is composed only where every target is priced.
    ``baseline`` is the skill's stored §17.5 baseline, when one exists; the regression gate is
    composed against it where the profile asks for the comparison and the key allows it.
    ``on_estimate`` receives the §19.1 pre-flight estimate after the matrix is planned and
    before anything is executed; returning False declines the run, which is refused with no
    container started. ``max_tokens_per_run`` is the per-repetition cap the estimate prices.
    ``run_cache`` (§19.2), when given, wraps the executor: a plan whose key — payload digest,
    scenario content, target, fixture digest, harness version, model id, sandbox image, platform
    baseline version, repetition — matches a live entry is served from the stored trace instead of
    being executed, and every executed complete run is stored. ``summary.matrix.runs_cached``
    counts the replays.
    ``platform_baseline`` is the ``.bellwether/platform-baseline.yaml`` document (§12.6): where
    it is keyed to the configured sandbox image its path entries are subtracted from every
    run's capability sets and its version is stamped on the summary; where it is not, nothing
    is absorbed and the verdict carries the reason, so "baseline not applied" never reads as
    "nothing infrastructural happened".
    ``depth`` (``--depth quick|standard|deep``, §19.1) is a preset over the matrix options and
    is exclusive with them: ``quick`` is one ``small`` target at a fixed 3 (descriptive only),
    ``standard`` is ``frontier`` + ``small`` at looks [6, 12], ``deep`` is every configured
    target at looks [6, 12, 20].
    """
    if depth is not None:
        target_aliases, looks_override, repetitions = depth_options(
            depth,
            target_aliases=target_aliases,
            n_max_override=n_max_override,
            looks_override=looks_override,
            repetitions=repetitions,
        )
        n_max_override = None
    resolved = resolve_run(
        config, policy, package.manifest, environ=environ, profile_override=profile_override
    )
    resolved = apply_matrix_options(
        resolved,
        target_aliases=target_aliases,
        n_max_override=n_max_override,
        looks_override=looks_override,
        repetitions=repetitions,
        require_every_alias=depth is not None,
    )
    resolved = apply_budget_override(resolved, budget_usd=budget_usd)

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
    # §7.2 / §20: `--scenario ID` and `--tag TAG` narrow the suite. A filter that selects
    # nothing refuses — an empty selection run to completion would be a clean-looking verdict
    # about no evidence at all.
    scenarios = select_scenarios(suite.scenarios, scenario_ids=scenario_ids, tags=tags)
    targets = [rt.target for rt in resolved.targets]

    # §16.4 / BW-51: refuse an unsatisfiable policy/target/composition combination *now*,
    # before the executor is built and a container is paid for. Observability is read from
    # the same config fields that wire the components (egress.image → proxy, dns.image →
    # resolver), so this refuses exactly the runs that would end not_evaluable-and-blocked
    # after the matrix — and no others.
    refuse_on_preflight_failures(
        config,
        resolved.profile,
        targets,
        profile_name=resolved.profile_name,
        multi_turn_scenario_ids=[s.id for s in scenarios if isinstance(s.prompt, list)],
        deterministic_sampling=deterministic_sampling,
    )

    # §16.1: a capability class the manifest denies must not be weighted 0. Weight 0 erases it
    # from the risk-weighted Jaccard — the one figure feeding the BCI — so a skill could be
    # denied a tool by its own manifest and still post a clean consistency score while using it.
    # This is a *cross-document* check (policy weights × manifest deny list) neither document can
    # make alone, so it runs here, where both are in hand, and raises before a container is paid
    # for. A denied tool maps to the `tool:<name>` class the weight table names.
    if package.manifest is not None:
        validate_capability_weights(
            resolved.profile.metrics.capability_risk_weights,
            deny_classes={f"tool:{tool}" for tool in package.manifest.declared_scope.tools.deny},
        )

    model_id_by_slug = {rt.target.slug: rt.model_id for rt in resolved.targets}
    provider_by_slug = {rt.target.slug: rt.target.provider for rt in resolved.targets}
    key_by_slug = {rt.target.slug: environ[rt.api_key_env] for rt in resolved.targets}
    # §3.3: extra trusted model-endpoint hosts come from the process environment — trusted config
    # *outside* the evaluated checkout — never from config.yaml, which a malicious PR can edit to
    # redirect the real key. The harness client refuses any openai_compatible base_url not on this
    # set (plus the canonical OpenAI host); the anthropic client is pinned regardless.
    trusted_hosts = frozenset(
        host.strip().lower()
        for host in environ.get(TRUSTED_MODEL_HOSTS_ENV, "").split(",")
        if host.strip()
    )

    def client_factory(plan: RunPlan) -> tuple[ModelClient, str]:
        slug = plan.target.slug
        provider = config.providers[provider_by_slug[slug]]
        client = build_model_client(
            provider, api_key=key_by_slug[slug], trusted_openai_hosts=trusted_hosts
        )
        return client, model_id_by_slug[slug]

    executor: RunExecutor = make_executor(package, fixture, client_factory)
    # §7.2: with a resolver, each scenario's fixture is resolved here — before the executor and
    # any container — and stamped on its plans; a missing named fixture refuses at this point.
    # Likewise each scenario's sequential schedule (§7.2 `looks`/`n_max`, else the suite default,
    # else the resolved matrix) is settled now, so an inconsistent override refuses before a run.
    schedule = {
        scenario.id: effective_schedule(
            scenario, suite.defaults, looks=resolved.looks, n_max=resolved.n_max
        )
        for scenario in scenarios
    }
    plans = plan_matrix(
        scenarios,
        targets,
        repetitions=resolved.n_max,
        fixture_for=fixture_for,
        n_max_for=lambda scenario: schedule[scenario.id][1],
        companions_for=companions_for,
    )

    def pricing_for(target: TargetInfo) -> ModelPricing | None:
        return config.providers[target.provider].pricing_for(target.model_alias)

    # §19.1: the pre-flight estimate is mandatory and comes before anything is spent. The
    # caller shows it and may decline; a decline is a refusal with no container started.
    estimate = estimate_run(
        schedules=schedule,
        targets=targets,
        max_tokens_per_run=max_tokens_per_run,
        pricing_for=pricing_for,
        baseline=baseline,
        fixed_mode=repetitions is not None,
        cache_enabled=run_cache is not None,
    )
    if on_estimate is not None and not on_estimate(estimate):
        raise RunDeclinedError(
            "run declined at the pre-flight estimate (§19.1); nothing was executed"
        )
    # Declared scope (§12.5) is applied as a *declared-vs-observed table*, not as outcome
    # assertions: `scope=None` keeps the scenario's own assertions deciding each run's outcome,
    # while `declared_scope` feeds the manifest's scope into the `scope` gate — every area of the
    # table, tools, filesystem reads and writes, and network egress alike — so a skill that reads,
    # writes, or reaches a host outside its manifest is caught and blocked there. The split is
    # deliberate: an auto-derived absence assertion on a plane a run cannot observe would drag an
    # otherwise-clean outcome to not_evaluable, whereas the table records that row as
    # not_evaluable on its own. This is the same split the demo uses; passing `scope=None` alone
    # (the old first-light shortcut) left the `scope` gate reporting a false "within scope" for
    # every live run (BW-47).
    declared_scope = package.manifest.declared_scope if package.manifest is not None else None
    weights = resolve_capability_weights(resolved.profile.metrics.capability_risk_weights)
    applied_baseline: PlatformBaseline | None = None
    baseline_notes: list[str] = []
    if platform_baseline is not None:
        applicable, why = platform_baseline.applicable_to(config.sandbox.image)
        if applicable:
            applied_baseline = platform_baseline
        else:
            baseline_notes.append(
                f"platform baseline {platform_baseline.version!r} not applied: {why} (§12.6); "
                "no infrastructural access was subtracted from the capability sets"
            )
    caching: CachingExecutor | None = None
    if run_cache is not None:
        # §19.2: the key is formed from what the run *is* — the skill's payload, the scenario's
        # content, the target and the exact model id, the fixture, the sandbox image, the platform
        # baseline — plus the repetition index, the pinned sampling and the companions' payloads
        # (spec-notes). The harness version is the adapter shipped with this package for api-loop
        # and the configured pin for claude-code; unpinned, the plan bypasses the cache.
        harness_versions = {
            target.harness: cache_version_for(
                target.harness, config.harnesses.get(target.harness), __version__
            )
            for target in targets
        }
        applied_version = applied_baseline.version if applied_baseline is not None else ""
        sampling_key = render_sampling(
            SamplingSpec(temperature=0.0, seed=0) if deterministic_sampling else None
        )
        # §5/§6/§18: the bundle's content outside the skill's own directory reaches the
        # container, so it belongs in the key that decides whether a trace may be replayed.
        # The output directory is excluded here for the same reason the executor excludes it
        # from the copy — a bundle that is its own checkout must not hand the skill previous
        # evaluations' verdicts — and it has to be the *same* exclusion, or the key would
        # describe a different set of files from the one staged.
        plugin_digest = (
            plugin_bundle_digest(plugin.root, exclude_roots=(out_dir,))
            if plugin is not None
            else ""
        )
        # What this configuration can watch, and the limits it runs under: a trace captured
        # with no proxy is a different observation from one captured behind it (§19.2).
        observability = observability_key(config)

        def inputs_for(plan: RunPlan) -> CacheKeyInputs | None:
            harness_version = harness_versions.get(plan.target.harness)
            if harness_version is None:
                return None
            return CacheKeyInputs(
                payload_digest=package.payload_digest,
                scenario_id=plan.scenario.id,
                scenario_digest=scenario_content_digest(plan.scenario),
                target_slug=plan.target.slug,
                fixture_digest=fixture_digest(
                    plan.fixture if plan.fixture is not None else fixture
                ),
                harness=plan.target.harness,
                harness_version=harness_version,
                model_id=model_id_by_slug[plan.target.slug],
                sandbox_image=config.sandbox.image,
                platform_baseline_version=applied_version,
                repetition=plan.repetition,
                sampling=sampling_key,
                companion_digests=tuple(c.payload_digest for c in plan.companions),
                plugin_digest=plugin_digest,
                observability=observability,
            )

        caching = CachingExecutor(
            executor,
            run_cache,
            inputs_for,
            eval_id=eval_id,
            run_root=out_dir / eval_id / "runs",
        )
        executor = caching

    readings = drive_evaluation(
        plans,
        executor,
        profile=resolved.profile,
        scope=None,
        declared_scope=declared_scope,
        weights=weights,
        looks_for=lambda scenario_id: schedule[scenario_id][0],
        platform_baseline=applied_baseline,
    )
    if caching is not None and caching.bypassed:
        # §19.2: disclosed, not silent — the operator turned the cache on and part of the
        # matrix could not honestly use it.
        baseline_notes.append(
            f"run cache bypassed for {len(caching.bypassed)} run(s) on an unpinned claude-code "
            "target: the CLI version is observable only after a run, so no key can be formed "
            "before it (set harnesses.<name>.version_pin to cache these) (§19.2)"
        )

    criticality = (
        package.manifest.metadata.criticality if package.manifest is not None else "medium"
    )
    # §19.1: the executor's per-run wall-clock cap (the scenario's timeout, §7.2) is what
    # bounds a footerless run's duration for the budget gate; pricing resolves per target
    # alias so reported tokens become dollars only at a configured rate, never a guessed one.
    configured_limits = run_limits_from_config(config, max_total_tokens=max_tokens_per_run)
    per_run_wall_cap_ms = max(
        int(run_limits_for(configured_limits, scenario, suite.defaults).wall_seconds * 1000)
        for scenario in scenarios
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
        descriptive_only=repetitions is not None,
        per_run_wall_cap_ms=per_run_wall_cap_ms,
        pricing_for=pricing_for,
        baseline=baseline,
        platform_baseline_version=applied_baseline.version if applied_baseline else "",
        extra_notes=baseline_notes,
        deterministic_sampling=deterministic_sampling,
    )


#: §19.1's tiered depth: (target aliases to keep, look schedule, fixed repetitions).
#: ``quick`` is fixed-N so it is ``descriptive_only`` and can never return ``ready``.
DEPTHS: Mapping[str, tuple[tuple[str, ...], tuple[int, ...] | None, int | None]] = {
    "quick": (("small",), None, 3),
    "standard": (("frontier", "small"), (6, 12), None),
    "deep": ((), (6, 12, 20), None),
}


def depth_options(
    depth: str,
    *,
    target_aliases: Sequence[str] = (),
    n_max_override: int | None = None,
    looks_override: Sequence[int] | None = None,
    repetitions: int | None = None,
) -> tuple[tuple[str, ...], tuple[int, ...] | None, int | None]:
    """Expand ``--depth`` into the matrix options it presets, or refuse (§19.1, §20).

    A depth is a preset *over* ``--targets``/``--n-max``/``--looks``/``--repetitions``, so
    naming both is two instructions for one setting and is refused rather than merged.
    """
    if depth not in DEPTHS:
        raise BellwetherError(f"--depth must be one of {', '.join(DEPTHS)}, not {depth!r}")
    if target_aliases or n_max_override is not None or looks_override is not None or repetitions:
        raise BellwetherError(
            f"--depth {depth} presets the targets and the schedule and cannot be combined with "
            "--targets, --n-max, --looks or --repetitions; drop the preset to set them by hand"
        )
    return DEPTHS[depth]


def apply_budget_override(resolved: ResolvedRun, *, budget_usd: float | None) -> ResolvedRun:
    """Apply ``--budget-usd`` (§20) to the resolved profile's ``gates.budget.max_cost_usd``.

    A negative budget is refused: the gate would block every priced matrix, which is a typo,
    not an intent. Zero is allowed — it is the explicit "any priced spend blocks" setting.
    """
    if budget_usd is None:
        return resolved
    if budget_usd < 0:
        raise BellwetherError(f"--budget-usd must be zero or positive, got {budget_usd:g}")
    profile = resolved.profile
    budget = profile.gates.budget.model_copy(update={"max_cost_usd": budget_usd})
    gates = profile.gates.model_copy(update={"budget": budget})
    return replace(resolved, profile=profile.model_copy(update={"gates": gates}))


def apply_matrix_options(
    resolved: ResolvedRun,
    *,
    target_aliases: Sequence[str] = (),
    n_max_override: int | None = None,
    looks_override: Sequence[int] | None = None,
    repetitions: int | None = None,
    require_every_alias: bool = False,
) -> ResolvedRun:
    """Apply the §20 matrix options to a resolved run, or refuse.

    ``--targets`` filters by model alias and refuses when nothing matches, naming the aliases the
    matrix has — a silently empty target list would be a run about nothing; with
    ``require_every_alias`` (a ``--depth`` preset) every named alias must be present, since a
    preset that silently ran on half its targets would not be the preset. ``--repetitions``
    is exclusive with ``--n-max``/``--looks``: fixed mode *is* a schedule (one look at N), so
    combining them would be two schedules. ``--n-max``/``--looks`` go through the same §13.1
    consistency rule as every other schedule override.
    """
    if target_aliases:
        wanted = set(target_aliases)
        kept = tuple(rt for rt in resolved.targets if rt.target.model_alias in wanted)
        have = sorted({rt.target.model_alias for rt in resolved.targets})
        missing = sorted(wanted - {rt.target.model_alias for rt in kept})
        if not kept or (require_every_alias and missing):
            raise BellwetherError(
                f"--targets {sorted(wanted)} "
                + (
                    f"matches none of the matrix's model aliases {have}"
                    if not kept
                    else f"names alias(es) the matrix does not have: {missing} (have {have})"
                )
            )
        resolved = replace(resolved, targets=kept)
    if repetitions is not None:
        if n_max_override is not None or looks_override is not None:
            raise BellwetherError(
                "--repetitions forces a fixed-N schedule (one look at N) and cannot be combined "
                "with --n-max or --looks"
            )
        if repetitions < 2:
            raise BellwetherError(
                f"--repetitions {repetitions}: a repetition set needs at least two runs "
                "(repetition is mandatory; a single run is an anecdote, §13.2)"
            )
        return replace(resolved, looks=(repetitions,), n_max=repetitions)
    if n_max_override is not None or looks_override is not None:
        looks = list(looks_override) if looks_override is not None else list(resolved.looks)
        n_max = (
            n_max_override
            if n_max_override is not None
            else (looks[-1] if looks_override is not None else resolved.n_max)
        )
        checked_looks, checked_n = consistent_schedule(looks, n_max, subject="--looks/--n-max")
        return replace(resolved, looks=checked_looks, n_max=checked_n)
    return resolved


def run_limits_from_config(config: Config, *, max_total_tokens: int | None = None) -> RunLimits:
    """The per-run bounds this configuration allows (§9.2, §12.7).

    ``execution.limits`` rather than the generic :class:`RunLimits` defaults, which were
    previously what every run got no matter what the operator configured. ``max_total_tokens``
    overrides the configured token cap where the caller passed ``--max-tokens``: that flag is
    the documented per-invocation cost control, and it would be surprising for a config value
    to win over a flag typed on the command line.

    ``wall_seconds`` stays at the :class:`RunLimits` default here and is replaced per run by
    :func:`~bellwether.cli.execution.run_limits_for` from the scenario's §7.2 timeout, which is
    where the wall clock is specified.
    """
    limits = config.execution.limits
    return RunLimits(
        max_turns=limits.max_turns,
        max_tool_calls=limits.max_tool_calls,
        max_total_tokens=(
            limits.max_total_tokens if max_total_tokens is None else max_total_tokens
        ),
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
    provider_types: Mapping[str, str] | None = None,
    plugin: PluginBundle | None = None,
    platform_baseline_version: str | None = None,
    sampling: SamplingSpec | None = None,
    artifact_root: Path | None = None,
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
            provider_types=dict(provider_types or {}),
            plugin=plugin,
            artifact_root=artifact_root,
            platform_baseline_version=platform_baseline_version,
            sampling=sampling,
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
