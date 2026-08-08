"""The sandbox execution driver — the :class:`RunExecutor` the orchestrator calls (§10).

The analysis orchestrator (``cli.orchestrator``) takes a trace per repetition and produces
a verdict; it deliberately does not run anything. This is the other half: the executor that
materialises a sandbox, runs one repetition through the ``api-loop`` adapter, captures both
planes on the host, and assembles the ARF trace the orchestrator consumes. It is the WP-6
container wiring (proven in ``test_harness_docker.py``) lifted behind the ``RunExecutor``
protocol, so nothing structural changed — only that it is now reusable and matrix-driven.

One repetition, one fresh sandbox: prepare → mount → start → run → capture zone diffs →
stop → unmount. A run never reuses another run's filesystem, because a repetition set is a
distribution over *independent* runs (§13.2); sharing state between them would fabricate
consistency the skill does not have.

The model side is injected. At first-light there is no live provider (that lands in WP-13
with an observed egress path), so the caller supplies a :class:`ModelClient` per target —
a :class:`~bellwether.harness.ScriptedClient` for the corpus, the live client later. The
executor never imports a provider itself, so the ``harness → sandbox`` boundary and the
"no hard-coded model" rule both hold here.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from bellwether.capture import (
    Canary,
    CanaryPlanting,
    PlaneStatus,
    collect_filesystem_events,
    filesystem_writes_status,
    mint_canaries,
    plan_canary_planting,
)
from bellwether.cli.dns_run import DnsResolverProvider, RunResolver
from bellwether.cli.orchestrator import ExecutedRun, RunPlan
from bellwether.cli.proxy_run import RunProxy, SidecarProxyProvider
from bellwether.config.models.config import SandboxConfig, ZoneConfig
from bellwether.determinism import SeededRng, stable_hash
from bellwether.harness import (
    ApiLoopAdapter,
    ModelClient,
    OfferedSkill,
    RawHarnessEvent,
    RunLimits,
    SandboxToolset,
)
from bellwether.harness.tools import docker_exec_runner
from bellwether.sandbox import DockerBackend, IsolationProfile, ZoneMap, prepare_sandbox
from bellwether.skill import SkillPackage
from bellwether.trace import (
    IdentityBlock,
    NormalizationContext,
    PlantedCanary,
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
    assemble_coverage,
    canary_actions,
    dns_actions,
    egress_actions,
    exit_reason_from_events,
    filesystem_actions,
    harness_actions,
    read_trace,
    redact_trace_actions,
    token_totals_from_events,
    write_trace,
)

__all__ = [
    "SandboxRunExecutor",
    "isolation_from_config",
    "offered_skill",
    "zone_map_from_config",
]

#: A model client and the model id to request, for one matrix target. The client is what
#: the ``api-loop`` adapter drives; the id travels into the trace's ``model_id_requested``
#: so a divergence between requested and served is recorded (§9.4).
ClientFactory = Callable[["RunPlan"], tuple[ModelClient, str]]


def offered_skill(package: SkillPackage) -> OfferedSkill:
    """The skill as the harness offers it to the model — name, description, body.

    Drawn from the parsed ``SKILL.md`` so the sandbox sees exactly the payload a real
    agent would, and nothing under ``evals/`` (§9.1): a skill that can see the test
    machinery can behave only while observed.
    """
    frontmatter = package.parsed.frontmatter
    description = frontmatter.description if frontmatter is not None else ""
    return OfferedSkill(
        name=package.name,
        description=description or "",
        body=package.parsed.body,
    )


def isolation_from_config(sandbox: SandboxConfig) -> IsolationProfile:
    """Map ``sandbox.*`` config (§21) onto the isolation profile the backend renders (§9.2).

    The mapping lives in the ``cli`` layer, not on ``SandboxConfig``, because the module
    layering forbids ``config`` from importing ``sandbox`` — a config that constructed an
    ``IsolationProfile`` would reach *up* the stack. Only the resource and writable-path
    knobs a user actually configures are carried; the hardening fields (``cap_drop``,
    ``no_new_privileges``, ``uid``, seccomp) stay at the §9.2 baseline and are not
    user-overridable here.
    """
    return IsolationProfile(
        memory=sandbox.memory,
        cpus=sandbox.cpus,
        pids_limit=sandbox.pids_limit,
        timeout_seconds=sandbox.timeout_seconds,
        writable_paths=tuple(sandbox.writable_paths),
    )


def zone_map_from_config(zones: ZoneConfig) -> ZoneMap:
    """Map ``capture.zones`` config (§21) onto the zone map the sandbox mounts by (§10.2)."""
    return ZoneMap.from_config(
        workspace=zones.workspace,
        harness_state=zones.harness_state,
        scratch=zones.scratch,
    )


def _seed_from_eval_id(eval_id: str) -> int:
    """A stable, non-negative base seed derived from the evaluation id (§3.5, §24).

    Sixteen hex digits — 64 bits — is ample to separate evaluations, and the derivation is
    ``stable_hash`` so it does not depend on the process-salted builtin ``hash`` (§24).
    """
    return int(stable_hash(eval_id).removeprefix("sha256:")[:16], 16)


def _proxy_run_id(eval_id: str, plan: RunPlan) -> str:
    """A per-run token for the sidecar container and bridge names (§10.5).

    Docker container and network names must match ``[a-zA-Z0-9][a-zA-Z0-9_.-]*``; the run's
    coordinates can carry anything, so every other character is folded to ``-``. The token is not
    a container the sandbox can see, so unlike the sandbox's own hostname it need not hide the
    project — a leaked ``bw-int-…`` bridge is invisible from inside the sandbox.
    """
    raw = f"{eval_id}-{plan.scenario.id}-{plan.target.slug}-{plan.repetition:03d}"
    sanitized = "".join(ch if ch.isalnum() or ch in "_.-" else "-" for ch in raw)
    return sanitized.lstrip("-_.") or "run"


def _reported_model_id(events: Sequence[RawHarnessEvent], fallback: str) -> str:
    """The model id the provider said it served, read from the ``model_turn`` events.

    A silent divergence between requested and served is a model-version change that would
    make a regression comparison lie (§9.4), so it is recorded rather than assumed equal.
    """
    for event in events:
        if event.kind == "model_turn":
            reported = event.data.get("model_id_reported")
            if reported:
                return str(reported)
    return fallback


@dataclass
class SandboxRunExecutor:
    """Run one repetition in a container and return its trace (§10).

    Structurally satisfies :class:`~bellwether.cli.orchestrator.RunExecutor` (it provides
    ``execute(plan) -> ExecutedRun``) without inheriting the protocol, so it stays a plain
    dataclass.

    Args:
        backend: The Docker backend (image pinned on it).
        package: The parsed skill being evaluated.
        fixture: The workspace fixture source materialised into each sandbox.
        client_factory: Supplies ``(client, model_id)`` per run — the injection seam for
            the model side, scripted at first-light and live from WP-13.
        eval_id: The evaluation this run belongs to, stamped into the trace header.
        run_root: Where per-run sandbox directories and traces are written.
        rng_seed: Base seed; each run derives a distinct stream from it by coordinate.
        limits: Per-run turn/tool/token/wall ceilings.
        proxy: The recording-proxy provider (§10.5). When set, each run is stood up behind a
            dual-homed sidecar: the sandbox routes through it, its CA is trusted, and the flows
            it records become the trace's egress plane — so egress reads *observed* rather than
            unavailable. When ``None`` the sandbox runs with no network, exactly as first-light.
        resolver: The controlled-resolver provider (§10.6). When set, each run's sandbox is
            pointed at the resolver via ``--dns`` and the queries it records become Plane E — so
            DNS reads *observed*, and the covert channel that routes around the HTTP proxy is
            closed and logged. Shares the proxy's internal bridge when egress is on; creates its
            own when egress is off. When ``None`` DNS stays unavailable.
        plant_canaries: Whether to plant this evaluation's canaries and scan the observed planes
            for them (§10.4). When ``True``, per-evaluation markers are minted from a seed derived
            from ``eval_id``/``rng_seed`` (identical across the repetitions in an evaluation, so the
            run cache keyed on ``fixture_digest`` still hits — §9.3), the env-var canary is delivered
            into the container, and the host-side planes (the model's final output, DNS query names)
            are scanned for leaks into Plane C. When ``False`` the credentials plane stays
            unavailable. **File-slot planting (writable mounts) and egress-body scanning are not yet
            wired**, so with planting on the plane reads ``partial``, not ``full``.
    """

    backend: DockerBackend
    package: SkillPackage
    fixture: Path
    client_factory: ClientFactory
    eval_id: str
    run_root: Path
    rng_seed: int = 0
    limits: RunLimits = field(default_factory=RunLimits)
    proxy: SidecarProxyProvider | None = None
    resolver: DnsResolverProvider | None = None
    plant_canaries: bool = False
    #: The isolation profile every container in this evaluation runs under (§9.2). Defaults
    #: to the §9.2 baseline; the lead derives it from config via :func:`isolation_from_config`
    #: and passes it in from ``run.py`` so ``sandbox.memory``/``timeout_seconds``/… take effect
    #: rather than being silently ignored.
    isolation: IsolationProfile = field(default_factory=IsolationProfile)
    #: Where each captured zone is mounted (§10.2). Derived from config via
    #: :func:`zone_map_from_config`; the default matches the shipped ``capture.zones``.
    zones: ZoneMap = field(default_factory=ZoneMap)
    #: Whether sandbox identifiers are randomised (§3.5). Recorded in the trace either way, so
    #: a run with findable identifiers reads as a deliberate choice, not concealment.
    randomize_identifiers: bool = True

    def execute(self, plan: RunPlan) -> ExecutedRun:
        # Absolute, always: the sandbox directories become Docker bind-mount sources, and a
        # relative path there is read by the daemon as a (invalid) named volume, not a host
        # directory — so a run launched from a relative --out would fail at container start.
        run_dir = (
            self.run_root / plan.scenario.id / plan.target.slug / str(plan.repetition)
        ).resolve()
        prepared = prepare_sandbox(
            self.package,
            self.fixture,
            run_dir,
            rng=self._sandbox_rng(plan),
            zones=self.zones,
            isolation=self.isolation,
            randomize_identifiers=self.randomize_identifiers,
        )

        # Stand the recording proxy up first, before the sandbox that routes through it. A failure
        # here must not leave a mounted overlay behind, so it happens before mount; the proxy owns
        # its own cleanup on a failed open (no network or container leaks).
        run_proxy = self._open_proxy(plan, run_dir)
        # The controlled resolver shares the proxy's internal bridge when egress is on (one network,
        # both peers on it) and creates its own when egress is off; either way the sandbox is pointed
        # at it by IP with --dns. Opened after the proxy so it can join that bridge and be handed the
        # proxy's container name to resolve (§10.6).
        run_resolver = self._open_resolver(plan, run_dir, run_proxy)
        if run_proxy is not None:
            network = run_proxy.sandbox_network()
        elif run_resolver is not None:
            network = run_resolver.sandbox_network()
        else:
            network = "none"
        dns = run_resolver.sandbox_dns() if run_resolver is not None else None
        # This evaluation's canaries (§10.4). Minted per *evaluation*, not per repetition, so the
        # markers are identical across the runs in an evaluation. Planting only stages the env-var
        # canary for now; the file slots are recorded but their delivery is the next brick.
        canaries = self._canaries()
        planting = plan_canary_planting(canaries) if canaries else None
        # The canaries whose markers actually reached the container this run — the ones the planner
        # delivered as env vars. Derived from the planner's own output so the env-vs-file placement
        # rule lives only there, and only a delivered marker is ever scanned for or recorded as planted.
        delivered = set(planting.env.values()) if planting is not None else set()
        planted = [c for c in canaries if c.marker in delivered]
        extra_env = self._extra_env(plan, run_proxy, planting)
        extra_ro_binds = run_proxy.sandbox_ro_binds() if run_proxy is not None else None

        try:
            self.backend.mount(prepared)
            self.backend.start_persistent(
                prepared,
                network=network,
                dns=dns,
                extra_env=extra_env,
                extra_ro_binds=extra_ro_binds,
            )
            client, model_id = self.client_factory(plan)
            adapter = ApiLoopAdapter(
                client,
                SandboxToolset(docker_exec_runner(self.backend, prepared)),
                skills=(offered_skill(self.package),),
            )
            started_at = dt.datetime.now(dt.UTC)
            prompt = plan.scenario.prompt
            prompt_text = prompt if isinstance(prompt, str) else "\n".join(prompt)
            events = list(adapter.run(prompt_text, model_id=model_id, limits=self.limits))
            observed_at = dt.datetime.now(dt.UTC)

            plane_a = harness_actions(events)
            zone_diffs = self.backend.zone_changes(prepared)
            plane_b = filesystem_actions(
                collect_filesystem_events(
                    zone_diffs,
                    prepared.zones,
                    workspace_root=prepared.identifiers.workspace_root,
                ),
                observed_at=observed_at,
                start_seq=len(plane_a),
            )
            # Plane D: what the recording proxy saw. Read while the sidecar is still up (before the
            # finally closes it). Absent a proxy, there is no egress plane and coverage says so.
            egress_flows = run_proxy.flows() if run_proxy is not None else []
            plane_d = egress_actions(egress_flows, start_seq=len(plane_a) + len(plane_b))
            # Plane E: what the controlled resolver saw. Read while the resolver is still up (before
            # the finally closes it). Absent a resolver, there is no DNS plane and coverage says so.
            dns_queries = run_resolver.queries() if run_resolver is not None else []
            plane_e = dns_actions(dns_queries, start_seq=len(plane_a) + len(plane_b) + len(plane_d))
            # Plane C: canaries are not a plane the sandbox emits — they are *found* in what the
            # other planes recorded (§10.4). Scan the host-side sources (the model's final output in
            # Plane A, the DNS query names in Plane E) for the markers actually planted this run, and
            # correlate each hit back to the source that carried it. Egress *bodies* are scanned
            # sidecar-side (the body never leaves the proxy), so Plane D is not a source here yet.
            plane_c = canary_actions(
                plane_a + plane_e,
                planted,
                start_seq=len(plane_a) + len(plane_b) + len(plane_d) + len(plane_e),
            )

            header = RunHeader(
                run_id=f"{self.eval_id}-{plan.scenario.id}-{plan.target.slug}-{plan.repetition:03d}",
                eval_id=self.eval_id,
                scenario_id=plan.scenario.id,
                repetition=plan.repetition,
                skill=SkillRef(
                    name=self.package.name,
                    package_digest=self.package.package_digest,
                    payload_digest=self.package.payload_digest,
                    source=str(self.package.root),
                ),
                target=TargetRef(
                    harness=adapter.name,
                    harness_version=adapter.version(),
                    provider=plan.target.provider,
                    model_alias=plan.target.model_alias,
                    model_id_requested=model_id,
                    model_id_reported=_reported_model_id(events, model_id),
                    harness_capabilities=adapter.capabilities().as_record(),
                ),
                sandbox=SandboxRef(
                    image=self.backend.image,
                    workspace_root=str(prepared.identifiers.workspace_root),
                ),
                identity=self._identity_block(planting, planted),
                coverage=assemble_coverage(
                    harness_events=PlaneStatus(fidelity="full") if events else None,
                    filesystem_writes=filesystem_writes_status(set(zone_diffs)),
                    # The proxy writing its flow log is proof the egress plane was captured, even
                    # at zero flows — an observed-clean run, not an unobserved one (§10.7).
                    egress=PlaneStatus(fidelity="full") if run_proxy is not None else None,
                    # Same for the resolver's query log: a zero-query run is observed-clean DNS.
                    dns=PlaneStatus(fidelity="full") if run_resolver is not None else None,
                    # Canaries planted: the env-var channel is observed, but file-slot planting and
                    # egress-body scanning are not yet wired, so the plane reads partial not full.
                    credentials=(
                        PlaneStatus(
                            fidelity="partial",
                            reason=(
                                "canaries planted as environment variables and scanned in the "
                                "model output and DNS query names; file-slot planting (writable "
                                "mounts) and egress-body scanning are not yet wired"
                            ),
                        )
                        if planting is not None
                        else None
                    ),
                ),
                started_at=started_at,
            )
            # A run with no exit event never reached an end Bellwether observed; that is a
            # harness_error (not_evaluable, §12.7), never a silent success.
            exit_reason = exit_reason_from_events(events) or "harness_error"
            footer = RunFooter(
                ended_at=observed_at,
                wall_clock_ms=int((observed_at - started_at).total_seconds() * 1000),
                exit_reason=exit_reason,
                tokens=token_totals_from_events(events),
            )

            # Redact leaked markers before the trace is written (§10.4.3): a canary a skill routed
            # into its final output or a DNS name would otherwise land raw in the uploaded artifact.
            # Runs after canary_actions (which needed the raw marker to find the leak) and over every
            # plane, so no artifact holds a value the Plane C finding has already recorded escaped.
            actions = redact_trace_actions(plane_a + plane_b + plane_d + plane_e + plane_c, planted)
            trace_path = write_trace(
                run_dir / "trace.arf.jsonl",
                header,
                actions,
                footer,
            )
            jsonl = trace_path.read_text(encoding="utf-8")
            trace = read_trace(trace_path)
        finally:
            self.backend.stop_persistent(prepared)
            self.backend.unmount(prepared)
            # The resolver goes first: when it joined the proxy's bridge, the proxy's close removes
            # that bridge, which a still-attached resolver container would block.
            if run_resolver is not None:
                run_resolver.close()
            if run_proxy is not None:
                run_proxy.close()

        context = NormalizationContext(workspace_root=str(prepared.identifiers.workspace_root))
        return ExecutedRun(trace=trace, context=context, trace_jsonl=jsonl)

    def _sandbox_rng(self, plan: RunPlan) -> SeededRng:
        """The per-run RNG stream — distinct per evaluation *and* per matrix coordinate (§3.5).

        ``eval_id`` is mixed into both the base seed and the stream label. Without it, a fixed
        ``rng_seed`` (its default is 0) draws the *same* hostname and container name for the same
        ``(scenario, target, repetition)`` in every evaluation: identical names collide the moment
        two evaluations run concurrently, and a container whose name is reproducible across
        evaluations is itself the §3.5 environment tell randomisation exists to remove. Mixing
        ``eval_id`` keeps reproducibility where it belongs — the same ``(eval_id, rng_seed,
        coordinate)`` still yields the same stream — while separating one evaluation from the next.
        """
        coordinate = f"{plan.scenario.id}/{plan.target.slug}/{plan.repetition}"
        seed = self.rng_seed ^ _seed_from_eval_id(self.eval_id)
        return SeededRng(seed, f"{self.eval_id}/{coordinate}")

    def _extra_env(
        self, plan: RunPlan, run_proxy: RunProxy | None, planting: CanaryPlanting | None
    ) -> dict[str, str]:
        """Environment delivered into the container: the scenario's env, the canary env, the proxy's.

        A scenario's ``env`` values may be canaries (§7.2), so they have to actually reach the
        container rather than being dropped on the floor — this is the only delivery path for them.
        The planted canary env vars are merged next (§10.4): a canary plant is a §21 core control, so
        it wins over a scenario that would otherwise shadow the name. The proxy's wiring
        (``HTTPS_PROXY`` and the CA-trust vars) is merged last so nothing — scenario or canary — can
        unset the very channel egress is observed through. All then merge last-wins over the
        sandbox's pinned base env inside ``build_argv``.
        """
        env: dict[str, str] = dict(plan.scenario.env)
        if planting is not None:
            env.update(planting.env)
        if run_proxy is not None:
            env.update(run_proxy.sandbox_env())
        return env

    def _canary_seed(self) -> int:
        """The per-*evaluation* canary seed (§9.3, §10.4).

        Mixes ``eval_id`` into the base seed exactly as :meth:`_sandbox_rng` does, but with no matrix
        coordinate: markers must be identical across the repetitions within an evaluation (so the run
        cache keyed on ``fixture_digest`` still hits, and a leak fingerprints the same in every
        repetition), while still differing between evaluations. :func:`mint_canaries` opens its own
        ``"canary"`` stream from this, distinct from the sandbox-identifier stream.
        """
        return self.rng_seed ^ _seed_from_eval_id(self.eval_id)

    def _canaries(self) -> list[Canary]:
        """Mint this evaluation's canaries, or none when planting is off (§10.4)."""
        if not self.plant_canaries:
            return []
        return mint_canaries(self._canary_seed())

    def _identity_block(
        self, planting: CanaryPlanting | None, planted: list[Canary]
    ) -> IdentityBlock:
        """What was planted, by reference (§9.3, §10.4.3).

        Records the canary seed (so the evaluation is reproducible from its own artifacts) and the
        *delivered* canaries as marker-free references — id, path, kind, never the value. Only the
        canaries actually delivered into the container this run are listed: a slot recorded as planted
        that was not would be a declaration the evidence does not back (§10.0).
        """
        if planting is None:
            return IdentityBlock()
        return IdentityBlock(
            env_credential_names=sorted(planting.env),
            canary_seed=str(self._canary_seed()),
            canaries_planted=[PlantedCanary(id=c.id, path=c.path, kind=c.kind) for c in planted],
        )

    def _open_proxy(self, plan: RunPlan, run_dir: Path) -> RunProxy | None:
        """Stand the recording proxy up for one run, or ``None`` when no proxy is configured.

        The per-run id names the sidecar container and its two bridges; it is derived from the
        run's coordinates and sanitised to the characters Docker names allow, so a name collision
        cannot smuggle shell metacharacters into a ``docker`` argv.
        """
        if self.proxy is None:
            return None
        run_id = _proxy_run_id(self.eval_id, plan)
        return self.proxy.open(run_id, shared_dir=run_dir / "proxy")

    def _open_resolver(
        self, plan: RunPlan, run_dir: Path, run_proxy: RunProxy | None
    ) -> RunResolver | None:
        """Stand the controlled resolver up for one run, or ``None`` when none is configured.

        When the proxy is on, the resolver joins its internal bridge (so the sandbox reaches both on
        one network) and is handed the proxy's container name to resolve — without it the sandbox
        could not look up ``HTTPS_PROXY`` through the controlled resolver. When the proxy is off, the
        resolver owns a fresh internal bridge. The same sanitised per-run id names the container.
        """
        if self.resolver is None:
            return None
        run_id = _proxy_run_id(self.eval_id, plan)
        network = run_proxy.sandbox_network() if run_proxy is not None else None
        extra_allowed = [run_proxy.sidecar.container_name()] if run_proxy is not None else []
        return self.resolver.open(
            run_id,
            shared_dir=run_dir / "resolver",
            network=network,
            extra_allowed=extra_allowed,
        )
