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
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from bellwether.capture import (
    Canary,
    CanaryPlanting,
    HostEventSink,
    ModelChannelScanner,
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
from bellwether.errors import BellwetherError
from bellwether.harness import (
    ApiLoopAdapter,
    ClaudeCodeAdapter,
    LaunchResult,
    ModelClient,
    OfferedSkill,
    RawHarnessEvent,
    RunLimits,
    SandboxToolset,
    claude_code_environment,
    hook_settings,
)
from bellwether.harness.claude_code import DEFAULT_SINK_CONTAINER_PATH
from bellwether.harness.tools import docker_exec_runner
from bellwether.sandbox import (
    DockerBackend,
    IsolationProfile,
    PreparedSandbox,
    ZoneMap,
    prepare_sandbox,
)
from bellwether.sandbox.docker import StreamedExec
from bellwether.skill import SkillPackage
from bellwether.trace import (
    Action,
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
    egress_body_actions,
    exit_reason_from_events,
    filesystem_actions,
    harness_actions,
    model_channel_actions,
    read_trace,
    redact_trace_actions,
    token_totals_from_events,
    tool_result_actions,
    write_trace,
    written_file_actions,
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

#: How many bytes of a written file are read for the canary scan. Matches the scan's own
#: ``MAX_SCAN_CHARS`` bound (§10.4.2): an unbounded read of a skill-written file is the same
#: CPU/memory exhaustion vector the scan already guards, reached through the filesystem. A marker
#: past this point in a single file is the documented limit, on the same footing as the scan's.
_CANARY_FILE_SCAN_BYTES = 262_144


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


def _resolve_canary_path(slot_path: str, *, home: str, workspace_root: str) -> PurePosixPath:
    """Resolve a canary slot path to the absolute container path it is planted at (§10.4).

    ``~/x`` maps to the container ``HOME`` — the realistic home of ``~/.aws/credentials`` and the
    like; a bare relative path maps to the workspace root, a skill's working directory, where a ``.env``
    naturally sits; an absolute path is taken verbatim. The result is where the read-only bind lands so
    a thieving skill finds the credential exactly where a real one would live.
    """
    if slot_path.startswith("~/"):
        return PurePosixPath(home) / slot_path[2:]
    if slot_path.startswith("/"):
        return PurePosixPath(slot_path)
    return PurePosixPath(workspace_root) / slot_path


class _DockerLaunch:
    """The claude-code adapter's launcher, bound to a run's persistent container.

    The whole coupling between the adapter and the backend: the CLI argv becomes one
    streamed ``docker exec`` against the container ``start_persistent`` opened, with the
    workspace root as its working directory and its stderr filed under the run directory.
    """

    def __init__(self, backend: DockerBackend, prepared: PreparedSandbox, run_dir: Path) -> None:
        self._backend = backend
        self._prepared = prepared
        self._run_dir = run_dir

    def __call__(self, argv: list[str], timeout: float) -> _DockerLaunched:
        streamed = self._backend.exec_stream(
            self._prepared, argv, timeout=timeout, stderr_path=self._run_dir / "harness-stderr.log"
        )
        return _DockerLaunched(streamed)


class _DockerLaunched:
    def __init__(self, streamed: StreamedExec) -> None:
        self._streamed = streamed

    def lines(self) -> Iterator[str]:
        return self._streamed.lines()

    def wait(self) -> LaunchResult:
        end = self._streamed.wait()
        return LaunchResult(
            exit_code=end.exit_code, timed_out=end.timed_out, stderr_tail=end.stderr_tail
        )


def _harness_events_status(
    adapter: ApiLoopAdapter | ClaudeCodeAdapter, events: Sequence[RawHarnessEvent]
) -> PlaneStatus | None:
    """Plane A's fidelity for this run (§10.7).

    On api-loop the loop *is* the harness, so an event stream is the whole plane. On
    claude-code the plane is the CLI's stdout corroborated by its hook stream on the host
    sink; where the hook stream is empty or disagrees, the plane is ``partial`` with the
    reason, so an assertion reading Plane A's silence knows what it rests on.
    """
    if not events:
        return None
    if isinstance(adapter, ClaudeCodeAdapter) and adapter.reconciliation is not None:
        reason = adapter.reconciliation.coverage_reason()
        if reason is not None:
            return PlaneStatus(fidelity="partial", reason=reason)
    return PlaneStatus(fidelity="full")


def _tool_result_sources(
    plane_a: Sequence[Action], texts: Sequence[tuple[str, str, str]]
) -> list[tuple[Action, str]]:
    """Pair each tool result's full text with the Plane A action that recorded it."""
    by_call_id = {
        str(action.action.get("tool_call_id")): action
        for action in plane_a
        if action.kind == "tool_result"
    }
    return [(by_call_id[call_id], text) for call_id, _tool, text in texts if call_id in by_call_id]


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
            run cache keyed on ``fixture_digest`` still hits — §9.3), the whole pool is delivered
            into the container (the env-var canary as an environment variable, the file canaries as
            read-only binds at their slot paths — ``~/.aws/credentials``, ``.env``, …), and the
            host-side planes (the model's final output, DNS query names) are scanned for leaks into
            Plane C. When ``False`` the credentials plane stays unavailable. The plane reads
            ``partial`` not ``full`` because the scan does not yet cover egress bodies (sidecar-side),
            written-file contents, or tool arguments.
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
    #: Provider name → its configured ``base_url`` (``None`` for the provider default), for a
    #: ``claude-code`` target whose CLI talks to the API from inside the sandbox and needs to
    #: be pointed at the same endpoint the proxy allowlists as ``model_api``.
    provider_base_urls: Mapping[str, str | None] = field(default_factory=dict)

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

        # This evaluation's canaries (§10.4). Minted per *evaluation*, not per repetition, so the
        # markers are identical across the runs in an evaluation. The whole pool is delivered — the
        # env-var canary through the env, the file canaries as read-only binds — so every minted
        # canary is a planted one, scanned for, redacted, and recorded by reference in the header.
        # Computed before the proxy standup because the proxy scans request bodies for these markers.
        canaries = self._canaries()
        planting = plan_canary_planting(canaries) if canaries else None

        # Stand the recording proxy up first, before the sandbox that routes through it. A failure
        # here must not leave a mounted overlay behind, so it happens before mount; the proxy owns
        # its own cleanup on a failed open (no network or container leaks). It is handed the run's
        # canaries so it scans each request body for them (§10.5.2).
        run_proxy = self._open_proxy(plan, run_dir, canaries)
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
        extra_env = self._extra_env(plan, run_proxy, planting)
        ro_binds: list[tuple[Path, PurePosixPath]] = (
            list(run_proxy.sandbox_ro_binds()) if run_proxy is not None else []
        )
        ro_binds += self._stage_canary_files(planting, prepared, run_dir)
        extra_ro_binds = ro_binds or None

        # The harness: the api-loop reference (the model runs host-side, tools exec into the
        # sandbox) or the real Claude Code CLI *inside* the sandbox (§9.4). The CLI's own
        # model calls leave only through the proxy carrying the sandbox-scoped token, and its
        # hook stream lands on the host-owned sink — both stood up here, before the container.
        use_claude_code = plan.target.harness == "claude-code"
        sink: HostEventSink | None = None
        sink_bind: tuple[Path, PurePosixPath] | None = None
        if use_claude_code:
            if run_proxy is None:
                raise BellwetherError(
                    "a claude-code target needs the recording proxy: the CLI's model calls "
                    "originate inside the sandbox and have no route out but the proxy, which "
                    "injects the real key (§3.3 invariant 1); set egress.image in config.yaml"
                )
            sink = HostEventSink((run_dir / "events").resolve())
            sink.start()
            sink_bind = (sink.path, PurePosixPath(DEFAULT_SINK_CONTAINER_PATH))
            extra_env.update(
                claude_code_environment(
                    api_token=run_proxy.sandbox_credential(plan.target.provider),
                    base_url=self.provider_base_urls.get(plan.target.provider),
                    config_dir=str(prepared.zones.harness_state),
                )
            )

        try:
            self.backend.mount(prepared)
            self.backend.start_persistent(
                prepared,
                network=network,
                dns=dns,
                sink_bind=sink_bind,
                extra_env=extra_env,
                extra_ro_binds=extra_ro_binds,
            )
            started_at = dt.datetime.now(dt.UTC)
            prompt = plan.scenario.prompt
            prompt_text = prompt if isinstance(prompt, str) else "\n".join(prompt)
            scanner: ModelChannelScanner | None = None
            adapter: ApiLoopAdapter | ClaudeCodeAdapter
            if use_claude_code:
                assert sink is not None
                hook_sink = sink
                claude = ClaudeCodeAdapter(
                    _DockerLaunch(self.backend, prepared, run_dir),
                    hook_source=lambda: [event.payload for event in hook_sink.stop()],
                    settings=hook_settings(DEFAULT_SINK_CONTAINER_PATH),
                )
                adapter = claude
                _client, model_id = self.client_factory(plan)
            else:
                client, model_id = self.client_factory(plan)
                # The model-API channel scan (§10.4.1): every request the loop composes is
                # scanned host-side for the run's canaries before it leaves, graded by whether
                # a tool-result block carried the marker into context (the recorded read).
                # This is the residual channel §2 names — it cannot be blocked, so it is
                # observed; wiring it is what lifts the credentials plane to `full`.
                scanner = ModelChannelScanner(client, tuple(canaries)) if canaries else None
                adapter = ApiLoopAdapter(
                    scanner if scanner is not None else client,
                    SandboxToolset(docker_exec_runner(self.backend, prepared)),
                    skills=(offered_skill(self.package),),
                )
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
            # other planes recorded (§10.4). Scan the host-side sources — the model's final output and
            # tool-call arguments in Plane A, the non-model request URLs in Plane D, the DNS query
            # names in Plane E — for the markers planted this run, and correlate each hit back to the
            # source that carried it. The Plane C sequence space follows the other planes.
            plane_c_base = len(plane_a) + len(plane_b) + len(plane_d) + len(plane_e)
            plane_c = canary_actions(plane_a + plane_d + plane_e, canaries, start_seq=plane_c_base)
            # The contents of files the skill *wrote*: Plane B records writes by hash only, so the
            # bytes are read host-side here and scanned — a marker in a written file is a written_file
            # leak correlated to the Plane B write that created it (§10.4.1). The content never enters
            # the trace, so there is nothing to redact for it.
            plane_c += self._written_file_leaks(
                prepared, plane_b, canaries, start_seq=plane_c_base + len(plane_c)
            )
            # The recorded reads on a harness whose model channel is only visible at the proxy:
            # the full text of every tool result the CLI reported, scanned for the run's
            # markers — a hit is the §10.4.1 read (`canary_in_context`, info), anchored to the
            # tool_result that carried it, and what grades the body hits below.
            if isinstance(adapter, ClaudeCodeAdapter):
                plane_c += tool_result_actions(
                    _tool_result_sources(plane_a, adapter.tool_result_texts),
                    canaries,
                    start_seq=plane_c_base + len(plane_c),
                )
            read_ids = frozenset(
                str(action.action.get("canary_id"))
                for action in plane_c
                if action.kind == "canary_in_context"
            )
            # And the request *bodies* the proxy scanned sidecar-side (the body never leaves the
            # proxy): the hits arrive on each flow, already located, so they are paired with their
            # Plane D egress action and recorded as body leaks (§10.5.2). ``egress_flows[i]`` is the
            # flow ``plane_d[i]`` was built from, so the two line up by position. A model-endpoint
            # hit is graded by whether a recorded read carried that canary into context.
            plane_c += egress_body_actions(
                list(zip(plane_d, (flow.canary_hits for flow in egress_flows), strict=True)),
                start_seq=plane_c_base + len(plane_c),
                read_canary_ids=read_ids,
            )
            # And the model-API channel: what the host-side scanner found in each composed
            # request, graded by read state and anchored to the model turn the request
            # produced (§10.4.1). This is the channel whose absence kept the plane partial.
            plane_c += model_channel_actions(
                scanner.scans if scanner is not None else [],
                plane_a,
                start_seq=plane_c_base + len(plane_c),
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
                    harness_capabilities=(
                        adapter.capabilities_record()
                        if isinstance(adapter, ClaudeCodeAdapter)
                        else adapter.capabilities().as_record()
                    ),
                ),
                sandbox=SandboxRef(
                    image=self.backend.image,
                    workspace_root=str(prepared.identifiers.workspace_root),
                ),
                identity=self._identity_block(planting, canaries),
                coverage=assemble_coverage(
                    harness_events=_harness_events_status(adapter, events),
                    filesystem_writes=filesystem_writes_status(set(zone_diffs)),
                    # The proxy writing its flow log is proof the egress plane was captured, even
                    # at zero flows — an observed-clean run, not an unobserved one (§10.7).
                    egress=PlaneStatus(fidelity="full") if run_proxy is not None else None,
                    # Same for the resolver's query log: a zero-query run is observed-clean DNS.
                    dns=PlaneStatus(fidelity="full") if run_resolver is not None else None,
                    # Canaries planted (env var + file slots) and scanned across every channel a
                    # value can move on: the model output, DNS query names, tool-call arguments,
                    # non-model egress URLs *and bodies* (bodies sidecar-side), written-file
                    # contents, and — since the model-channel scan landed — every composed model
                    # request, graded canary_in_context vs canary_without_read by the per-request
                    # read state (§10.4.1). With that last channel observed, the plane is `full`.
                    credentials=(PlaneStatus(fidelity="full") if planting is not None else None),
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
            actions = redact_trace_actions(
                plane_a + plane_b + plane_d + plane_e + plane_c, canaries
            )
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
            if sink is not None:
                sink.stop()  # idempotent: the adapter normally drained it already
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

    def _stage_canary_files(
        self, planting: CanaryPlanting | None, prepared: PreparedSandbox, run_dir: Path
    ) -> list[tuple[Path, PurePosixPath]]:
        """Write each file canary to a host file and bind it read-only at its slot path (§10.4).

        Read-only is enough and safer: a thief only needs to *read* the credential, and a read-only
        mount cannot be tampered into concealing the plant. The bind is how the marker reaches the
        container without reaching the trace — the header records the slot by reference only (§10.4.3).
        The host paths are resolved absolute because a Docker bind source must be (a relative one is
        read as a named volume and fails at container start).
        """
        if planting is None or not planting.files:
            return []
        home = prepared.environment().get("HOME", "/home/agent")
        workspace_root = str(prepared.identifiers.workspace_root)
        canary_dir = (run_dir / "canaries").resolve()
        canary_dir.mkdir(parents=True, exist_ok=True)
        binds: list[tuple[Path, PurePosixPath]] = []
        for index, (slot_path, content) in enumerate(planting.files):
            host_file = canary_dir / f"f{index}"
            host_file.write_text(content, encoding="utf-8")
            binds.append(
                (
                    host_file,
                    _resolve_canary_path(slot_path, home=home, workspace_root=workspace_root),
                )
            )
        return binds

    def _written_file_leaks(
        self,
        prepared: PreparedSandbox,
        plane_b: list[Action],
        canaries: list[Canary],
        *,
        start_seq: int,
    ) -> list[Action]:
        """Scan the contents of files the skill wrote for planted markers (§10.4).

        Plane B records writes by hash, not bytes, so the content is read here from the host-side
        overlay upper directory — the same files the diff already hashed, so no *new* file is opened,
        and only regular files are read (never a FIFO/socket/device the container made, §10.0). Each
        read is bounded to :data:`_CANARY_FILE_SCAN_BYTES`. A marker found is a ``written_file`` leak
        correlated to the Plane B write; the content itself never enters the trace.
        """
        if not canaries:
            return []
        zone_uppers: dict[str, Path] = {"workspace": prepared.upper_dir}
        for zone in prepared.captured_zones:
            zone_uppers[zone.zone] = zone.upper

        sources: list[tuple[Action, str]] = []
        for action in plane_b:
            payload = action.action
            if payload.get("change") not in ("created", "modified"):
                continue  # a deletion or a mode change carries no new content to scan
            if payload.get("special") or payload.get("file_type", "regular") != "regular":
                continue  # directories, symlinks, and the special files §10.0 forbids opening
            upper = zone_uppers.get(str(payload.get("zone")))
            relative = payload.get("zone_relative")
            if upper is None or not isinstance(relative, str):
                continue
            try:
                with (upper / relative).open("rb") as handle:
                    content = handle.read(_CANARY_FILE_SCAN_BYTES).decode("utf-8", "replace")
            except OSError:
                continue  # a race or permission error: skip rather than fail the whole run
            sources.append((action, content))
        return written_file_actions(sources, canaries, start_seq=start_seq)

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

    def _open_proxy(self, plan: RunPlan, run_dir: Path, canaries: list[Canary]) -> RunProxy | None:
        """Stand the recording proxy up for one run, or ``None`` when no proxy is configured.

        The per-run id names the sidecar container and its two bridges; it is derived from the
        run's coordinates and sanitised to the characters Docker names allow, so a name collision
        cannot smuggle shell metacharacters into a ``docker`` argv. The run's canaries travel into
        the sidecar config so the proxy scans each request body for them (§10.5.2).
        """
        if self.proxy is None:
            return None
        run_id = _proxy_run_id(self.eval_id, plan)
        return self.proxy.open(run_id, shared_dir=run_dir / "proxy", canaries=canaries)

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
