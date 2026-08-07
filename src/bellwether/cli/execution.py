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
    PlaneStatus,
    collect_filesystem_events,
    filesystem_writes_status,
)
from bellwether.cli.orchestrator import ExecutedRun, RunPlan
from bellwether.determinism import SeededRng
from bellwether.harness import (
    ApiLoopAdapter,
    ModelClient,
    OfferedSkill,
    RawHarnessEvent,
    RunLimits,
    SandboxToolset,
)
from bellwether.harness.tools import docker_exec_runner
from bellwether.sandbox import DockerBackend, prepare_sandbox
from bellwether.skill import SkillPackage
from bellwether.trace import (
    NormalizationContext,
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
    assemble_coverage,
    exit_reason_from_events,
    filesystem_actions,
    harness_actions,
    read_trace,
    token_totals_from_events,
    write_trace,
)

__all__ = ["SandboxRunExecutor", "offered_skill"]

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
    """

    backend: DockerBackend
    package: SkillPackage
    fixture: Path
    client_factory: ClientFactory
    eval_id: str
    run_root: Path
    rng_seed: int = 0
    limits: RunLimits = field(default_factory=RunLimits)

    def execute(self, plan: RunPlan) -> ExecutedRun:
        # Absolute, always: the sandbox directories become Docker bind-mount sources, and a
        # relative path there is read by the daemon as a (invalid) named volume, not a host
        # directory — so a run launched from a relative --out would fail at container start.
        run_dir = (
            self.run_root / plan.scenario.id / plan.target.slug / str(plan.repetition)
        ).resolve()
        rng = SeededRng(self.rng_seed, f"{plan.scenario.id}/{plan.target.slug}/{plan.repetition}")
        prepared = prepare_sandbox(self.package, self.fixture, run_dir, rng=rng)

        self.backend.mount(prepared)
        self.backend.start_persistent(prepared)
        try:
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
                coverage=assemble_coverage(
                    harness_events=PlaneStatus(fidelity="full") if events else None,
                    filesystem_writes=filesystem_writes_status(set(zone_diffs)),
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

            trace_path = write_trace(run_dir / "trace.arf.jsonl", header, plane_a + plane_b, footer)
            jsonl = trace_path.read_text(encoding="utf-8")
            trace = read_trace(trace_path)
        finally:
            self.backend.stop_persistent(prepared)
            self.backend.unmount(prepared)

        context = NormalizationContext(workspace_root=str(prepared.identifiers.workspace_root))
        return ExecutedRun(trace=trace, context=context, trace_jsonl=jsonl)
