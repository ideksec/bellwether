"""The library-wide trigger-collision matrix (§7.4) and its baseline.

A small library with a greedy member whose description claims everything, driven through the
real per-member evaluation (``run_evaluation`` on the scripted executor) with the whole library
offered beside each probe. The matrix shows the greedy skill winning the others' activations;
the stored baseline then shows the delta when it stops. The probe-selection rule, the one-target
and api-loop refusals, the library key, and the command's front door are pinned beside it.
"""

from __future__ import annotations

import datetime as dt
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bellwether.cli.app import app
from bellwether.cli.coexistence import (
    COEXISTENCE_N,
    NO_ACTIVATION,
    CoexistenceMatrix,
    compare_with_baseline,
    library_key,
    library_members,
    load_library_baseline,
    probe_scenarios_for,
    render_coexistence_json,
    render_coexistence_markdown,
    resolve_coexistence_target,
    run_coexistence,
    write_library_baseline,
)
from bellwether.cli.orchestrator import ExecutedRun, RunPlan
from bellwether.errors import BellwetherError
from bellwether.harness import (
    ApiLoopAdapter,
    ModelClient,
    ModelTurn,
    OfferedSkill,
    RunLimits,
    SandboxToolset,
    ScriptedClient,
    ToolCallRequest,
    TurnUsage,
)
from bellwether.skill import SkillPackage
from bellwether.skill.probes import ACTIVATION_PROBE_ID
from bellwether.trace import (
    Coverage,
    NormalizationContext,
    PlaneCoverage,
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
    exit_reason_from_events,
    harness_actions,
    read_trace,
    token_totals_from_events,
    write_trace,
)
from tests.test_run import _ENVIRON, _config, _fixed_clock, _NoopExec, _policy

runner = CliRunner()

_CREATED = "2026-10-29T01:00:00+00:00"

# ---------------------------------------------------------------------------
# A library: alpha (marked probes), beta (one should_trigger), greedy (no scenarios)
# ---------------------------------------------------------------------------

_SUITE_HEAD = "apiVersion: bellwether/v1\nkind: ScenarioSuite\nscenarios:\n"


def _skill(root: Path, name: str, description: str, scenarios: str | None) -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\nbody of {name}\n", encoding="utf-8"
    )
    if scenarios is not None:
        (directory / "evals").mkdir()
        (directory / "evals" / "scenarios.yaml").write_text(
            _SUITE_HEAD + scenarios, encoding="utf-8"
        )
    return directory


def _library(root: Path) -> Path:
    library = root / "skills"
    _skill(
        library,
        "alpha",
        "Summarises the team's standup notes.",
        "  - id: act\n    expectation: should_trigger\n    probe: activation\n"
        '    prompt: "Summarise standup."\n    assert:\n      - skill_activated: true\n'
        "  - id: rep\n    expectation: should_trigger\n    probe: representative\n"
        '    prompt: "Write the standup summary."\n    assert:\n      - skill_activated: true\n'
        "  - id: other\n    expectation: should_trigger\n"
        '    prompt: "Another task."\n    assert:\n      - skill_activated: true\n',
    )
    _skill(
        library,
        "beta",
        "Compiles a changelog from commits.",
        "  - id: compile\n    expectation: should_trigger\n"
        '    prompt: "Compile the changelog."\n    assert:\n      - skill_activated: true\n',
    )
    _skill(library, "greedy", "Does anything you ask, whatever it is.", None)
    return library


# ---------------------------------------------------------------------------
# A scripted executor whose activation depends on who is offered
# ---------------------------------------------------------------------------

Decide = Callable[[str, tuple[str, ...]], str | None]


class _CoexistenceExecutor:
    """Runs the scripted api-loop with the primary *and its companions* offered; ``decide``
    names which offered skill the model loads for a prompt (``None`` for no activation)."""

    def __init__(
        self,
        package: SkillPackage,
        tmp_path: Path,
        client_factory: Callable[[RunPlan], tuple[ModelClient, str]],
        decide: Decide,
        *,
        qualify: bool = False,
    ) -> None:
        self.package = package
        self.tmp_path = tmp_path
        self.client_factory = client_factory
        self.decide = decide
        #: Report activations the way the real CLI reports a plugin-staged skill: qualified
        #: by its bundle (``demo-bundle:alpha``).
        self.qualify = qualify
        self._lock = threading.Lock()
        self.offered: list[tuple[str, ...]] = []

    def execute(self, plan: RunPlan) -> ExecutedRun:
        _client, model_id = self.client_factory(plan)
        offered = (self.package, *plan.companions)
        names = tuple(sorted(p.name for p in offered))
        prompt = plan.scenario.prompt if isinstance(plan.scenario.prompt, str) else ""
        winner = self.decide(prompt, names)
        with self._lock:
            self.offered.append(names)
        turns = (
            [
                ModelTurn(
                    stop_reason="tool_use",
                    usage=TurnUsage(input=100, output=10),
                    tool_calls=(ToolCallRequest(id="t1", name="skill", input={"name": winner}),),
                ),
                ModelTurn(text="done", usage=TurnUsage(input=50, output=5)),
            ]
            if winner is not None
            else [ModelTurn(text="done without a skill", usage=TurnUsage(input=50, output=5))]
        )
        adapter = ApiLoopAdapter(
            ScriptedClient(turns, model_id_reported="model-as-served"),
            SandboxToolset(_NoopExec()),
            skills=tuple(
                OfferedSkill(name=p.name, description=p.description, body="b") for p in offered
            ),
            clock=_fixed_clock(),
        )
        events = list(adapter.run(prompt, model_id=model_id, limits=RunLimits()))
        header = RunHeader(
            run_id=f"{plan.scenario.id}-{plan.target.slug}-{plan.repetition:03d}",
            eval_id="e",
            scenario_id=plan.scenario.id,
            repetition=plan.repetition,
            skill=SkillRef(
                name=self.package.name,
                package_digest=self.package.package_digest,
                payload_digest=self.package.payload_digest,
                source="t",
            ),
            target=TargetRef(
                harness=plan.target.harness,
                harness_version=adapter.version(),
                provider=plan.target.provider,
                model_alias=plan.target.model_alias,
                model_id_requested=model_id,
                model_id_reported="model-as-served",
                harness_capabilities=adapter.capabilities().as_record(),
            ),
            sandbox=SandboxRef(image="scripted@sha256:" + "2" * 64, isolation="none"),
            coverage=Coverage(
                harness_events=PlaneCoverage(fidelity="full"),
                filesystem_writes=PlaneCoverage(fidelity="unavailable", reason="scripted"),
            ),
            started_at=dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.UTC),
        )
        footer = RunFooter(
            ended_at=dt.datetime(2026, 8, 5, 12, 5, 0, tzinfo=dt.UTC),
            wall_clock_ms=30_000,
            exit_reason=exit_reason_from_events(events),
            tokens=token_totals_from_events(events),
        )
        actions = harness_actions(events)
        if self.qualify:
            actions = [
                action.model_copy(
                    update={
                        "action": {
                            **action.action,
                            "skill": f"demo-bundle:{action.action['skill']}",
                        }
                    }
                )
                if action.kind == "skill_activated"
                else action
                for action in actions
            ]
        path = write_trace(
            self.tmp_path
            / f"{self.package.name}-{plan.scenario.id}-{plan.repetition}-{plan.attempt}.jsonl",
            header,
            actions,
            footer,
        )
        return ExecutedRun(
            trace=read_trace(path),
            context=NormalizationContext(workspace_root="/home/agent/workspace"),
            trace_jsonl=path.read_text(encoding="utf-8"),
        )


def _greedy_wins(prompt: str, offered: tuple[str, ...]) -> str | None:
    del prompt
    return "greedy" if "greedy" in offered else offered[0]


def _everyone_behaves(prompt: str, offered: tuple[str, ...]) -> str | None:
    if "standup" in prompt.lower():
        return "alpha"
    if "changelog" in prompt.lower():
        return "beta"
    return "greedy" if "anything" in prompt.lower() else None


def _run(
    tmp_path: Path, library: Path, decide: Decide, *, qualify: bool = False
) -> CoexistenceMatrix:
    members = library_members(library)
    config, policy = _config(), _policy()
    target = resolve_coexistence_target(
        config, policy, environ=_ENVIRON, profile_override="low", target_aliases=(), force=True
    )
    executors: dict[str, _CoexistenceExecutor] = {}

    def factory_for(eval_id: str):  # type: ignore[no-untyped-def]
        def make(package, fixture, client_factory):  # type: ignore[no-untyped-def]
            executors[eval_id] = _CoexistenceExecutor(
                package, tmp_path / "traces", client_factory, decide, qualify=qualify
            )
            return executors[eval_id]

        return make

    (tmp_path / "traces").mkdir(parents=True, exist_ok=True)
    matrix = run_coexistence(
        config=config,
        policy=policy,
        members=members,
        target=target,
        environ=_ENVIRON,
        executor_factory_for=factory_for,
        out_dir=tmp_path / "out",
        created_at=_CREATED,
        bellwether_version="0.1.0",
        profile_override="low",
    )
    # Every member was offered with the whole library beside it (§7.4: full library).
    for executor in executors.values():
        assert all(offered == ("alpha", "beta", "greedy") for offered in executor.offered)
    return matrix


# ---------------------------------------------------------------------------
# Probe selection (§7.4 item 2)
# ---------------------------------------------------------------------------


def test_probe_selection_follows_the_marks_then_the_fallbacks(tmp_path: Path) -> None:
    by_name = {m.name: m.package for m in library_members(_library(tmp_path))}
    assert [(s.id, kind, source) for s, kind, source in probe_scenarios_for(by_name["alpha"])] == [
        ("act", "activation", "marked"),
        ("rep", "representative", "marked"),
    ]
    assert [(s.id, kind, source) for s, kind, source in probe_scenarios_for(by_name["beta"])] == [
        (ACTIVATION_PROBE_ID, "activation", "generated"),
        ("compile", "representative", "first_should_trigger"),
    ]
    assert [(s.id, kind, source) for s, kind, source in probe_scenarios_for(by_name["greedy"])] == [
        (ACTIVATION_PROBE_ID, "activation", "generated"),
    ]


def test_a_library_needs_two_members_with_distinct_names(tmp_path: Path) -> None:
    lonely = tmp_path / "one"
    _skill(lonely, "solo", "Does one thing.", None)
    with pytest.raises(BellwetherError, match="at least two"):
        library_members(lonely)
    with pytest.raises(BellwetherError, match="not a directory"):
        library_members(tmp_path / "missing")


def test_the_library_key_is_the_sorted_member_digests(tmp_path: Path) -> None:
    members = [m.package for m in library_members(_library(tmp_path))]
    assert library_key(members) == library_key(list(reversed(members)))
    (tmp_path / "skills" / "beta" / "SKILL.md").write_text(
        "---\nname: beta\ndescription: Compiles a changelog from commits, differently.\n---\nb\n",
        encoding="utf-8",
    )
    assert library_key([m.package for m in library_members(tmp_path / "skills")]) != library_key(
        members
    )


# ---------------------------------------------------------------------------
# Target resolution: one target, and api-loop only by force (§7.4, §9.4)
# ---------------------------------------------------------------------------


def test_api_loop_is_refused_without_force() -> None:
    with pytest.raises(BellwetherError, match="api-loop"):
        resolve_coexistence_target(
            _config(),
            _policy(),
            environ=_ENVIRON,
            profile_override="low",
            target_aliases=(),
            force=False,
        )
    target = resolve_coexistence_target(
        _config(),
        _policy(),
        environ=_ENVIRON,
        profile_override="low",
        target_aliases=(),
        force=True,
    )
    assert target.harness == "api-loop"


def test_two_targets_are_refused_rather_than_averaged() -> None:
    from bellwether.config.models.policy import Target
    from bellwether.config.models.provider import ProviderConfig

    config = _config()
    config = config.model_copy(
        update={
            "providers": {
                "anthropic": ProviderConfig(
                    type="anthropic",
                    api_key_env="ANTHROPIC_API_KEY",
                    models={"frontier": "a-real-model-id", "small": "a-small-model-id"},
                )
            }
        }
    )
    policy = _policy()
    low = policy.profile("low")
    matrix = low.matrix.model_copy(
        update={
            "required_targets": [
                Target(harness="api-loop", provider="anthropic", model_alias="frontier"),
                Target(harness="api-loop", provider="anthropic", model_alias="small"),
            ]
        }
    )
    policy = policy.model_copy(
        update={"profiles": {**policy.profiles, "low": low.model_copy(update={"matrix": matrix})}}
    )
    with pytest.raises(BellwetherError, match="one target"):
        resolve_coexistence_target(
            config, policy, environ=_ENVIRON, profile_override="low", target_aliases=(), force=True
        )
    picked = resolve_coexistence_target(
        config,
        policy,
        environ=_ENVIRON,
        profile_override="low",
        target_aliases=("small",),
        force=True,
    )
    assert picked.model_alias == "small"


# ---------------------------------------------------------------------------
# The matrix, the baseline and the delta
# ---------------------------------------------------------------------------


def test_a_greedy_skill_wins_the_others_activations(tmp_path: Path) -> None:
    matrix = _run(tmp_path, _library(tmp_path), _greedy_wins)
    assert matrix.members == ("alpha", "beta", "greedy")
    assert not matrix.portable and matrix.harness == "api-loop"
    assert matrix.n == COEXISTENCE_N
    cells = {(cell.skill, cell.probe_id): cell for cell in matrix.cells}
    assert set(cells) == {
        ("alpha", "act"),
        ("alpha", "rep"),
        ("beta", ACTIVATION_PROBE_ID),
        ("beta", "compile"),
        ("greedy", ACTIVATION_PROBE_ID),
    }
    for cell in matrix.cells:
        assert cell.runs == COEXISTENCE_N
        assert cell.winners == {"greedy": COEXISTENCE_N}
    assert cells[("alpha", "act")].collisions() == {"greedy": COEXISTENCE_N}
    assert cells[("greedy", ACTIVATION_PROBE_ID)].collisions() == {}
    markdown = render_coexistence_markdown(matrix, compare_with_baseline(matrix, None))
    assert "harness-specific: not portable" in markdown
    assert "| `alpha` | `act` (activation, marked) | `greedy` 12/12 |" in markdown
    assert "no library baseline stored" in markdown


def test_a_bundle_qualified_activation_is_credited_to_the_member(tmp_path: Path) -> None:
    """End to end: the harness reports `demo-bundle:greedy`, the matrix counts `greedy`."""
    matrix = _run(tmp_path, _library(tmp_path), _greedy_wins, qualify=True)
    assert all(cell.winners == {"greedy": COEXISTENCE_N} for cell in matrix.cells)


def test_runs_with_no_activation_are_counted_as_none(tmp_path: Path) -> None:
    matrix = _run(tmp_path, _library(tmp_path), lambda _prompt, _offered: None)
    assert all(cell.winners == {NO_ACTIVATION: COEXISTENCE_N} for cell in matrix.cells)
    assert all(cell.collisions() == {} for cell in matrix.cells)


def test_the_baseline_delta_names_who_began_and_stopped_winning(tmp_path: Path) -> None:
    library = _library(tmp_path)
    before = _run(tmp_path / "first", library, _everyone_behaves)
    baselines = tmp_path / "baselines"
    path = write_library_baseline(before, baselines)
    assert path.name == "_library.coexistence.json"
    stored = load_library_baseline(path)
    assert stored == before
    assert render_coexistence_json(stored) == render_coexistence_json(before)

    after = _run(tmp_path / "second", library, _greedy_wins)
    delta = compare_with_baseline(after, stored)
    assert delta.comparable
    assert delta.baseline_digest == before.digest
    # §7.4's headline shape: who began winning what, previously whose.
    assert any(
        "`greedy` began winning 12 of 12 activations on `alpha`'s `act` probe" in change
        for change in delta.changes
    )
    assert any("`alpha` lost 12 of 12 activations" in change for change in delta.changes)
    # greedy's own probe did not move: no line about it.
    assert not any("`greedy`'s `" in change for change in delta.changes)
    assert compare_with_baseline(before, stored).changes == ()


def test_a_changed_member_invalidates_the_baseline(tmp_path: Path) -> None:
    library = _library(tmp_path)
    before = _run(tmp_path / "first", library, _everyone_behaves)
    (library / "beta" / "SKILL.md").write_text(
        "---\nname: beta\ndescription: Compiles a changelog, now broader.\n---\nb\n",
        encoding="utf-8",
    )
    after = _run(tmp_path / "second", library, _everyone_behaves)
    delta = compare_with_baseline(after, before)
    assert not delta.comparable
    assert "changed: beta" in delta.reason
    assert delta.changes == ()


# ---------------------------------------------------------------------------
# The command's front door
# ---------------------------------------------------------------------------


def test_coexistence_resolves_the_target_before_the_daemon_and_the_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scaffold's profiles run two claude-code targets, so the first refusal is §7.4's
    one-target rule; with one picked, the next thing touched is the daemon — never a run."""
    import importlib

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-value")
    app_module = importlib.import_module("bellwether.cli.app")
    monkeypatch.setattr(
        app_module.DockerBackend, "available", lambda _self: (False, "no daemon in this test")
    )
    assert runner.invoke(app, ["init", str(tmp_path)]).exit_code == 0
    config = tmp_path / ".bellwether" / "config.yaml"
    # The scaffold ships placeholder model ids, which resolution refuses first; fill them in
    # so the refusals under test are the matrix's own.
    config.write_text(
        config.read_text(encoding="utf-8").replace("<fill in current model id>", "a-real-model-id"),
        encoding="utf-8",
    )
    library = _library(tmp_path)
    result = runner.invoke(app, ["coexistence", str(library), "--config", str(config)])
    assert result.exit_code == 3
    assert "one target" in result.output and "--targets" in result.output
    picked = runner.invoke(
        app, ["coexistence", str(library), "--config", str(config), "--targets", "frontier"]
    )
    assert picked.exit_code == 3
    assert "sandbox is unavailable" in picked.output


def test_a_winner_is_credited_to_the_member_it_names_through_a_bundle_qualifier() -> None:
    """The real CLI reports a plugin-staged skill qualified by its bundle (`bundle:alpha`);
    the matrix credits the member it names, by the same rule `skill_activated` uses, and keeps
    an unknown name as recorded rather than dropping it."""
    from bellwether.cli.coexistence import _credit

    assert _credit("demo-bundle:alpha", ["alpha", "beta"]) == "alpha"
    assert _credit("alpha", ["alpha", "beta"]) == "alpha"
    assert _credit("outsider", ["alpha", "beta"]) == "outsider"


def test_coexistence_help_describes_the_matrix() -> None:
    result = runner.invoke(app, ["coexistence", "--help"])
    assert result.exit_code == 0
    assert "--set-baseline" in result.output and "--force" in result.output
