"""WP-6, offline half: the api-loop adapter against a scripted transcript.

Everything here runs without a daemon or an API key. The container end — tools executing
inside a real sandbox, and the WP-6 done-when of a complete two-plane ARF trace — is in
``test_harness_docker.py``.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from bellwether.errors import BellwetherError
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
    resolve_model,
)
from bellwether.trace import (
    exit_reason_from_events,
    harness_actions,
    token_totals_from_events,
)

START = dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.UTC)


def ticking_clock(step_seconds: int = 1):  # type: ignore[no-untyped-def]
    """A deterministic clock: fixed epoch, fixed step. Golden traces depend on it."""
    state = {"tick": 0}

    def clock() -> dt.datetime:
        instant = START + dt.timedelta(seconds=state["tick"] * step_seconds)
        state["tick"] += 1
        return instant

    return clock


class FakeExec:
    """An exec runner backed by a dict, standing in for the container."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {"README.md": "# project\n"}
        self.commands: list[list[str]] = []

    def __call__(self, argv: list[str], *, stdin: str | None = None, timeout: float) -> ExecResult:
        self.commands.append(argv)
        if argv[0] == "cat":
            path = argv[-1]
            if path in self.files:
                return ExecResult(exit_code=0, stdout=self.files[path], stderr="")
            return ExecResult(exit_code=1, stdout="", stderr=f"cat: {path}: No such file")
        if argv[0] == "sh" and len(argv) == 5 and argv[2].startswith("mkdir -p"):
            self.files[argv[4]] = stdin or ""
            return ExecResult(exit_code=0, stdout="", stderr="")
        if argv[0] == "sh":
            return ExecResult(exit_code=0, stdout=f"ran: {argv[2]}\n", stderr="")
        return ExecResult(exit_code=127, stdout="", stderr="not found")


SKILL = OfferedSkill(
    name="security-review",
    description="Reviews code for vulnerabilities.",
    body="# Security review\nRead the code, report findings.\n",
)


def call(call_id: str, tool: str, /, **tool_input: Any) -> ToolCallRequest:
    return ToolCallRequest(id=call_id, name=tool, input=dict(tool_input))


def usage(n: int = 100) -> TurnUsage:
    return TurnUsage(input=n, output=n // 2, cache_read=n // 4, cache_write=0)


def make_adapter(
    turns: list[ModelTurn],
    *,
    skills: tuple[OfferedSkill, ...] = (SKILL,),
    exec_runner: FakeExec | None = None,
) -> tuple[ApiLoopAdapter, ScriptedClient, FakeExec]:
    client = ScriptedClient(turns, model_id_reported="served-model")
    runner = exec_runner or FakeExec()
    adapter = ApiLoopAdapter(
        client,
        SandboxToolset(runner),
        skills=skills,
        clock=ticking_clock(),
    )
    return adapter, client, runner


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def test_a_full_session_emits_the_expected_event_sequence() -> None:
    adapter, _client, runner = make_adapter(
        [
            ModelTurn(
                stop_reason="tool_use",
                usage=usage(),
                tool_calls=(
                    call("tc_1", "skill", name="security-review"),
                    call("tc_2", "read", path="README.md"),
                ),
            ),
            ModelTurn(
                stop_reason="tool_use",
                usage=usage(),
                tool_calls=(call("tc_3", "write", path="report.md", content="findings\n"),),
            ),
            ModelTurn(text="Done. See report.md.", usage=usage()),
        ]
    )

    events = list(adapter.run("Review this project.", model_id="cfg-model", limits=RunLimits()))

    assert [event.kind for event in events] == [
        "skill_offered",
        "model_turn",
        "tool_call",
        "skill_activated",
        "skill_body_loaded",
        "tool_result",
        "tool_call",
        "tool_result",
        "model_turn",
        "tool_call",
        "tool_result",
        "model_turn",
        "final_output",
    ]
    assert events[-1].data["text"] == "Done. See report.md."
    assert runner.files["report.md"] == "findings\n"


def test_tool_calls_and_results_carry_the_originating_id() -> None:
    """The WP-6 done-when: explicit correlation is the strong path for WP-10."""
    adapter, _, _ = make_adapter(
        [
            ModelTurn(
                stop_reason="tool_use",
                usage=usage(),
                tool_calls=(call("toolu_abc123", "read", path="README.md"),),
            ),
            ModelTurn(text="done", usage=usage()),
        ]
    )
    events = list(adapter.run("p", model_id="m", limits=RunLimits()))

    ids = [event.tool_call_id for event in events if event.kind in ("tool_call", "tool_result")]
    assert ids == ["toolu_abc123", "toolu_abc123"]


def test_the_model_sees_what_the_trace_says_it_saw() -> None:
    """On api-loop the prompt is the trigger surface, so it is pinned behaviour."""
    adapter, client, _ = make_adapter([ModelTurn(text="hi", usage=usage())])
    list(adapter.run("p", model_id="m", limits=RunLimits()))

    (request,) = client.requests
    assert "security-review: Reviews code for vulnerabilities." in request.system
    assert [tool.name for tool in request.tools] == ["read", "write", "bash", "fetch", "skill"]
    assert request.model_id == "m"


def test_skills_are_presented_sorted_and_deterministically() -> None:
    zeta = OfferedSkill(name="zeta", description="z", body="z")
    alpha = OfferedSkill(name="alpha", description="a", body="a")
    one, client_one, _ = make_adapter([ModelTurn(text="x", usage=usage())], skills=(zeta, alpha))
    two, client_two, _ = make_adapter([ModelTurn(text="x", usage=usage())], skills=(alpha, zeta))
    list(one.run("p", model_id="m", limits=RunLimits()))
    list(two.run("p", model_id="m", limits=RunLimits()))

    assert client_one.requests[0].system == client_two.requests[0].system
    assert client_one.requests[0].system.index("alpha") < client_one.requests[0].system.index(
        "zeta"
    )


def test_loading_an_unknown_skill_is_an_error_result_not_a_crash() -> None:
    adapter, _, _ = make_adapter(
        [
            ModelTurn(
                stop_reason="tool_use",
                usage=usage(),
                tool_calls=(call("tc_1", "skill", name="nope"),),
            ),
            ModelTurn(text="ok", usage=usage()),
        ]
    )
    events = list(adapter.run("p", model_id="m", limits=RunLimits()))

    result = next(event for event in events if event.kind == "tool_result")
    assert result.data["outcome"] == "error"
    assert "no skill named 'nope'" in result.data["result_preview"]
    assert not any(event.kind == "skill_activated" for event in events)


# ---------------------------------------------------------------------------
# Limits (§12.7)
# ---------------------------------------------------------------------------


def test_the_turn_limit_ends_the_run_as_a_timeout_shape() -> None:
    looping_turn = ModelTurn(
        stop_reason="tool_use",
        usage=usage(),
        tool_calls=(call("tc", "read", path="README.md"),),
    )
    adapter, _, _ = make_adapter([looping_turn, looping_turn, looping_turn])
    events = list(adapter.run("p", model_id="m", limits=RunLimits(max_turns=3)))

    assert events[-1].kind == "harness_error"
    assert events[-1].data["exit_reason"] == "timeout"
    assert exit_reason_from_events(events) == "timeout"


def test_the_token_budget_is_budget_exceeded_not_a_failure() -> None:
    adapter, _, _ = make_adapter(
        [ModelTurn(stop_reason="tool_use", usage=TurnUsage(input=5000, output=5000))]
    )
    events = list(adapter.run("p", model_id="m", limits=RunLimits(max_total_tokens=100)))

    assert events[-1].kind == "harness_error"
    assert events[-1].data["exit_reason"] == "budget_exceeded"
    assert exit_reason_from_events(events) == "budget_exceeded"


def test_the_tool_call_limit_stops_mid_turn() -> None:
    adapter, _, _ = make_adapter(
        [
            ModelTurn(
                stop_reason="tool_use",
                usage=usage(),
                tool_calls=(
                    call("tc_1", "read", path="README.md"),
                    call("tc_2", "read", path="README.md"),
                ),
            )
        ]
    )
    events = list(adapter.run("p", model_id="m", limits=RunLimits(max_tool_calls=1)))

    assert sum(1 for event in events if event.kind == "tool_call") == 1
    assert events[-1].kind == "harness_error"


def test_an_exhausted_script_names_the_disagreement() -> None:
    adapter, _, _ = make_adapter([])
    with pytest.raises(BellwetherError, match="scripted transcript"):
        list(adapter.run("p", model_id="m", limits=RunLimits()))


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def test_fetch_is_refused_and_says_why() -> None:
    toolset = SandboxToolset(FakeExec())
    outcome = toolset.execute("fetch", {"url": "https://example.com"})

    assert not outcome.ok
    assert outcome.error is not None
    assert "recorded and not sent" in outcome.error


def test_tool_output_is_truncated_with_full_fidelity_in_the_digest() -> None:
    from bellwether.determinism import stable_hash

    runner = FakeExec()
    runner.files["big.txt"] = "x" * 100
    toolset = SandboxToolset(runner, max_output_chars=10)
    outcome = toolset.execute("read", {"path": "big.txt"})

    assert outcome.truncated
    assert outcome.output.startswith("xxxxxxxxxx\n[output truncated")
    assert outcome.output_digest == stable_hash("x" * 100)


def test_a_failed_command_reports_exit_code_and_stderr() -> None:
    toolset = SandboxToolset(FakeExec())
    outcome = toolset.execute("read", {"path": "absent.txt"})

    assert not outcome.ok
    assert outcome.error == "exit code 1"
    assert "No such file" in outcome.output


def test_bad_tool_input_is_an_error_result() -> None:
    toolset = SandboxToolset(FakeExec())
    assert not toolset.execute("read", {}).ok
    assert not toolset.execute("write", {"path": "x"}).ok
    assert not toolset.execute("no-such-tool", {}).ok


def test_a_timed_out_tool_call_fails_that_call_only() -> None:
    def hanging(argv: list[str], *, stdin: str | None = None, timeout: float) -> ExecResult:
        return ExecResult(exit_code=124, stdout="", stderr="", timed_out=True)

    toolset = SandboxToolset(hanging, tool_timeout=5.0)
    outcome = toolset.execute("bash", {"command": "sleep 999"})
    assert not outcome.ok
    assert outcome.error is not None and "did not finish within 5s" in outcome.error


# ---------------------------------------------------------------------------
# Capabilities (§9.4)
# ---------------------------------------------------------------------------


def test_api_loop_declares_its_critical_limitation() -> None:
    adapter, _, _ = make_adapter([ModelTurn(text="x", usage=usage())])
    caps = adapter.capabilities()

    assert caps.controls_skill_presentation
    assert not caps.trigger_metrics_portable, (
        "trigger metrics from api-loop measure Bellwether's own prompt assembly and "
        "must carry the not-portable label (§9.4)"
    )
    record = caps.as_record()
    assert record["trigger_metrics_portable"] is False
    assert record["infrastructure_endpoints"] == []


def test_egress_is_declared_unobservable_until_a_capture_point_exists() -> None:
    """False keeps `no_egress` at not_evaluable rather than passing vacuously."""
    adapter, _, _ = make_adapter([ModelTurn(text="x", usage=usage())])
    assert not adapter.capabilities().egress_observable


# ---------------------------------------------------------------------------
# Alias resolution (§9.5)
# ---------------------------------------------------------------------------


def make_provider(models: dict[str, str]):  # type: ignore[no-untyped-def]
    from bellwether.config.models.provider import ProviderConfig

    return ProviderConfig(type="anthropic", api_key_env="X", models=models)


def test_aliases_resolve_through_configuration() -> None:
    provider = make_provider({"frontier": "some-model-id"})
    assert resolve_model(provider, "frontier") == "some-model-id"


def test_an_unknown_alias_names_the_known_ones() -> None:
    provider = make_provider({"frontier": "some-model-id", "small": "small-id"})
    with pytest.raises(BellwetherError, match="frontier, small"):
        resolve_model(provider, "mid")


def test_a_placeholder_model_id_is_refused_by_name() -> None:
    """A first run must fail with a sentence naming the alias, not a provider 404."""
    provider = make_provider({"frontier": "<fill in current model id>"})
    with pytest.raises(BellwetherError, match="alias 'frontier'"):
        resolve_model(provider, "frontier", provider_name="anthropic")


# ---------------------------------------------------------------------------
# Trace translation (Plane A)
# ---------------------------------------------------------------------------


def run_events():  # type: ignore[no-untyped-def]
    adapter, _, _ = make_adapter(
        [
            ModelTurn(
                stop_reason="tool_use",
                usage=usage(),
                tool_calls=(call("tc_1", "read", path="README.md"),),
            ),
            ModelTurn(text="done", usage=usage(200)),
        ]
    )
    return list(adapter.run("p", model_id="m", limits=RunLimits()))


def test_harness_events_become_plane_a_actions() -> None:
    events = run_events()
    actions = harness_actions(events, start_seq=10)

    assert [action.seq for action in actions] == list(range(10, 10 + len(events)))
    assert all(action.plane == "harness" for action in actions)
    tool_call = next(action for action in actions if action.kind == "tool_call")
    assert tool_call.action["tool_call_id"] == "tc_1"
    assert tool_call.actor is not None and tool_call.actor.turn == 1
    # None values are dropped, matching the writer's null omission.
    result = next(action for action in actions if action.kind == "tool_result")
    assert "error" not in result.action


def test_token_totals_sum_across_turns_with_cache_separate() -> None:
    totals = token_totals_from_events(run_events())
    assert totals.input == 300
    assert totals.output == 150
    assert totals.cache_read == 75


def test_exit_reason_reads_the_event_stream() -> None:
    assert exit_reason_from_events(run_events()) == "completed"
    assert exit_reason_from_events([]) is None


# ---------------------------------------------------------------------------
# The golden trace (§24)
# ---------------------------------------------------------------------------


def test_the_golden_trace_regenerates_byte_identically(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The committed reference is what the offline analysis pipeline is tested against;
    a byte of drift here is a schema change and must be reviewed as one."""
    from tests.golden_trace import GOLDEN_PATH, build_golden

    regenerated = build_golden(tmp_path / "regenerated.jsonl")
    assert regenerated.read_bytes() == GOLDEN_PATH.read_bytes()


def test_the_golden_trace_is_complete_and_two_sourced() -> None:
    from bellwether.trace import read_trace
    from tests.golden_trace import GOLDEN_PATH

    trace = read_trace(GOLDEN_PATH)
    assert trace.is_complete
    assert trace.evaluability() == "evaluable"
    assert trace.header.target.harness == "api-loop"
    capabilities = trace.header.target.harness_capabilities
    assert capabilities is not None
    assert capabilities["trigger_metrics_portable"] is False
    # Plane A is populated; tool calls carry their originating ids.
    calls = trace.actions_of_kind("tool_call")
    assert [action.action["tool_call_id"] for action in calls] == [
        "toolu_01",
        "toolu_02",
        "toolu_03",
    ]
    assert trace.footer is not None
    assert trace.footer.tokens.total > 0
