"""§9.2/§12.7: the per-run bounds come from `execution.limits`, reach the adapter, and are
recorded on every run header.

Before this, every run took the generic `RunLimits` defaults no matter what the operator
configured, and a run stopped at a turn or tool-call ceiling produced a trace that said
`timeout` without saying whose ceiling it was — §12.7 scores that as the skill failing, so
the bound in force belongs on the record.
"""

from __future__ import annotations

from bellwether.cli.run import run_limits_from_config
from bellwether.cli.run_cache import observability_key
from bellwether.config.models.config import Config, RunLimitsConfig
from bellwether.harness import ApiLoopAdapter, OfferedSkill, RunLimits, ScriptedClient
from bellwether.harness.provider import ModelTurn, ToolCallRequest, TurnUsage
from bellwether.harness.tools import ExecResult, SandboxToolset
from bellwether.trace import exit_reason_from_events


def _config(**limits: int) -> Config:
    return Config.model_validate(
        {
            "apiVersion": "bellwether/v1",
            "kind": "Config",
            "sandbox": {"image": "img@sha256:" + "d" * 64},
            **({"execution": {"limits": limits}} if limits else {}),
        }
    )


def test_the_configured_limits_are_what_a_run_gets() -> None:
    """The defect this closes: `execution.limits` was configurable and read nowhere, so the
    generic defaults bounded every run whatever the operator wrote."""
    default = run_limits_from_config(_config())
    assert (default.max_turns, default.max_tool_calls) == (32, 128)

    tightened = run_limits_from_config(_config(max_turns=4, max_tool_calls=6))
    assert (tightened.max_turns, tightened.max_tool_calls) == (4, 6)
    assert tightened != RunLimits(), "the config must not resolve to the generic defaults"


def test_max_tokens_on_the_command_line_wins_over_the_configured_cap() -> None:
    """`--max-tokens` is the documented per-invocation cost control; a config value winning
    over a flag typed at the terminal would be surprising."""
    configured = run_limits_from_config(_config(max_total_tokens=500))
    assert configured.max_total_tokens == 500
    overridden = run_limits_from_config(_config(max_total_tokens=500), max_total_tokens=9_000)
    assert overridden.max_total_tokens == 9_000
    # The other two bounds are untouched by the override.
    assert (overridden.max_turns, overridden.max_tool_calls) == (
        configured.max_turns,
        configured.max_tool_calls,
    )


def test_the_wall_clock_is_not_taken_from_config() -> None:
    """§7.2 gives the wall clock to the scenario (`timeout_seconds`, else the suite default).
    A second wall clock in config would silently override the suite author's choice, so
    `RunLimitsConfig` has no field for one."""
    assert "wall_seconds" not in RunLimitsConfig.model_fields
    assert run_limits_from_config(_config()).wall_seconds == RunLimits().wall_seconds


def test_raising_a_ceiling_misses_the_run_cache() -> None:
    """A run stopped at a turn ceiling is a different observation from one that ran to its
    own end, so raising the ceiling must not replay the truncated trace (§19.2)."""
    base = observability_key(_config())
    assert observability_key(_config(max_turns=4)) != base
    assert observability_key(_config(max_tool_calls=6)) != base
    assert observability_key(_config(max_total_tokens=500)) != base
    assert observability_key(_config()) == base


class _NoopExec:
    """Tool calls succeed and do nothing: these tests are about the bounds, not the tools."""

    def __call__(self, argv: list[str], *, stdin: str | None = None, timeout: float) -> ExecResult:
        return ExecResult(exit_code=0, stdout="", stderr="")


def _adapter(turns: list[ModelTurn]) -> ApiLoopAdapter:
    return ApiLoopAdapter(
        ScriptedClient(turns),
        SandboxToolset(_NoopExec()),
        skills=(OfferedSkill(name="s", description="d", body="b"),),
    )


def test_a_tightened_turn_limit_actually_stops_the_run() -> None:
    """Run it, don't assert the plumbing: a two-turn ceiling stops a model that would keep
    going, and the event names the bound that stopped it."""
    chatty = [
        ModelTurn(
            stop_reason="tool_use",
            usage=TurnUsage(input=10, output=5),
            tool_calls=(ToolCallRequest(id=f"t{i}", name="read", input={"path": "x"}),),
        )
        for i in range(10)
    ]
    events = list(
        _adapter(chatty).run("go", model_id="m", limits=RunLimits(max_turns=2, max_tool_calls=99))
    )
    assert exit_reason_from_events(events) == "timeout"
    assert [e.data["limit"] for e in events if e.kind == "harness_error"] == ["turn limit: 2"]


def test_a_tightened_tool_call_limit_actually_stops_the_run() -> None:
    chatty = [
        ModelTurn(
            stop_reason="tool_use",
            usage=TurnUsage(input=10, output=5),
            tool_calls=(ToolCallRequest(id=f"t{i}", name="read", input={"path": "x"}),),
        )
        for i in range(10)
    ]
    events = list(
        _adapter(chatty).run("go", model_id="m", limits=RunLimits(max_turns=99, max_tool_calls=1))
    )
    assert exit_reason_from_events(events) == "timeout"
    assert [e.data["limit"] for e in events if e.kind == "harness_error"] == ["tool call limit: 1"]


def test_a_token_ceiling_is_budget_exceeded_not_a_failure() -> None:
    """§12.7 keeps the two apart: a turn ceiling is timeout-shaped and scores as a failure,
    while an operator's token budget is `budget_exceeded` and therefore not_evaluable."""
    events = list(
        _adapter([ModelTurn(text="done", usage=TurnUsage(input=900, output=900))]).run(
            "go", model_id="m", limits=RunLimits(max_total_tokens=100)
        )
    )
    assert exit_reason_from_events(events) == "budget_exceeded"


def test_the_cli_token_override_reaches_the_cache_key() -> None:
    """R10: the key hashed ``config.execution.limits`` — the *configured* cap — while the run
    enforced the cap ``--max-tokens`` had overridden it to. So an evaluation at a generous cap
    executed the matrix, and a second at a tight one replayed every run from the cache and
    reported them under a limit that had never been exercised: results presented under limits
    that were not actually applied, which is the cache's one job not to do (§19.2)."""
    config = _config(max_total_tokens=10_000)
    configured = run_limits_from_config(config)
    tightened = run_limits_from_config(config, max_total_tokens=1)

    assert observability_key(config, run_limits=tightened) != observability_key(
        config, run_limits=configured
    )
    # And the override is what the key follows, not the config it overrode: two configs whose
    # effective cap is the same must agree, or the key would miss where it should hit.
    assert observability_key(config, run_limits=tightened) == observability_key(
        _config(max_total_tokens=99), run_limits=tightened
    )
