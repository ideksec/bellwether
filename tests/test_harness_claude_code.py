"""WP-17, offline half: the ``claude-code`` adapter against the real CLI's own output.

The fixtures under ``tests/golden/claude-code/`` are the verbatim stdout stream and hook
stream of a real headless session of Claude Code 2.1.257 driven against a scripted Messages
API (paths normalised) — the §9.4 "consult the harness at build time" done for real, and
kept so a future CLI change that alters a field name breaks a test here rather than
silently emptying Plane A. The container half — the CLI running inside the sandbox behind
the proxy — is CI-only, in ``test_execution_claude_code_docker.py``.

Where the real ``claude`` binary is on PATH, one test re-runs the session for real against a
local scripted Messages API with the hooks writing to a real FIFO through the host sink, so
the adapter is exercised end to end on this machine, no container and no key needed.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from bellwether.capture import HostEventSink
from bellwether.harness import (
    ClaudeCodeAdapter,
    LaunchResult,
    RunLimits,
    ScriptedLaunch,
    claude_code_argv,
    claude_code_environment,
    hook_settings,
)
from bellwether.harness.claude_code import reconcile_hooks
from bellwether.trace import (
    NormalizationContext,
    canonicalize,
    exit_reason_from_events,
    filesystem_access,
    harness_actions,
    token_totals_from_events,
)

GOLDEN = Path(__file__).parent / "golden" / "claude-code"
START = dt.datetime(2026, 9, 1, 22, 41, 30, tzinfo=dt.UTC)


def _ticking_clock():  # type: ignore[no-untyped-def]
    state = {"tick": 0}

    def clock() -> dt.datetime:
        instant = START + dt.timedelta(milliseconds=state["tick"] * 10)
        state["tick"] += 1
        return instant

    return clock


def _stream_lines() -> list[str]:
    return (GOLDEN / "stream.jsonl").read_text(encoding="utf-8").splitlines()


def _hook_payloads() -> list[dict[str, object] | None]:
    out: list[dict[str, object] | None] = []
    for line in (GOLDEN / "hooks.jsonl").read_text(encoding="utf-8").splitlines():
        try:
            payload = json.loads(line)
        except ValueError:
            out.append(None)
        else:
            out.append(payload if isinstance(payload, dict) else None)
    return out


def _run_golden(hooks: bool = True) -> tuple[ClaudeCodeAdapter, list]:  # type: ignore[type-arg]
    launch = ScriptedLaunch(_stream_lines())
    adapter = ClaudeCodeAdapter(
        launch,
        hook_source=_hook_payloads if hooks else None,
        settings=hook_settings(),
        clock=_ticking_clock(),
    )
    events = list(
        adapter.run(
            "Use the demo-skill to take notes.", model_id="fake-model-v1", limits=RunLimits()
        )
    )
    return adapter, events


# ---------------------------------------------------------------------------
# The stdout stream → Plane A
# ---------------------------------------------------------------------------


def test_the_real_session_maps_onto_the_event_vocabulary() -> None:
    """Every §11.3 kind the run exercised, in the loop's causal order: the offer, four model
    turns, three tool calls with their results, the skill activation, the final output."""
    _adapter, events = _run_golden()
    kinds = [e.kind for e in events]
    assert kinds.count("skill_offered") >= 1
    assert "demo-skill" in {e.data["skill"] for e in events if e.kind == "skill_offered"}
    assert kinds.count("model_turn") == 4
    assert kinds.count("tool_call") == 3
    assert kinds.count("tool_result") == 3
    assert kinds.count("skill_activated") == 1
    assert kinds.count("skill_body_loaded") == 1
    assert kinds[-1] == "final_output"
    assert events[-1].data["text"] == "Read README.md and wrote notes.md."
    # No cross-check finding: the hook stream corroborated every call.
    assert "trace_inconsistency" not in kinds
    assert exit_reason_from_events(events) == "completed"


def test_tool_calls_carry_their_originating_id_and_correlate_with_results() -> None:
    _adapter, events = _run_golden()
    calls = [e for e in events if e.kind == "tool_call"]
    results = [e for e in events if e.kind == "tool_result"]
    assert [c.tool_call_id for c in calls] == ["toolu_01", "toolu_02", "toolu_03"]
    assert [r.tool_call_id for r in results] == ["toolu_01", "toolu_02", "toolu_03"]
    assert [c.data["tool"] for c in calls] == ["Skill", "Read", "Write"]
    assert calls[1].data["input"] == {"file_path": "/work/k9x2m7q1/README.md"}
    # Every call is auto-approved under the headless permission mode, and the trace says so
    # (§10.1: privilege pre-approval must be visible).
    assert {c.data["permission"] for c in calls} == {"auto_approved"}
    read_result = results[1]
    assert read_result.data["outcome"] == "ok"
    assert read_result.data["result_preview"].startswith("1\t# project")
    assert read_result.data["duration_ms"] >= 0
    # The activation is anchored to the Skill call and precedes its result, as on api-loop.
    activated = next(e for e in events if e.kind == "skill_activated")
    assert activated.tool_call_id == "toolu_01" and activated.data["skill"] == "demo-skill"
    assert events.index(activated) < events.index(results[0])


def test_model_turns_carry_usage_model_and_stop_reason() -> None:
    _adapter, events = _run_golden()
    turns = [e for e in events if e.kind == "model_turn"]
    assert [t.turn for t in turns] == [1, 2, 3, 4]
    assert turns[0].data["model_id_reported"] == "fake-model-v1"
    assert turns[0].data["tokens"] == {"input": 100, "output": 1, "cache_read": 0, "cache_write": 0}
    # The CLI emits the assistant line with stop_reason null; the content implies it.
    assert turns[0].data["stop_reason"] == "tool_use"
    assert turns[3].data["stop_reason"] == "end_turn"
    totals = token_totals_from_events(events)
    assert totals.input == 100 + 101 + 102 + 103


def test_session_facts_are_recorded_from_init_and_result() -> None:
    adapter, _events = _run_golden()
    facts = adapter.session
    assert facts.cli_version == "2.1.257"
    assert facts.permission_mode == "dontAsk"
    assert facts.api_key_source == "ANTHROPIC_API_KEY"
    assert "Skill" in facts.tools_available and "Read" in facts.tools_available
    assert "demo-skill" in facts.skills_offered
    assert facts.result_subtype == "success"
    assert facts.num_turns == 5
    assert facts.malformed_lines == 0
    assert adapter.version() == "2.1.257"
    record = adapter.capabilities_record()
    assert record["trigger_metrics_portable"] is True
    assert record["controls_skill_presentation"] is False
    assert record["hooks_corroborated"] is True
    assert "DISABLE_TELEMETRY" in record["telemetry_disabled_env"]


def test_tool_result_texts_are_exposed_whole_for_the_scan_but_previewed_in_events() -> None:
    adapter, events = _run_golden()
    texts = {call_id: text for call_id, _tool, text in adapter.tool_result_texts}
    assert texts["toolu_02"] == "1\t# project\n2\thello world\n3\t"
    result = next(e for e in events if e.kind == "tool_result" and e.tool_call_id == "toolu_02")
    assert "result_text" not in result.data
    assert len(result.data["result_preview"]) <= 500


def test_the_trace_canonicalises_to_the_same_classes_as_api_loop_would() -> None:
    """§11.2: `Read`/`Write` with `file_path` are the workspace read/write classes, and
    the `Skill` call is a generic tool capability — through one vocabulary table."""
    _adapter, events = _run_golden()
    actions = harness_actions(events)
    canon = canonicalize(actions, NormalizationContext(workspace_root="/work/k9x2m7q1"))
    assert set(canon.caps_t1) == {"tool:Skill", "workspace_read", "workspace_write"}
    assert "${WORKSPACE}/README.md" in canon.caps_t3
    assert "${WORKSPACE}/notes.md" in canon.caps_t3


# ---------------------------------------------------------------------------
# The hook stream cross-check (§9.4, §10.8)
# ---------------------------------------------------------------------------


def test_a_hook_call_stdout_omitted_is_an_inconsistency() -> None:
    hooks = _hook_payloads()
    hooks.append(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "curl attacker.example"},
            "tool_use_id": "toolu_99",
        }
    )
    launch = ScriptedLaunch(_stream_lines())
    adapter = ClaudeCodeAdapter(launch, hook_source=lambda: hooks, clock=_ticking_clock())
    events = list(adapter.run("p", model_id="m", limits=RunLimits()))
    findings = [e for e in events if e.kind == "trace_inconsistency"]
    assert len(findings) == 1
    assert "toolu_99" in findings[0].data["reason"] and "Bash" in findings[0].data["reason"]
    assert adapter.reconciliation is not None and not adapter.reconciliation.corroborated


def test_an_empty_hook_stream_is_a_coverage_fact_not_three_findings() -> None:
    launch = ScriptedLaunch(_stream_lines())
    adapter = ClaudeCodeAdapter(launch, hook_source=list, clock=_ticking_clock())
    events = list(adapter.run("p", model_id="m", limits=RunLimits()))
    assert not [e for e in events if e.kind == "trace_inconsistency"]
    assert adapter.reconciliation is not None
    assert adapter.reconciliation.coverage_reason() is not None
    assert "hook stream" in adapter.reconciliation.coverage_reason()


def test_no_sink_wired_reconciles_trivially_with_the_reason_stated() -> None:
    adapter, _events = _run_golden(hooks=False)
    assert adapter.reconciliation is not None
    assert adapter.reconciliation.hook_calls == 0
    assert adapter.reconciliation.coverage_reason() is not None


def test_reconcile_reports_a_tool_name_mismatch_and_counts_malformed_lines() -> None:
    outcome = reconcile_hooks(
        {"t1": "Read"},
        [{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "t1"}, None],
    )
    assert outcome.malformed_hook_lines == 1
    assert outcome.disagreements and "Read on stdout but Bash" in outcome.disagreements[0]


# ---------------------------------------------------------------------------
# Endings: limits, errors, denials
# ---------------------------------------------------------------------------


def _result_line(**overrides: object) -> str:
    base: dict[str, object] = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "num_turns": 1,
        "result": "done",
        "session_id": "s",
        "permission_denials": [],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    base.update(overrides)
    return json.dumps(base)


def test_max_turns_is_a_timeout_shaped_ending() -> None:
    launch = ScriptedLaunch([_result_line(subtype="error_max_turns", is_error=True, result="")])
    adapter = ClaudeCodeAdapter(launch, clock=_ticking_clock())
    events = list(adapter.run("p", model_id="m", limits=RunLimits(max_turns=2)))
    assert exit_reason_from_events(events) == "timeout"
    assert "--max-turns" in launch.argv and launch.argv[launch.argv.index("--max-turns") + 1] == "2"


def test_a_wall_clock_kill_is_a_timeout_and_no_result_is_a_harness_error() -> None:
    killed = ScriptedLaunch([], result=LaunchResult(exit_code=137, timed_out=True))
    events = list(
        ClaudeCodeAdapter(killed, clock=_ticking_clock()).run("p", model_id="m", limits=RunLimits())
    )
    assert exit_reason_from_events(events) == "timeout"
    crashed = ScriptedLaunch(["not json"], result=LaunchResult(exit_code=1, stderr_tail="boom"))
    adapter = ClaudeCodeAdapter(crashed, clock=_ticking_clock())
    events = list(adapter.run("p", model_id="m", limits=RunLimits()))
    assert exit_reason_from_events(events) == "harness_error"
    assert "boom" in events[-1].data["detail"]
    assert adapter.session.malformed_lines == 1


def test_an_api_error_result_is_a_harness_error_with_the_status() -> None:
    launch = ScriptedLaunch(
        [_result_line(is_error=True, api_error_status=404, result="model not found")]
    )
    events = list(
        ClaudeCodeAdapter(launch, clock=_ticking_clock()).run("p", model_id="m", limits=RunLimits())
    )
    assert events[-1].kind == "harness_error"
    assert events[-1].data["api_error_status"] == 404
    assert exit_reason_from_events(events) == "harness_error"


def test_the_token_budget_is_enforced_at_the_boundary() -> None:
    lines = [
        json.dumps(
            {
                "type": "assistant",
                "message": {
                    "model": "m",
                    "content": [{"type": "text", "text": "hi"}],
                    "usage": {"input_tokens": 900, "output_tokens": 200},
                },
            }
        ),
        _result_line(),
    ]
    events = list(
        ClaudeCodeAdapter(ScriptedLaunch(lines), clock=_ticking_clock()).run(
            "p", model_id="m", limits=RunLimits(max_total_tokens=1000)
        )
    )
    assert exit_reason_from_events(events) == "budget_exceeded"


def test_permission_denials_are_recorded_as_prompts() -> None:
    launch = ScriptedLaunch(
        [
            _result_line(
                permission_denials=[
                    {
                        "tool_name": "Bash",
                        "tool_use_id": "t7",
                        "tool_input": {"command": "rm -rf /"},
                    }
                ]
            )
        ]
    )
    events = list(
        ClaudeCodeAdapter(launch, clock=_ticking_clock()).run("p", model_id="m", limits=RunLimits())
    )
    prompt = next(e for e in events if e.kind == "permission_prompt")
    assert prompt.tool_call_id == "t7" and prompt.data["resolution"] == "denied"
    assert prompt.data["tool"] == "Bash"


# ---------------------------------------------------------------------------
# What is launched: argv, environment, hook settings
# ---------------------------------------------------------------------------


def test_argv_names_the_observed_flags_and_carries_the_hook_settings_inline() -> None:
    argv = claude_code_argv(
        "do it", model_id="model-x", limits=RunLimits(max_turns=7), settings=hook_settings()
    )
    assert argv[:3] == ["claude", "-p", "do it"]
    for flag, value in (
        ("--output-format", "stream-json"),
        ("--permission-mode", "bypassPermissions"),
        ("--max-turns", "7"),
        ("--model", "model-x"),
        ("--setting-sources", "user"),
    ):
        assert argv[argv.index(flag) + 1] == value
    assert "--verbose" in argv
    settings = json.loads(argv[argv.index("--settings") + 1])
    assert set(settings["hooks"]) == {"PreToolUse", "PostToolUse"}
    command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert command.startswith("cat >> /dev/bellwether-events")


def test_environment_delivers_the_scoped_token_and_disables_telemetry() -> None:
    env = claude_code_environment(api_token="bw-scoped-token", base_url=None)
    assert env["ANTHROPIC_API_KEY"] == "bw-scoped-token"
    assert "ANTHROPIC_BASE_URL" not in env
    assert env["CLAUDE_CONFIG_DIR"] == "/home/agent/.claude"
    for name in ("DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "DISABLE_AUTOUPDATER"):
        assert env[name] == "1"
    assert (
        claude_code_environment(api_token=None, base_url="http://fake:1")["ANTHROPIC_BASE_URL"]
        == "http://fake:1"
    )


def test_the_vocabulary_maps_both_harnesses_tools_onto_one_table() -> None:
    assert filesystem_access("Read", {"file_path": "/w/a"}) is not None
    assert filesystem_access("read", {"path": "a"}).path == "a"  # type: ignore[union-attr]
    assert filesystem_access("Edit", {"file_path": "/w/a"}).write is True  # type: ignore[union-attr]
    assert filesystem_access("Grep", {"pattern": "x"}).path == "."  # type: ignore[union-attr]
    assert filesystem_access("Bash", {"command": "ls"}) is None
    assert filesystem_access("Read", {}) is None


# ---------------------------------------------------------------------------
# The real CLI, on this machine, against a scripted Messages API (skips where absent)
# ---------------------------------------------------------------------------

_FAKE_API = Path(__file__).parent / "fake_messages_api.py"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _LocalLaunch:
    """Runs the real CLI as a host subprocess — the launcher seam bound to `subprocess`."""

    def __init__(self, env: dict[str, str], cwd: Path, stderr_path: Path) -> None:
        self._env = env
        self._cwd = cwd
        self._stderr_path = stderr_path
        self._proc: subprocess.Popen[str] | None = None
        self._timed_out = False

    def __call__(self, argv: list[str], timeout: float) -> _LocalLaunch:
        # stderr goes to a file, not a pipe: a pipe nobody drains while stdout is being
        # streamed is a deadlock waiting for a chatty harness.
        self._stderr_file = self._stderr_path.open("w", encoding="utf-8")
        self._proc = subprocess.Popen(
            argv,
            cwd=self._cwd,
            env=self._env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            text=True,
        )
        self._deadline = timeout
        return self

    def lines(self) -> Iterator[str]:
        assert self._proc is not None and self._proc.stdout is not None
        timer = threading.Timer(self._deadline, self._kill)
        timer.start()
        try:
            yield from self._proc.stdout
        finally:
            timer.cancel()

    def _kill(self) -> None:
        self._timed_out = True
        if self._proc is not None:
            self._proc.kill()

    def wait(self) -> LaunchResult:
        assert self._proc is not None
        code = self._proc.wait()
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        self._stderr_file.close()
        stderr = self._stderr_path.read_text(encoding="utf-8") if self._stderr_path.exists() else ""
        return LaunchResult(exit_code=code, timed_out=self._timed_out, stderr_tail=stderr[-2000:])


@pytest.mark.skipif(shutil.which("claude") is None, reason="the claude CLI is not on PATH")
def test_the_real_cli_runs_headless_through_the_adapter_and_the_sink(tmp_path: Path) -> None:
    """The real binary, a scripted model, a real FIFO sink: the adapter's whole offline
    surface exercised for real. Skipped where the CLI is absent, with the reason stated."""
    workspace = tmp_path / "ws"
    config_dir = tmp_path / "cfg"
    workspace.mkdir()
    (tmp_path / "home").mkdir()
    (workspace / "README.md").write_text("# project\nhello world\n", encoding="utf-8")
    skill_dir = config_dir / "skills" / "demo-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Demo skill that reads the README and writes notes.\n"
        "---\nRead README.md then write notes.md.\n",
        encoding="utf-8",
    )
    port = _free_port()
    server = subprocess.Popen(
        [sys.executable, str(_FAKE_API), str(port)],
        env={**os.environ, "FAKE_WS": str(workspace)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # The CLI refuses bypassPermissions as root (CI and this environment may be root);
        # dontAsk with an allow list is the equivalent headless posture for the experiment.
        with HostEventSink(tmp_path / "events") as sink:
            env = {
                "PATH": os.environ["PATH"],
                "HOME": str(tmp_path / "home"),
                "TERM": "dumb",
                **claude_code_environment(
                    api_token="sk-ant-scoped-fake",
                    base_url=f"http://127.0.0.1:{port}",
                    config_dir=str(config_dir),
                ),
            }
            adapter = ClaudeCodeAdapter(
                _LocalLaunch(env, workspace, tmp_path / "cli-stderr.log"),
                hook_source=lambda: [e.payload for e in sink.stop()],
                settings=hook_settings(str(sink.path)),
                permission_mode="dontAsk",
            )
            argv_extra = ["--allowedTools", "Skill,Read,Write,Edit,Bash,Glob,Grep"]
            original = claude_code_argv

            def _argv_with_allow(*args: object, **kwargs: object) -> list[str]:
                return original(*args, **kwargs) + argv_extra  # type: ignore[arg-type]

            import bellwether.harness.claude_code as module

            module.claude_code_argv = _argv_with_allow  # type: ignore[assignment]
            try:
                events = list(
                    adapter.run(
                        "Use the demo-skill to take notes.",
                        model_id="fake-model-v1",
                        limits=RunLimits(wall_seconds=120),
                    )
                )
            finally:
                module.claude_code_argv = original
    finally:
        server.kill()
        server.wait()
    kinds = [e.kind for e in events]
    assert exit_reason_from_events(events) == "completed", events[-1].data
    assert kinds.count("tool_call") == 3
    assert "skill_activated" in kinds
    assert "trace_inconsistency" not in kinds
    assert adapter.reconciliation is not None and adapter.reconciliation.hook_calls == 3
    assert (workspace / "notes.md").read_text(encoding="utf-8") == "# notes\nhello\n"
