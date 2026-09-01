"""The ``claude-code`` adapter: the real CLI as the harness (§9.4 adapter 1, §10.1).

Runs the Claude Code CLI non-interactively inside the sandbox — ``claude -p <prompt>
--output-format stream-json`` — and reads two independent sources of what it did:

1. **Its structured stdout stream.** One JSON object per line: a ``system``/``init`` line
   (session, model, permission mode, tools, skills offered), an ``assistant`` line per model
   turn carrying the message's content blocks (``text`` / ``tool_use``) and usage, a ``user``
   line per tool result (``tool_result`` block, correlated by ``tool_use_id``), and a final
   ``result`` line (outcome subtype, ``is_error``, ``permission_denials``, token totals).
   This is Plane A's semantic layer, mapped onto the §11.3 event vocabulary.
2. **Its hook stream.** The CLI's own ``PreToolUse``/``PostToolUse`` hooks are configured to
   append their stdin JSON to the **host-owned sink** (§10.1) — a FIFO the container can
   write but never read or truncate. The two sources are cross-checked after the run: a tool
   call one reports and the other does not is a ``trace_inconsistency`` (§10.8), because the
   whole point of the second source is that it does not depend on parsing stdout.

Where the facts came from — the exact CLI version, flag names, stream and hook field names —
is a **build-time observation**, not an assumption: the shapes below were taken from a real
headless session of CLI 2.1.257 against a scripted Messages API (``tests/golden/claude-code``),
as §9.4 instructs ("consult the harness's current CLI and hooks documentation at build time
rather than assuming flag names; they change"). The parser tolerates unknown line types and
fields rather than refusing them, and records what it could not read.

The critical difference from ``api-loop``: this harness **controls its own skill
presentation**, so activation and trigger measurements describe the skill's behaviour in a
real harness, and ``trigger_metrics_portable`` is True. And its model calls originate
*inside* the sandbox, so they can only leave through the recording proxy carrying the
sandbox-scoped token — this is the adapter where §3.3 invariant 1 actually bites.

Layering: this module knows the CLI and the sink's *line format*; it must not know about
canaries, assertions, or the trace format (``harness -> capture -> trace``). Tool-result text
is exposed on the adapter for the executor to scan; it never enters the event payloads whole.
"""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from bellwether.determinism import canonical_json, stable_hash
from bellwether.harness.protocol import HarnessCapabilities, RawHarnessEvent, RunLimits

__all__ = [
    "CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS",
    "CLAUDE_CODE_TELEMETRY_ENV",
    "ClaudeCodeAdapter",
    "HookReconciliation",
    "LaunchResult",
    "LaunchedProcess",
    "Launcher",
    "ScriptedLaunch",
    "SessionFacts",
    "claude_code_argv",
    "claude_code_environment",
    "hook_settings",
]

#: Characters of a tool result carried in the event payload as a preview; the full text is
#: bound by its digest, and exposed separately for the canary scan (§10.4).
_PREVIEW_CHARS = 500

#: The environment that turns the CLI's own optional traffic off (§10.5.0). Each is recorded
#: in the trace as set, so a reader knows the harness was told not to phone home — and the
#: hosts it would otherwise contact are still declared as infrastructure below, because a
#: flag is a request and an allowlist entry is what keeps a stray telemetry call from reading
#: as a skill's egress.
CLAUDE_CODE_TELEMETRY_ENV: Mapping[str, str] = {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_AUTOUPDATER": "1",
    "DISABLE_BUG_COMMAND": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
}

#: Hosts the CLI contacts on its own behalf: usage telemetry and error reporting intake
#: (§9.4 ``infrastructure_endpoints``). Declared by suffix so a regional intake host still
#: classifies as ``harness_infrastructure`` rather than as the skill's egress (§10.5.0).
#: Deliberately *not* here: the download, package-registry and documentation hosts the CLI
#: reaches for updates and plugin installs — auto-update is disabled, nothing is installed at
#: run time, and an allowlisted content host is a route a skill could carry data out on.
CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS: tuple[str, ...] = (
    "datadoghq.com",
    "sentry.io",
    "statsig.com",
)

#: The permission mode the CLI runs under. ``bypassPermissions`` is what makes a headless run
#: proceed through every tool call without a prompt; every call is therefore *auto-approved*,
#: which the trace records rather than hides (§10.1 — "critical for detecting privilege
#: pre-approval"). The CLI refuses this mode as root; the sandbox runs as uid 1000.
DEFAULT_PERMISSION_MODE = "bypassPermissions"

#: The container path the host-owned sink FIFO is bound at (§10.1) and the hook command that
#: appends stdin to it. ``>>`` opens the FIFO write-only, which is the only open the node's
#: mode permits from inside; the trailing ``echo`` keeps the hook's own stdout a valid
#: (empty-line) response so the CLI never treats the recorder as a blocking hook.
DEFAULT_SINK_CONTAINER_PATH = "/dev/bellwether-events"
_HOOK_EVENTS: tuple[str, ...] = ("PreToolUse", "PostToolUse")


# ---------------------------------------------------------------------------
# What to run: argv, environment, hook settings (pure, unit-tested)
# ---------------------------------------------------------------------------


def hook_settings(sink_container_path: str = DEFAULT_SINK_CONTAINER_PATH) -> dict[str, Any]:
    """The ``--settings`` JSON that makes every tool call write its hook event to the sink.

    One hook per event, no matcher (every tool), one ``command`` that appends stdin. This is
    the second, in-band source of tool-call evidence §9.4 asks for; it is independent of the
    stdout parser and lands on a channel the container cannot rewrite.
    """
    command = f"cat >> {sink_container_path}; echo"
    return {
        "hooks": {
            event: [{"hooks": [{"type": "command", "command": command}]}] for event in _HOOK_EVENTS
        }
    }


def claude_code_argv(
    prompt: str,
    *,
    model_id: str,
    limits: RunLimits,
    settings: Mapping[str, Any] | None = None,
    permission_mode: str = DEFAULT_PERMISSION_MODE,
    binary: str = "claude",
) -> list[str]:
    """The CLI invocation for one run (the flags observed on CLI 2.1.257).

    ``--setting-sources user`` reads the container user's own ``~/.claude/settings.json`` (the
    staged harness state) and nothing project-scoped from the workspace — a fixture could
    otherwise carry a ``.claude/settings.json`` that reconfigures the harness under test.
    ``--settings`` carries the hook configuration inline so no extra file is mounted. The
    model is passed by the resolved id, never an alias (§9.5).
    """
    argv = [
        binary,
        "-p",
        prompt,
        "--output-format",
        "stream-json",
        "--verbose",
        "--permission-mode",
        permission_mode,
        "--max-turns",
        str(limits.max_turns),
        "--model",
        model_id,
        "--setting-sources",
        "user",
    ]
    if settings is not None:
        argv += ["--settings", json.dumps(settings, sort_keys=True, separators=(",", ":"))]
    return argv


def claude_code_environment(
    *,
    api_token: str | None,
    base_url: str | None = None,
    config_dir: str = "/home/agent/.claude",
) -> dict[str, str]:
    """The environment the CLI runs under inside the sandbox.

    ``api_token`` is the **sandbox-scoped** token the recording proxy swaps for the real key
    on the way out (§3.3 invariant 1, §10.5.1) — never the real key. It is delivered under
    ``ANTHROPIC_API_KEY`` because that is the variable the CLI reads, whatever name the
    provider's ``api_key_env`` uses on the host. ``base_url`` overrides the API endpoint only
    where the provider configures one. ``config_dir`` pins the CLI's state directory to the
    harness-state zone so its session writes are captured there (§10.2).
    """
    env: dict[str, str] = dict(CLAUDE_CODE_TELEMETRY_ENV)
    env["CLAUDE_CONFIG_DIR"] = config_dir
    if api_token is not None:
        env["ANTHROPIC_API_KEY"] = api_token
    if base_url:
        env["ANTHROPIC_BASE_URL"] = base_url
    return env


# ---------------------------------------------------------------------------
# The launch seam
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LaunchResult:
    """How the CLI process ended."""

    exit_code: int
    timed_out: bool = False
    stderr_tail: str = ""


class LaunchedProcess(Protocol):
    """A running CLI: its stdout as lines, then how it ended."""

    def lines(self) -> Iterator[str]: ...

    def wait(self) -> LaunchResult: ...


#: Starts the CLI with an argv under a wall-clock bound. Injected: the executor binds it to a
#: ``docker exec`` into the run's container; tests script the stream.
Launcher = Callable[[list[str], float], LaunchedProcess]


class ScriptedLaunch:
    """A launched process that replays a fixed stdout, for tests and golden fixtures."""

    def __init__(self, stdout_lines: Sequence[str], *, result: LaunchResult | None = None) -> None:
        self._lines = list(stdout_lines)
        self._result = result or LaunchResult(exit_code=0)
        self.argv: list[str] = []
        self.timeout: float = 0.0

    def __call__(self, argv: list[str], timeout: float) -> ScriptedLaunch:
        self.argv = list(argv)
        self.timeout = timeout
        return self

    def lines(self) -> Iterator[str]:
        yield from self._lines

    def wait(self) -> LaunchResult:
        return self._result


# ---------------------------------------------------------------------------
# What the run said about itself
# ---------------------------------------------------------------------------


@dataclass
class SessionFacts:
    """Facts the CLI reported in its ``init`` and ``result`` lines (§9.3, §10.1)."""

    cli_version: str | None = None
    session_id: str | None = None
    permission_mode: str | None = None
    api_key_source: str | None = None
    model_reported: str | None = None
    tools_available: tuple[str, ...] = ()
    skills_offered: tuple[str, ...] = ()
    result_subtype: str | None = None
    num_turns: int | None = None
    #: Lines on stdout that were not JSON objects. Kept as a count: garbage on the harness's
    #: own channel is evidence too, and the trace must not read as if the stream was clean.
    malformed_lines: int = 0
    unknown_line_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class HookReconciliation:
    """The cross-check between the stdout stream and the hook stream (§9.4, §10.8)."""

    #: Tool calls stdout reported, by ``tool_use_id``.
    stdout_calls: int
    #: ``PreToolUse`` events the sink received, by ``tool_use_id``.
    hook_calls: int
    #: Sink lines that were not readable hook events.
    malformed_hook_lines: int
    disagreements: tuple[str, ...]

    @property
    def corroborated(self) -> bool:
        return not self.disagreements

    def coverage_reason(self) -> str | None:
        """Why the harness-events plane is not ``full``, or ``None`` where it is."""
        if self.stdout_calls and not self.hook_calls:
            return (
                "the CLI reported tool calls on stdout but its hook stream reached the host "
                "sink empty; Plane A rests on the parsed stdout alone"
            )
        if self.disagreements:
            return (
                f"the CLI's stdout and hook streams disagree on {len(self.disagreements)} "
                "tool call(s); see the trace_inconsistency records"
            )
        return None


#: A hook event as the sink delivered it: the parsed payload, or ``None`` where the line was
#: not a JSON object. The executor hands these over from the sink after the run.
HookSource = Callable[[], Sequence[Mapping[str, Any] | None]]


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------


@dataclass
class _PendingCall:
    tool: str
    tool_input: dict[str, Any]
    started: dt.datetime
    turn: int


class ClaudeCodeAdapter:
    """The Claude Code CLI as a harness adapter (§9.4 adapter 1)."""

    name = "claude-code"

    def __init__(
        self,
        launcher: Launcher,
        *,
        hook_source: HookSource | None = None,
        settings: Mapping[str, Any] | None = None,
        permission_mode: str = DEFAULT_PERMISSION_MODE,
        binary: str = "claude",
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        """Args:
        launcher: Starts the CLI (``argv``, wall-clock seconds) and streams its stdout.
        hook_source: Yields the sink's hook events after the CLI exits; ``None`` where no
            sink is wired, in which case the plane rests on stdout alone and says so.
        settings: The ``--settings`` JSON (normally :func:`hook_settings`).
        permission_mode: The CLI permission mode; recorded on every run.
        clock: Injected for deterministic tests; defaults to real UTC time. Event
            timestamps are the host's receipt time of each stdout line.
        """
        self._launcher = launcher
        self._hook_source = hook_source
        self._settings = settings
        self._permission_mode = permission_mode
        self._binary = binary
        self._clock = clock or (lambda: dt.datetime.now(dt.UTC))
        self.session = SessionFacts()
        self.reconciliation: HookReconciliation | None = None
        #: ``(tool_call_id, tool, full result text)`` for every tool result the CLI reported,
        #: for the executor's canary scan (§10.4.1: a marker in a tool result is the recorded
        #: read). Never placed in an event payload whole.
        self.tool_result_texts: list[tuple[str, str, str]] = []
        #: The argv actually run, for the trace's command record.
        self.last_argv: list[str] = []

    def version(self) -> str:
        """The CLI version the run reported, once it has; the adapter's own before."""
        return self.session.cli_version or "unknown"

    def capabilities(self) -> HarnessCapabilities:
        return self.static_capabilities()

    @staticmethod
    def static_capabilities() -> HarnessCapabilities:
        """The adapter's declaration — static, so the §16.4 preflight can read it."""
        return HarnessCapabilities(
            structured_tool_events=True,
            supports_hooks=True,
            token_accounting=True,
            multi_turn=True,
            multiple_skills=True,
            # Adapter-alone truth, as for api-loop: egress becomes observed when the executor
            # stands the proxy up — and for this adapter the proxy is not optional, since the
            # CLI's own model calls have no other way out (§3.3).
            egress_observable=False,
            # The CLI presents skills to the model its own way; Bellwether only installs the
            # skill and writes the prompt. Trigger metrics therefore describe the skill in a
            # real harness — the reason this adapter is in v0.1 (§9.4).
            controls_skill_presentation=False,
            infrastructure_endpoints=CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS,
        )

    def capabilities_record(self) -> dict[str, Any]:
        """The trace-embeddable declaration plus what this run recorded about the harness."""
        record = self.static_capabilities().as_record()
        record["permission_mode"] = self._permission_mode
        record["telemetry_disabled_env"] = sorted(CLAUDE_CODE_TELEMETRY_ENV)
        record["cli_version"] = self.session.cli_version
        record["hooks_corroborated"] = (
            self.reconciliation.corroborated if self.reconciliation is not None else None
        )
        return record

    # -- the run --------------------------------------------------------------

    def run(self, prompt: str, *, model_id: str, limits: RunLimits) -> Iterator[RawHarnessEvent]:
        self.session = SessionFacts()
        self.reconciliation = None
        self.tool_result_texts = []
        argv = claude_code_argv(
            prompt,
            model_id=model_id,
            limits=limits,
            settings=self._settings,
            permission_mode=self._permission_mode,
            binary=self._binary,
        )
        self.last_argv = argv
        process = self._launcher(argv, limits.wall_seconds)

        pending: dict[str, _PendingCall] = {}
        stdout_calls: dict[str, str] = {}
        turn = 0
        tokens_used = 0
        saw_result = False
        for raw in process.lines():
            line = raw.strip()
            if not line:
                continue
            ts = self._clock()
            try:
                record = json.loads(line)
            except ValueError:
                self.session.malformed_lines += 1
                continue
            if not isinstance(record, dict):
                self.session.malformed_lines += 1
                continue
            kind = record.get("type")

            if kind == "system":
                if record.get("subtype") == "init":
                    yield from self._on_init(record, ts)
                continue

            if kind == "assistant":
                turn += 1
                message = _dict(record.get("message"))
                usage = _dict(message.get("usage"))
                tokens = {
                    "input": _int(usage.get("input_tokens")),
                    "output": _int(usage.get("output_tokens")),
                    "cache_read": _int(usage.get("cache_read_input_tokens")),
                    "cache_write": _int(usage.get("cache_creation_input_tokens")),
                }
                tokens_used += sum(tokens.values())
                content = _list(message.get("content"))
                tool_blocks = [
                    b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"
                ]
                reported = message.get("model")
                if isinstance(reported, str) and reported:
                    self.session.model_reported = reported
                yield RawHarnessEvent(
                    ts=ts,
                    kind="model_turn",
                    turn=turn,
                    data={
                        "model_id_requested": model_id,
                        "model_id_reported": reported if isinstance(reported, str) else None,
                        "stop_reason": _stop_reason(message.get("stop_reason"), bool(tool_blocks)),
                        "tokens": tokens,
                        "message_id": message.get("id"),
                    },
                )
                for block in tool_blocks:
                    call_id = str(block.get("id") or f"tool_{turn}_{len(pending) + 1}")
                    tool = str(block.get("name") or "unknown")
                    tool_input = _dict(block.get("input"))
                    pending[call_id] = _PendingCall(tool, tool_input, ts, turn)
                    stdout_calls[call_id] = tool
                    yield RawHarnessEvent(
                        ts=ts,
                        kind="tool_call",
                        turn=turn,
                        tool_call_id=call_id,
                        data={
                            "tool": tool,
                            "input": tool_input,
                            "input_digest": stable_hash(canonical_json(tool_input)),
                            # Every call under a headless permission mode is pre-approved:
                            # the harness never asked, so nothing could have declined (§10.1).
                            "permission": _permission_label(self._permission_mode),
                        },
                    )
                continue

            if kind == "user":
                message = _dict(record.get("message"))
                # A string `content` is a synthetic text line (the skill body being injected)
                # or a replayed prompt: no tool result, nothing to record.
                for block in _list(message.get("content")):
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    call_id = str(block.get("tool_use_id") or "")
                    call = pending.pop(call_id, None)
                    tool = call.tool if call is not None else "unknown"
                    text = _result_text(block.get("content"))
                    is_error = bool(block.get("is_error"))
                    started = call.started if call is not None else ts
                    duration_ms = max(0, int((ts - started).total_seconds() * 1000))
                    self.tool_result_texts.append((call_id, tool, text))
                    if call is not None and tool == "Skill" and not is_error:
                        skill = call.tool_input.get("skill")
                        if isinstance(skill, str):
                            for activation_kind in ("skill_activated", "skill_body_loaded"):
                                yield RawHarnessEvent(
                                    ts=ts,
                                    kind=activation_kind,
                                    turn=call.turn,
                                    tool_call_id=call_id,
                                    data={"skill": skill},
                                )
                    yield RawHarnessEvent(
                        ts=ts,
                        kind="tool_result",
                        turn=call.turn if call is not None else turn,
                        tool_call_id=call_id,
                        data={
                            "tool": tool,
                            "outcome": "error" if is_error else "ok",
                            "error": text if is_error else None,
                            "duration_ms": duration_ms,
                            "result_digest": stable_hash(text),
                            "result_preview": text[:_PREVIEW_CHARS],
                            "truncated": len(text) > _PREVIEW_CHARS,
                        },
                    )
                continue

            if kind == "result":
                saw_result = True
                yield from self._on_result(record, ts, turn)
                continue

            if isinstance(kind, str) and kind not in self.session.unknown_line_types:
                self.session.unknown_line_types += (kind,)

        outcome = process.wait()
        if outcome.timed_out:
            yield RawHarnessEvent(
                ts=self._clock(),
                kind="harness_error",
                turn=turn or None,
                data={
                    "exit_reason": "timeout",
                    "detail": f"wall clock: {limits.wall_seconds:.0f}s",
                },
            )
        elif not saw_result:
            yield RawHarnessEvent(
                ts=self._clock(),
                kind="harness_error",
                turn=turn or None,
                data={
                    "exit_reason": "harness_error",
                    "detail": (
                        f"the CLI exited {outcome.exit_code} without a result line"
                        + (
                            f": {outcome.stderr_tail.strip()}"
                            if outcome.stderr_tail.strip()
                            else ""
                        )
                    ),
                },
            )
        if tokens_used > limits.max_total_tokens:
            # An operator limit the CLI has no flag for, so it is enforced at the boundary:
            # the run spent more than allowed and is not_evaluable, never a pass (§12.7).
            yield RawHarnessEvent(
                ts=self._clock(),
                kind="harness_error",
                turn=turn or None,
                data={
                    "exit_reason": "budget_exceeded",
                    "detail": f"token budget: {limits.max_total_tokens} (used {tokens_used})",
                },
            )

        # The second source: the hook stream the sink collected, cross-checked against stdout.
        hook_events = list(self._hook_source()) if self._hook_source is not None else None
        self.reconciliation = reconcile_hooks(stdout_calls, hook_events)
        for reason in self.reconciliation.disagreements:
            yield RawHarnessEvent(
                ts=self._clock(),
                kind="trace_inconsistency",
                data={"signal": "harness_hook_vs_stdout", "reason": reason},
            )

    # -- pieces -------------------------------------------------------------------

    def _on_init(self, record: dict[str, Any], ts: dt.datetime) -> Iterator[RawHarnessEvent]:
        facts = self.session
        facts.cli_version = _opt_str(record.get("claude_code_version"))
        facts.session_id = _opt_str(record.get("session_id"))
        facts.permission_mode = _opt_str(record.get("permissionMode"))
        facts.api_key_source = _opt_str(record.get("apiKeySource"))
        facts.model_reported = _opt_str(record.get("model")) or facts.model_reported
        facts.tools_available = _str_tuple(record.get("tools"))
        facts.skills_offered = _str_tuple(record.get("skills"))
        for skill in facts.skills_offered:
            yield RawHarnessEvent(ts=ts, kind="skill_offered", data={"skill": skill})

    def _on_result(
        self, record: dict[str, Any], ts: dt.datetime, turn: int
    ) -> Iterator[RawHarnessEvent]:
        facts = self.session
        facts.result_subtype = _opt_str(record.get("subtype"))
        facts.num_turns = (
            _int(record.get("num_turns")) if record.get("num_turns") is not None else None
        )
        denials = record.get("permission_denials")
        if isinstance(denials, list):
            for denial in denials:
                if not isinstance(denial, dict):
                    continue
                yield RawHarnessEvent(
                    ts=ts,
                    kind="permission_prompt",
                    turn=turn or None,
                    tool_call_id=_opt_str(denial.get("tool_use_id")),
                    data={
                        "tool": _opt_str(denial.get("tool_name")),
                        "resolution": "denied",
                        "input": denial.get("tool_input")
                        if isinstance(denial.get("tool_input"), dict)
                        else None,
                    },
                )
        subtype = facts.result_subtype or ""
        is_error = bool(record.get("is_error"))
        text = record.get("result")
        if subtype == "success" and not is_error:
            yield RawHarnessEvent(
                ts=ts,
                kind="final_output",
                turn=turn or None,
                data={"text": text if isinstance(text, str) else ""},
            )
            return
        detail = text if isinstance(text, str) and text else subtype or "error"
        exit_reason = _exit_reason_for(subtype)
        yield RawHarnessEvent(
            ts=ts,
            kind="harness_error",
            turn=turn or None,
            data={
                "exit_reason": exit_reason,
                "detail": detail,
                "result_subtype": subtype or None,
                "api_error_status": record.get("api_error_status"),
            },
        )


def reconcile_hooks(
    stdout_calls: Mapping[str, str], hook_events: Sequence[Mapping[str, Any] | None] | None
) -> HookReconciliation:
    """Cross-check the tool calls stdout reported against the hook stream (§9.4, §10.8).

    Both sources key on the provider-assigned ``tool_use_id``, so the comparison is exact
    rather than by position or time. A ``None`` hook source (no sink wired) reconciles
    trivially with no hook calls, and the coverage reason says the plane rests on stdout.
    """
    if hook_events is None:
        return HookReconciliation(
            stdout_calls=len(stdout_calls),
            hook_calls=0,
            malformed_hook_lines=0,
            disagreements=(),
        )
    hooked: dict[str, str] = {}
    malformed = 0
    for payload in hook_events:
        if payload is None:
            malformed += 1
            continue
        if payload.get("hook_event_name") != "PreToolUse":
            continue
        call_id = payload.get("tool_use_id")
        tool = payload.get("tool_name")
        if isinstance(call_id, str) and isinstance(tool, str):
            hooked[call_id] = tool
    disagreements: list[str] = []
    for call_id in sorted(set(stdout_calls) - set(hooked)):
        if not hooked:
            continue  # an empty hook stream is a coverage fact, not N disagreements
        disagreements.append(
            f"stdout reported tool call {call_id} ({stdout_calls[call_id]}) that the hook "
            "stream never saw (§10.8: the host-sink hook record corroborates stdout)"
        )
    for call_id in sorted(set(hooked) - set(stdout_calls)):
        disagreements.append(
            f"the hook stream recorded tool call {call_id} ({hooked[call_id]}) that stdout "
            "never reported (§10.8: a call the structured output omitted)"
        )
    for call_id in sorted(set(hooked) & set(stdout_calls)):
        if hooked[call_id] != stdout_calls[call_id]:
            disagreements.append(
                f"tool call {call_id} is {stdout_calls[call_id]} on stdout but "
                f"{hooked[call_id]} in the hook stream"
            )
    return HookReconciliation(
        stdout_calls=len(stdout_calls),
        hook_calls=len(hooked),
        malformed_hook_lines=malformed,
        disagreements=tuple(disagreements),
    )


# ---------------------------------------------------------------------------
# Small readers
# ---------------------------------------------------------------------------


def _int(value: object) -> int:
    return int(value) if isinstance(value, int | float) else 0


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _str_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _stop_reason(
    reported: object, has_tool_use: bool
) -> Literal["end_turn", "tool_use", "max_tokens", "other"]:
    """The provider's stop reason, or — where the CLI emits the line before the stream's
    ``message_delta`` carried one (observed as ``null``) — the reason the content implies."""
    if reported == "end_turn":
        return "end_turn"
    if reported == "tool_use":
        return "tool_use"
    if reported == "max_tokens":
        return "max_tokens"
    if reported is None or reported == "":
        return "tool_use" if has_tool_use else "end_turn"
    return "other"


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _result_text(content: object) -> str:
    """A tool result's text: a string, or the text blocks of a content list joined."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            str(block.get("text", ""))
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        return "\n".join(parts)
    return ""


def _exit_reason_for(subtype: str) -> str:
    if subtype == "error_max_turns":
        return "timeout"
    if subtype == "error_max_budget_usd":
        return "budget_exceeded"
    return "harness_error"


def _permission_label(mode: str) -> str:
    return (
        "auto_approved" if mode in ("bypassPermissions", "dontAsk", "acceptEdits", "auto") else mode
    )
