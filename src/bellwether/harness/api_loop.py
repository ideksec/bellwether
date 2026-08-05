"""The ``api-loop`` adapter: the reference harness (§9.4).

A minimal agent loop against a provider's messages/tool-use API, with the tool set
implemented by Bellwether itself. It exists for three reasons: it is the reference
implementation of the event stream, the generator of §24's golden traces, and the
fallback for providers with no CLI.

**Critical limitation, §9.4.** This adapter writes the system prompt and decides how
skill descriptions are presented to the model. Activation rate, trigger entropy, and
coexistence collisions measured here are measurements of Bellwether's own prompt
assembly, not of the skill's behaviour in a real harness. The capabilities declaration
carries ``controls_skill_presentation=True``, from which every trigger-derived metric
gets its ``harness-specific: not portable`` label — wired at this boundary, so the
metrics layer derives the label from a declaration rather than from knowing adapter
names.

Skill presentation is deliberately boring and deterministic: skills are listed by name
and description in a fixed template, sorted, and the model loads one by calling the
``skill`` tool. Boring is a feature — the golden traces this adapter generates must be
byte-stable, and every ounce of cleverness in prompt assembly here would be measured and
mistaken for skill behaviour.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from bellwether.determinism import stable_hash
from bellwether.harness.protocol import HarnessCapabilities, RawHarnessEvent, RunLimits
from bellwether.harness.provider import (
    ModelClient,
    ModelRequest,
    ModelTurn,
    ToolSpec,
)
from bellwether.harness.tools import SandboxToolset

__all__ = ["ApiLoopAdapter", "OfferedSkill"]

#: Characters of a tool result carried in the event payload as a preview. The full
#: result is bound by its digest; the preview is for a human reading the trace.
_PREVIEW_CHARS = 500


@dataclass(frozen=True)
class OfferedSkill:
    """One skill made available to the model for this run."""

    name: str
    description: str
    #: The SKILL.md body, returned when the model loads the skill.
    body: str


class ApiLoopAdapter:
    """The reference agent loop (§9.4 adapter 2)."""

    name = "api-loop"

    def __init__(
        self,
        client: ModelClient,
        toolset: SandboxToolset,
        *,
        skills: tuple[OfferedSkill, ...] = (),
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        """Args:
        client: The model client — a live provider or a scripted transcript.
        toolset: The sandbox tool set, already bound to a running container.
        skills: Skills offered for this run, presented sorted by name.
        clock: Injected for golden traces, which must be byte-stable and therefore
            cannot read the wall clock (§24). Defaults to real UTC time.
        """
        self._client = client
        self._tools = toolset
        self._skills = tuple(sorted(skills, key=lambda skill: skill.name))
        self._clock = clock or (lambda: dt.datetime.now(dt.UTC))

    def version(self) -> str:
        return "0.1"

    def capabilities(self) -> HarnessCapabilities:
        return HarnessCapabilities(
            structured_tool_events=True,
            supports_hooks=False,
            token_accounting=True,
            multi_turn=True,
            multiple_skills=True,
            # The model call is made by Bellwether itself and the container has no
            # egress path at all until WP-13; there is no capture point this adapter's
            # traffic traverses yet. False keeps `no_egress` at `not_evaluable` rather
            # than letting it pass vacuously (§9.4).
            egress_observable=False,
            # The critical limitation: Bellwether writes the prompt, so trigger metrics
            # describe Bellwether, and `trigger_metrics_portable` derives False.
            controls_skill_presentation=True,
            # api-loop phones nothing home on its own behalf.
            infrastructure_endpoints=(),
        )

    # -- the loop -----------------------------------------------------------

    def run(self, prompt: str, *, model_id: str, limits: RunLimits) -> Iterator[RawHarnessEvent]:
        deadline = time.monotonic() + limits.wall_seconds
        tool_calls_made = 0
        tokens_used = 0

        for skill in self._skills:
            yield RawHarnessEvent(
                ts=self._clock(),
                kind="skill_offered",
                data={"skill": skill.name, "description": skill.description},
            )

        system = self._system_prompt()
        messages: list[dict[str, object]] = [
            {"role": "user", "content": [{"type": "text", "text": prompt}]}
        ]
        loaded_skills: set[str] = set()

        for turn in range(1, limits.max_turns + 1):
            if time.monotonic() >= deadline:
                yield self._limit_event("timeout", f"wall clock: {limits.wall_seconds:.0f}s", turn)
                return

            model_turn = self._client.complete(
                ModelRequest(
                    model_id=model_id,
                    system=system,
                    messages=tuple(messages),
                    tools=self._tool_specs(),
                )
            )
            usage = model_turn.usage
            tokens_used += usage.input + usage.output + usage.cache_read + usage.cache_write
            yield RawHarnessEvent(
                ts=self._clock(),
                kind="model_turn",
                turn=turn,
                data={
                    "model_id_requested": model_id,
                    "model_id_reported": model_turn.model_id_reported,
                    "stop_reason": model_turn.stop_reason,
                    "tokens": {
                        "input": usage.input,
                        "output": usage.output,
                        "cache_read": usage.cache_read,
                        "cache_write": usage.cache_write,
                    },
                },
            )
            if tokens_used > limits.max_total_tokens:
                # An operator limit, detected at a turn boundary: budget_exceeded, which
                # is not_evaluable rather than a failure (§12.7).
                yield self._limit_event(
                    "budget_exceeded", f"token budget: {limits.max_total_tokens}", turn
                )
                return

            if not model_turn.tool_calls:
                yield RawHarnessEvent(
                    ts=self._clock(),
                    kind="final_output",
                    turn=turn,
                    data={"text": model_turn.text},
                )
                return

            messages.append(_assistant_message(model_turn))
            results: list[dict[str, object]] = []
            for call in model_turn.tool_calls:
                if tool_calls_made >= limits.max_tool_calls:
                    yield self._limit_event(
                        "timeout", f"tool call limit: {limits.max_tool_calls}", turn
                    )
                    return
                tool_calls_made += 1

                yield RawHarnessEvent(
                    ts=self._clock(),
                    kind="tool_call",
                    turn=turn,
                    tool_call_id=call.id,
                    data={
                        "tool": call.name,
                        "input": call.input,
                        "input_digest": stable_hash(json.dumps(call.input, sort_keys=True)),
                    },
                )
                # Duration from the injected clock, not time.monotonic(): golden traces
                # are byte-compared, and duration is load-bearing for epoch boundaries
                # (§11.5), so it must be as replayable as every other field.
                started = self._clock()
                outcome = self._execute(call.name, call.input, loaded=loaded_skills)
                duration_ms = int((self._clock() - started).total_seconds() * 1000)

                if call.name == "skill" and outcome.activated is not None:
                    yield RawHarnessEvent(
                        ts=self._clock(),
                        kind="skill_activated",
                        turn=turn,
                        tool_call_id=call.id,
                        data={"skill": outcome.activated},
                    )
                    yield RawHarnessEvent(
                        ts=self._clock(),
                        kind="skill_body_loaded",
                        turn=turn,
                        tool_call_id=call.id,
                        data={"skill": outcome.activated},
                    )

                yield RawHarnessEvent(
                    ts=self._clock(),
                    kind="tool_result",
                    turn=turn,
                    tool_call_id=call.id,
                    data={
                        "tool": call.name,
                        "outcome": "ok" if outcome.ok else "error",
                        "error": outcome.error,
                        "duration_ms": duration_ms,
                        "result_digest": outcome.output_digest,
                        "result_preview": outcome.output[:_PREVIEW_CHARS],
                        "truncated": outcome.truncated,
                    },
                )
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": call.id,
                        "content": outcome.output,
                        "is_error": not outcome.ok,
                    }
                )
            messages.append({"role": "user", "content": results})

        yield self._limit_event("timeout", f"turn limit: {limits.max_turns}", limits.max_turns)

    # -- pieces -------------------------------------------------------------

    def _system_prompt(self) -> str:
        """Deterministic by construction: fixed template, skills sorted by name.

        On this adapter the prompt *is* the trigger surface, so it stays boring and
        stable — golden traces are byte-compared, and any variation here would read as
        skill nondeterminism (§9.4).
        """
        lines = [
            "You are a coding agent working in a project workspace.",
            "Use the available tools to complete the user's task, then reply with a short summary.",
        ]
        if self._skills:
            lines.append("")
            lines.append(
                "The following skills are available. To use one, call the `skill` tool"
                " with its name; it returns the skill's full instructions."
            )
            for skill in self._skills:
                lines.append(f"- {skill.name}: {skill.description}")
        return "\n".join(lines)

    def _tool_specs(self) -> tuple[ToolSpec, ...]:
        specs = [ToolSpec(**raw) for raw in SandboxToolset.specs()]
        if self._skills:
            specs.append(
                ToolSpec(
                    name="skill",
                    description="Load a skill's full instructions by name.",
                    input_schema={
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"],
                    },
                )
            )
        return tuple(specs)

    def _execute(
        self, name: str, tool_input: dict[str, object], *, loaded: set[str]
    ) -> _LoopOutcome:
        if name == "skill":
            requested = tool_input.get("name")
            for skill in self._skills:
                if skill.name == requested:
                    loaded.add(skill.name)
                    return _LoopOutcome(
                        ok=True,
                        output=skill.body,
                        output_digest=stable_hash(skill.body),
                        activated=skill.name,
                    )
            offered = ", ".join(skill.name for skill in self._skills) or "none"
            message = f"no skill named {requested!r} is available (offered: {offered})"
            return _LoopOutcome(
                ok=False, output=message, output_digest=stable_hash(message), error=message
            )

        outcome = self._tools.execute(name, dict(tool_input))
        return _LoopOutcome(
            ok=outcome.ok,
            output=outcome.output,
            output_digest=outcome.output_digest,
            error=outcome.error,
            truncated=outcome.truncated,
        )

    def _limit_event(self, exit_reason: str, detail: str, turn: int) -> RawHarnessEvent:
        return RawHarnessEvent(
            ts=self._clock(),
            kind="harness_error",
            turn=turn,
            data={"exit_reason": exit_reason, "limit": detail},
        )


@dataclass(frozen=True)
class _LoopOutcome:
    """A tool outcome plus the loop-level skill-activation signal."""

    ok: bool
    output: str
    output_digest: str
    error: str | None = None
    truncated: bool = False
    activated: str | None = None


def _assistant_message(turn: ModelTurn) -> dict[str, object]:
    content: list[dict[str, object]] = []
    if turn.text:
        content.append({"type": "text", "text": turn.text})
    for call in turn.tool_calls:
        content.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.input})
    return {"role": "assistant", "content": content}
