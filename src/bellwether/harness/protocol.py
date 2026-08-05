"""The harness adapter contract (§9.4).

An adapter is the agent runtime a skill executes under. It reports what happened as a
stream of raw events; it never judges. The two consumers downstream are the trace layer,
which turns raw events into ARF action records, and — via the capabilities declaration —
the precondition check of §16.4, which refuses to start a matrix whose policy requires
evidence the declared capabilities cannot supply.

Capabilities are declared, recorded in the trace, and consulted — never assumed. A
capability the harness cannot observe produces ``not_evaluable``, never ``pass``: a
missing signal must stay distinguishable from an absent behaviour.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "HarnessAdapter",
    "HarnessCapabilities",
    "RawHarnessEvent",
    "RunLimits",
]

#: Event kinds an adapter may emit, a subset of the §11.3 action vocabulary. The adapter
#: speaks in these terms directly so the trace translation is a mapping, not a guess.
HarnessEventKind = Literal[
    "skill_offered",
    "skill_activated",
    "skill_body_loaded",
    "model_turn",
    "tool_call",
    "tool_result",
    "final_output",
    "harness_error",
]


@dataclass(frozen=True)
class RawHarnessEvent:
    """One thing the harness reports having happened (Plane A, §10.1).

    ``tool_call_id`` is the originating id the provider assigned to a tool invocation.
    It is carried on both the ``tool_call`` and its ``tool_result`` — and into the trace
    — because explicit correlation is the strong path for cross-plane attribution
    (§11.5); matching by timestamp is the fallback, not the design.
    """

    ts: dt.datetime
    kind: HarnessEventKind
    #: Kind-specific payload: tool name and input, token usage, output text. Free-form
    #: because the kinds observe different things; the trace layer preserves it.
    data: dict[str, Any] = field(default_factory=dict)
    tool_call_id: str | None = None
    #: Which model turn this event belongs to, 1-based. Set on everything that happens
    #: inside the loop; None on pre-loop events such as ``skill_offered``.
    turn: int | None = None


@dataclass(frozen=True)
class HarnessCapabilities:
    """What an adapter can observe, declared rather than assumed (§9.4).

    The trace records this block so a reader can distinguish "the harness saw nothing"
    from "the harness could not have seen it". The precondition check reads it to refuse
    unsatisfiable policies before any run is paid for.
    """

    structured_tool_events: bool
    supports_hooks: bool
    token_accounting: bool
    multi_turn: bool
    multiple_skills: bool
    #: Whether this adapter's egress traverses a capture point Bellwether controls.
    egress_observable: bool
    #: Whether Bellwether itself decides how skills are presented to the model. Where it
    #: does, activation and trigger measurements describe Bellwether's own prompt
    #: assembly, not the skill's behaviour in a real harness (§9.4).
    controls_skill_presentation: bool
    #: Telemetry and update hosts the harness contacts on its own behalf, for the
    #: egress classification of §10.5.0. Empty means the adapter phones nothing home.
    infrastructure_endpoints: tuple[str, ...] = ()

    @property
    def trigger_metrics_portable(self) -> bool:
        """False where trigger-derived metrics must carry ``harness-specific: not portable``.

        Wired here, at the adapter boundary, so the metrics layer derives the label from
        a declaration rather than from knowing adapter names (§9.4's critical
        limitation; the build plan says to wire this in now, not later).
        """
        return not self.controls_skill_presentation

    def as_record(self) -> dict[str, Any]:
        """The trace-embeddable form, with the derived label made explicit."""
        record = asdict(self)
        record["infrastructure_endpoints"] = list(self.infrastructure_endpoints)
        record["trigger_metrics_portable"] = self.trigger_metrics_portable
        return record


@dataclass(frozen=True)
class RunLimits:
    """Bounds on one run, enforced by the adapter (§9.2, §12.7).

    Hitting ``max_turns`` or ``max_tool_calls`` or the wall clock is a *timeout*-shaped
    outcome — something the skill did. Hitting ``max_total_tokens`` is
    ``budget_exceeded`` — an operator limit, detected at a turn boundary — and is
    ``not_evaluable`` rather than a failure (§12.7).
    """

    max_turns: int = 32
    max_tool_calls: int = 128
    wall_seconds: float = 600.0
    max_total_tokens: int = 1_000_000


@runtime_checkable
class HarnessAdapter(Protocol):
    """What every harness adapter must provide (§9.4).

    §9.4 sketches ``prepare(session, skill, extra_skills)`` with types that belong to
    the orchestrator, which does not exist until WP-11. Until it does, preparation is
    each adapter's constructor and this protocol pins down the two things every
    consumer relies on today: the event stream and the capabilities declaration.
    """

    name: str

    def version(self) -> str: ...

    def capabilities(self) -> HarnessCapabilities: ...

    def run(self, prompt: str, *, model_id: str, limits: RunLimits) -> Iterator[RawHarnessEvent]:
        """Execute one run, yielding events as they happen.

        A generator rather than a list so the caller can write each event to the trace
        as it is observed — a run killed mid-way must leave everything up to that point
        (§11.1).
        """
        ...
