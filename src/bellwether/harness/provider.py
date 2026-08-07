"""The model-client seam and alias resolution (§9.5).

The agent loop speaks to a :class:`ModelClient`, never to a vendor SDK. Two things
follow. First, alias resolution: scenarios and policy name ``frontier`` / ``mid`` /
``small``, and those resolve through the user's own configuration — a model identifier
literal anywhere in this package is a bug. Second, offline testability: the
:class:`ScriptedClient` plays a deterministic transcript, which is what makes the
api-loop adapter the golden-trace generator §24 requires — the whole analysis pipeline
must be testable by contributors without API keys.

The live HTTP client is :mod:`bellwether.harness.live_client` (WP-13, once the recording
proxy existed to carry and observe egress — a client added before that would have run
unobserved, the exact condition §10.5.2 exists to prevent). This module is the seam and the
scripted client; that one is the real implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from bellwether.config.models.provider import ProviderConfig, is_placeholder_model_id
from bellwether.errors import BellwetherError

__all__ = [
    "ModelClient",
    "ModelRequest",
    "ModelTurn",
    "ScriptedClient",
    "ToolCallRequest",
    "ToolSpec",
    "TurnUsage",
    "resolve_model",
]


@dataclass(frozen=True)
class ToolSpec:
    """One tool offered to the model."""

    name: str
    description: str
    #: JSON Schema for the tool input, in the provider-neutral shape.
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCallRequest:
    """The model asked for a tool to run.

    ``id`` is the provider-assigned originating identifier. It is carried through the
    tool result and into the trace, because explicit correlation is the strong path for
    cross-plane attribution (§11.5).
    """

    id: str
    name: str
    input: dict[str, Any]


@dataclass(frozen=True)
class TurnUsage:
    """Token accounting for one turn, cache reads and writes separate (§9.3)."""

    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write: int = 0


@dataclass(frozen=True)
class ModelTurn:
    """What the model returned for one request."""

    text: str = ""
    tool_calls: tuple[ToolCallRequest, ...] = ()
    stop_reason: Literal["end_turn", "tool_use", "max_tokens", "other"] = "end_turn"
    usage: TurnUsage = field(default_factory=TurnUsage)
    #: What the provider said it served. Recorded next to what was asked for, because a
    #: silent model update is a primary cause of "the skill changed but the code
    #: didn't" (§9.3).
    model_id_reported: str | None = None


@dataclass(frozen=True)
class ModelRequest:
    """One request to the model: the loop's full conversational state."""

    model_id: str
    system: str
    #: Provider-neutral messages: ``{"role": ..., "content": [...]}`` dicts. Kept as
    #: data rather than classes because the loop builds them and the client consumes
    #: them within one package; the wire shape is the client's concern.
    messages: tuple[dict[str, Any], ...]
    tools: tuple[ToolSpec, ...] = ()


class ModelClient(Protocol):
    """What the agent loop needs from a provider."""

    def complete(self, request: ModelRequest) -> ModelTurn: ...


class ScriptedClient:
    """A model client that plays a fixed transcript, deterministically.

    Every request it receives is retained, so a test can assert not only what the loop
    did with the responses but exactly what it sent — the prompt-assembly half of the
    adapter is behaviour worth pinning too, since on ``api-loop`` it *is* the trigger
    surface (§9.4).
    """

    def __init__(self, turns: list[ModelTurn], *, model_id_reported: str | None = None) -> None:
        self._turns = list(turns)
        self._served = 0
        self._model_id_reported = model_id_reported
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelTurn:
        self.requests.append(request)
        if self._served >= len(self._turns):
            raise BellwetherError(
                f"the scripted transcript has {len(self._turns)} turn(s) and the loop "
                f"asked for turn {self._served + 1}; the script and the loop disagree "
                "about how this conversation ends"
            )
        turn = self._turns[self._served]
        self._served += 1
        if turn.model_id_reported is None and self._model_id_reported is not None:
            return ModelTurn(
                text=turn.text,
                tool_calls=turn.tool_calls,
                stop_reason=turn.stop_reason,
                usage=turn.usage,
                model_id_reported=self._model_id_reported,
            )
        return turn


def resolve_model(provider: ProviderConfig, alias: str, *, provider_name: str = "") -> str:
    """Resolve a model alias against a provider's configuration (§9.5).

    Refuses placeholders by name: a first run must fail with a sentence naming the
    alias and where to fill it in, not with a provider 404 mentioning a string the user
    never wrote.
    """
    label = f"provider '{provider_name}'" if provider_name else "the provider"
    if alias not in provider.models:
        known = ", ".join(sorted(provider.models)) or "none"
        raise BellwetherError(
            f"{label} defines no model alias '{alias}' (configured aliases: {known}); "
            "scenarios and policy refer to aliases, and aliases resolve through "
            ".bellwether/config.yaml"
        )
    model_id = provider.models[alias]
    if is_placeholder_model_id(model_id):
        raise BellwetherError(
            f"model alias '{alias}' on {label} still holds the shipped placeholder "
            f"({model_id!r}); fill in a real model identifier in .bellwether/config.yaml"
        )
    return model_id
