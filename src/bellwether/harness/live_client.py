"""The live model client — a real HTTP client behind the :class:`ModelClient` seam (§9.5, §9.3).

The agent loop speaks to a :class:`~bellwether.harness.ModelClient`; :class:`ScriptedClient` plays a
transcript for the corpus, and this is the other implementation — one that actually calls a provider.
For the ``api-loop`` adapter the loop runs on the *host* (its tools exec into the sandbox), so this
client runs host-side with the real key: the recording proxy observes the *sandbox's* egress, not the
harness's own model calls. The in-container agent of the ``claude-code`` adapter (WP-17) is the one
whose model calls route through the proxy with the scoped token.

The wire translation is kept as pure functions and the HTTP call behind a ``transport`` seam, so the
request shape, the response parsing, the auth headers, and the error mapping are all unit-tested
without a network or an API key — the same discipline the rest of the pipeline follows. The
``api-loop`` adapter already builds messages in the Anthropic content-block shape, so the Anthropic
client is a near-passthrough; an ``openai_compatible`` client needs a message-shape translation and
is a separate follow-on (see :func:`build_model_client`).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, NamedTuple

from bellwether.config.models.provider import ProviderConfig
from bellwether.errors import BellwetherError
from bellwether.harness.provider import (
    ModelClient,
    ModelRequest,
    ModelTurn,
    ToolCallRequest,
    TurnUsage,
)

__all__ = [
    "DEFAULT_ANTHROPIC_BASE_URL",
    "DEFAULT_ANTHROPIC_VERSION",
    "DEFAULT_MAX_TOKENS",
    "AnthropicClient",
    "HttpResponse",
    "HttpTransport",
    "anthropic_request_body",
    "build_model_client",
    "parse_anthropic_response",
]

#: The Anthropic API host, used when a provider of type ``anthropic`` sets no ``base_url``. This is
#: an *endpoint*, not a model identifier — the no-hard-coded-model rule (§9.5) is about model version
#: strings that go stale, which a stable API host is not.
DEFAULT_ANTHROPIC_BASE_URL = "https://api.anthropic.com"
#: The Anthropic API version header. Pinned, not floating: a silent version bump is exactly the kind
#: of environmental change §9.3 wants recorded rather than absorbed.
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
#: A required field on the Messages API. A ceiling, not a target — the loop stops when the model
#: stops; this only bounds a runaway single turn.
DEFAULT_MAX_TOKENS = 4096


class HttpResponse(NamedTuple):
    """The minimum of an HTTP response the client reads: status and raw body."""

    status: int
    body: bytes


#: The transport seam: ``(url, headers, body, timeout) -> HttpResponse``. Injected so the client is
#: tested with a fake and the real one is a thin urllib call.
HttpTransport = Callable[[str, Mapping[str, str], bytes, float], HttpResponse]

#: Anthropic ``stop_reason`` → the neutral :class:`ModelTurn` vocabulary. Anything unrecognised maps
#: to ``other`` rather than being dropped, so a new provider stop reason never reads as ``end_turn``.
_STOP_REASONS: dict[str, str] = {
    "end_turn": "end_turn",
    "tool_use": "tool_use",
    "max_tokens": "max_tokens",
    "stop_sequence": "other",
    "pause_turn": "other",
    "refusal": "other",
}


def anthropic_request_body(request: ModelRequest, *, max_tokens: int) -> dict[str, Any]:
    """The Messages API request body for one :class:`ModelRequest`.

    The loop already assembles messages in the Anthropic content-block shape, so they pass through;
    the client adds the model, the token ceiling, and — only when present — the system prompt and the
    tool list. An empty system string is omitted rather than sent as ``""``, which some versions reject.
    """
    body: dict[str, Any] = {
        "model": request.model_id,
        "max_tokens": max_tokens,
        "messages": [dict(message) for message in request.messages],
    }
    if request.system:
        body["system"] = request.system
    if request.tools:
        body["tools"] = [
            {"name": tool.name, "description": tool.description, "input_schema": tool.input_schema}
            for tool in request.tools
        ]
    return body


def parse_anthropic_response(payload: Mapping[str, Any]) -> ModelTurn:
    """Turn a Messages API response into a :class:`ModelTurn`.

    Text blocks are concatenated; ``tool_use`` blocks become :class:`ToolCallRequest`s carrying the
    provider-assigned id (the strong cross-plane correlation key, §11.5). ``usage`` keeps cache reads
    and writes separate (§9.3), and ``model`` is recorded as what the provider *said it served*, so a
    silent model swap is visible rather than assumed equal to what was requested.
    """
    text_parts: list[str] = []
    tool_calls: list[ToolCallRequest] = []
    for block in payload.get("content", []):
        kind = block.get("type")
        if kind == "text":
            text_parts.append(block.get("text", ""))
        elif kind == "tool_use":
            tool_calls.append(
                ToolCallRequest(
                    id=str(block.get("id", "")),
                    name=str(block.get("name", "")),
                    input=dict(block.get("input", {})),
                )
            )
    usage = payload.get("usage", {})
    stop = payload.get("stop_reason")
    return ModelTurn(
        text="".join(text_parts),
        tool_calls=tuple(tool_calls),
        stop_reason=_STOP_REASONS.get(stop or "", "other"),  # type: ignore[arg-type]
        usage=TurnUsage(
            input=int(usage.get("input_tokens", 0)),
            output=int(usage.get("output_tokens", 0)),
            cache_read=int(usage.get("cache_read_input_tokens", 0)),
            cache_write=int(usage.get("cache_creation_input_tokens", 0)),
        ),
        model_id_reported=payload.get("model"),
    )


def _urllib_post(url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> HttpResponse:
    """The default transport: a plain urllib POST. An HTTP error status is *returned*, not raised —
    the client maps status to a Bellwether error with context, so a 429 or 401 reads clearly."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return HttpResponse(int(response.status), response.read())
    except urllib.error.HTTPError as error:
        return HttpResponse(int(error.code), error.read())


@dataclass
class AnthropicClient:
    """A :class:`ModelClient` backed by the Anthropic Messages API.

    ``api_key`` is the real credential, supplied by the caller (resolved from the provider's
    ``api_key_env`` and the host environment) — this module never reads the environment itself, so
    the credential path stays explicit and the client stays testable.
    """

    api_key: str
    base_url: str = DEFAULT_ANTHROPIC_BASE_URL
    anthropic_version: str = DEFAULT_ANTHROPIC_VERSION
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: float = 120.0
    transport: HttpTransport = _urllib_post

    def complete(self, request: ModelRequest) -> ModelTurn:
        body = json.dumps(anthropic_request_body(request, max_tokens=self.max_tokens)).encode(
            "utf-8"
        )
        headers = {
            "content-type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
        }
        url = self.base_url.rstrip("/") + "/v1/messages"
        response = self.transport(url, headers, body, self.timeout)
        if response.status != 200:
            snippet = response.body[:500].decode("utf-8", "replace")
            raise BellwetherError(
                f"model API returned HTTP {response.status} from {url}: {snippet}"
            )
        try:
            payload = json.loads(response.body)
        except json.JSONDecodeError as error:
            raise BellwetherError(
                f"model API returned a non-JSON body from {url}: {error}"
            ) from error
        return parse_anthropic_response(payload)


def build_model_client(
    provider: ProviderConfig, *, api_key: str, transport: HttpTransport | None = None
) -> ModelClient:
    """Construct the live client for a configured provider (§9.5).

    ``anthropic`` is built; ``openai_compatible`` raises with a clear reason, because its Chat
    Completions shape needs a message-shape translation the loop's Anthropic-shaped messages do not
    carry — that client is a distinct follow-on, not a config toggle.
    """
    if provider.type == "anthropic":
        base_url = provider.base_url or DEFAULT_ANTHROPIC_BASE_URL
        client = AnthropicClient(api_key=api_key, base_url=base_url)
        if transport is not None:
            client.transport = transport
        return client
    raise BellwetherError(
        f"provider type {provider.type!r} has no live client yet; only 'anthropic' is implemented. "
        "An 'openai_compatible' client needs the Chat Completions message translation and lands "
        "separately."
    )
