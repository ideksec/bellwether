"""WP-13: the live model client, tested without a network or an API key (§9.5, §9.3).

The wire translation and the transport are seamed apart, so the request shape, the response parsing,
the auth headers, and the error mapping are all pinned offline. The client runs host-side for the
``api-loop`` adapter; the credential is passed in, never read from the environment here, so the test
holds the whole credential path in view.
"""

from __future__ import annotations

import json

import pytest

from bellwether.config.models.provider import ProviderConfig
from bellwether.errors import BellwetherError
from bellwether.harness import (
    AnthropicClient,
    HttpResponse,
    ModelRequest,
    ToolSpec,
    anthropic_request_body,
    build_model_client,
    parse_anthropic_response,
)

_REQUEST = ModelRequest(
    model_id="a-configured-model-id",
    system="be helpful",
    messages=({"role": "user", "content": [{"type": "text", "text": "hi"}]},),
    tools=(ToolSpec(name="read", description="read a file", input_schema={"type": "object"}),),
)


# ---------------------------------------------------------------------------
# request translation
# ---------------------------------------------------------------------------


def test_the_request_body_carries_model_messages_system_and_tools() -> None:
    body = anthropic_request_body(_REQUEST, max_tokens=1024)
    assert body["model"] == "a-configured-model-id"
    assert body["max_tokens"] == 1024
    assert body["messages"] == [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
    assert body["system"] == "be helpful"
    assert body["tools"] == [
        {"name": "read", "description": "read a file", "input_schema": {"type": "object"}}
    ]


def test_an_empty_system_prompt_is_omitted_not_sent_blank() -> None:
    """Some API versions reject ``system: ""``; absence is the safe encoding of 'no system'."""
    request = ModelRequest(model_id="m", system="", messages=())
    body = anthropic_request_body(request, max_tokens=8)
    assert "system" not in body
    assert "tools" not in body  # likewise for no tools


# ---------------------------------------------------------------------------
# response parsing
# ---------------------------------------------------------------------------


def test_text_and_tool_use_blocks_become_a_model_turn() -> None:
    payload = {
        "model": "served-model-id",
        "stop_reason": "tool_use",
        "content": [
            {"type": "text", "text": "let me look"},
            {"type": "tool_use", "id": "tu_1", "name": "read", "input": {"path": "a.py"}},
        ],
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_input_tokens": 3,
            "cache_creation_input_tokens": 2,
        },
    }
    turn = parse_anthropic_response(payload)
    assert turn.text == "let me look"
    assert turn.stop_reason == "tool_use"
    assert turn.model_id_reported == "served-model-id"
    assert len(turn.tool_calls) == 1
    call = turn.tool_calls[0]
    assert (call.id, call.name, call.input) == ("tu_1", "read", {"path": "a.py"})
    assert (turn.usage.input, turn.usage.output) == (10, 5)
    assert (turn.usage.cache_read, turn.usage.cache_write) == (3, 2)


def test_multiple_text_blocks_concatenate() -> None:
    payload = {"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}
    assert parse_anthropic_response(payload).text == "ab"


def test_an_unknown_stop_reason_maps_to_other_not_end_turn() -> None:
    """A new provider stop reason must never be silently read as a clean end of turn."""
    assert parse_anthropic_response({"stop_reason": "something_new"}).stop_reason == "other"
    assert parse_anthropic_response({"stop_reason": "end_turn"}).stop_reason == "end_turn"


# ---------------------------------------------------------------------------
# the client: auth, url, transport, errors
# ---------------------------------------------------------------------------


class _RecordingTransport:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.url = ""
        self.headers: dict[str, str] = {}
        self.body = b""

    def __call__(self, url, headers, body, timeout):  # type: ignore[no-untyped-def]
        self.url = url
        self.headers = dict(headers)
        self.body = body
        return self.response


def _ok(payload: dict[str, object]) -> HttpResponse:
    return HttpResponse(200, json.dumps(payload).encode("utf-8"))


def test_complete_posts_to_v1_messages_with_the_auth_headers() -> None:
    transport = _RecordingTransport(_ok({"content": [{"type": "text", "text": "hello"}]}))
    client = AnthropicClient(
        api_key="sk-secret", base_url="https://api.example.test", transport=transport
    )

    turn = client.complete(_REQUEST)

    assert turn.text == "hello"
    assert transport.url == "https://api.example.test/v1/messages"
    assert transport.headers["x-api-key"] == "sk-secret"
    assert transport.headers["anthropic-version"]
    assert transport.headers["content-type"] == "application/json"
    # The body is the translated request.
    assert json.loads(transport.body)["model"] == "a-configured-model-id"


def test_a_trailing_slash_on_the_base_url_does_not_double() -> None:
    transport = _RecordingTransport(_ok({"content": []}))
    AnthropicClient(api_key="k", base_url="https://h.test/", transport=transport).complete(_REQUEST)
    assert transport.url == "https://h.test/v1/messages"


def test_a_non_200_is_a_bellwether_error_naming_the_status() -> None:
    transport = _RecordingTransport(HttpResponse(401, b'{"error": "bad key"}'))
    client = AnthropicClient(api_key="k", transport=transport)
    with pytest.raises(BellwetherError, match="HTTP 401"):
        client.complete(_REQUEST)


def test_a_non_json_body_is_a_clear_error() -> None:
    transport = _RecordingTransport(HttpResponse(200, b"<html>gateway</html>"))
    client = AnthropicClient(api_key="k", transport=transport)
    with pytest.raises(BellwetherError, match="non-JSON"):
        client.complete(_REQUEST)


# ---------------------------------------------------------------------------
# the factory
# ---------------------------------------------------------------------------


def test_build_model_client_makes_an_anthropic_client_using_the_configured_base_url() -> None:
    transport = _RecordingTransport(_ok({"content": []}))
    provider = ProviderConfig(
        type="anthropic", base_url="https://proxy.test", models={"frontier": "m"}
    )
    client = build_model_client(provider, api_key="k", transport=transport)
    client.complete(_REQUEST)
    assert transport.url == "https://proxy.test/v1/messages"


def test_build_model_client_defaults_the_anthropic_host_when_unset() -> None:
    provider = ProviderConfig(type="anthropic", models={"frontier": "m"})
    client = build_model_client(provider, api_key="k")
    assert isinstance(client, AnthropicClient)
    assert client.base_url.endswith("anthropic.com")


def test_openai_compatible_has_no_live_client_yet_and_says_so() -> None:
    provider = ProviderConfig(
        type="openai_compatible", base_url="https://x.test", models={"frontier": "m"}
    )
    with pytest.raises(BellwetherError, match="openai_compatible"):
        build_model_client(provider, api_key="k")
