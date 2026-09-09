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
    OpenAiCompatibleClient,
    ToolSpec,
    anthropic_request_body,
    build_model_client,
    openai_request_body,
    parse_anthropic_response,
    parse_openai_response,
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


def test_the_repr_does_not_leak_the_api_key() -> None:
    """BW-31: the client holds the *real* credential, so its repr must not expose it — an
    accidental repr(client) in a log line or traceback would otherwise print the key."""
    client = AnthropicClient(api_key="sk-super-secret-value")
    assert "sk-super-secret-value" not in repr(client)
    # The credential is still usable; only its display is redacted.
    assert client.api_key == "sk-super-secret-value"


# ---------------------------------------------------------------------------
# the factory
# ---------------------------------------------------------------------------


def test_build_model_client_accepts_the_trusted_anthropic_host() -> None:
    transport = _RecordingTransport(_ok({"content": []}))
    provider = ProviderConfig(
        type="anthropic", base_url="https://api.anthropic.com", models={"frontier": "m"}
    )
    client = build_model_client(provider, api_key="k", transport=transport)
    client.complete(_REQUEST)
    assert transport.url == "https://api.anthropic.com/v1/messages"


def test_build_model_client_defaults_the_anthropic_host_when_unset() -> None:
    provider = ProviderConfig(type="anthropic", models={"frontier": "m"})
    client = build_model_client(provider, api_key="k")
    assert isinstance(client, AnthropicClient)
    assert client.base_url.endswith("anthropic.com")


def test_build_model_client_refuses_an_untrusted_base_url() -> None:
    """§3.3: the host-side client sends the *real* key, so an attacker-controlled base_url in a
    checked-in config would exfiltrate it. The endpoint is pinned, not trusted from config."""
    provider = ProviderConfig(
        type="anthropic", base_url="https://evil.example.com", models={"frontier": "m"}
    )
    with pytest.raises(BellwetherError, match="real API key"):
        build_model_client(provider, api_key="k")


def test_build_model_client_refuses_a_lookalike_host() -> None:
    provider = ProviderConfig(
        type="anthropic", base_url="https://api.anthropic.com.evil.test", models={"frontier": "m"}
    )
    with pytest.raises(BellwetherError, match="real API key"):
        build_model_client(provider, api_key="k")


def test_build_model_client_refuses_a_cleartext_endpoint() -> None:
    """Even the trusted host over http would leak the key on the wire."""
    provider = ProviderConfig(
        type="anthropic", base_url="http://api.anthropic.com", models={"frontier": "m"}
    )
    with pytest.raises(BellwetherError, match="real API key"):
        build_model_client(provider, api_key="k")


def test_build_model_client_builds_an_openai_client_for_the_canonical_host() -> None:
    provider = ProviderConfig(
        type="openai_compatible", base_url="https://api.openai.com/v1", models={"frontier": "m"}
    )
    client = build_model_client(provider, api_key="k")
    assert isinstance(client, OpenAiCompatibleClient)


def test_build_model_client_refuses_an_untrusted_openai_base_url() -> None:
    """§3.3: the host-side client sends the real key, and openai_compatible is operator-chosen — a
    base_url edited into a checked-in config would exfiltrate the key, so a host that is neither the
    canonical endpoint nor named out of band is refused."""
    provider = ProviderConfig(
        type="openai_compatible", base_url="https://evil.example.com/v1", models={"frontier": "m"}
    )
    with pytest.raises(BellwetherError, match="real API key"):
        build_model_client(provider, api_key="k")


def test_build_model_client_refuses_a_cleartext_openai_endpoint() -> None:
    provider = ProviderConfig(
        type="openai_compatible", base_url="http://api.openai.com/v1", models={"frontier": "m"}
    )
    with pytest.raises(BellwetherError, match="real API key"):
        build_model_client(provider, api_key="k")


def test_build_model_client_refuses_an_openai_lookalike_host() -> None:
    provider = ProviderConfig(
        type="openai_compatible", base_url="https://api.openai.com.evil.test", models={"f": "m"}
    )
    with pytest.raises(BellwetherError, match="real API key"):
        build_model_client(provider, api_key="k")


def test_build_model_client_accepts_a_gateway_host_named_out_of_band() -> None:
    """A custom gateway is trusted only when named in the env-sourced allowlist the cli threads in —
    trusted config outside the checkout, which a tampered config.yaml cannot reach."""
    provider = ProviderConfig(
        type="openai_compatible", base_url="https://gw.corp.test/v1", models={"frontier": "m"}
    )
    with pytest.raises(BellwetherError, match="real API key"):
        build_model_client(provider, api_key="k")  # not trusted without the out-of-band host
    client = build_model_client(
        provider, api_key="k", trusted_openai_hosts=frozenset({"gw.corp.test"})
    )
    assert isinstance(client, OpenAiCompatibleClient)


# ---------------------------------------------------------------------------
# openai_compatible — request translation, response parsing, the client
# ---------------------------------------------------------------------------

_OPENAI_CONVERSATION = ModelRequest(
    model_id="gpt-x",
    system="be helpful",
    messages=(
        {"role": "user", "content": [{"type": "text", "text": "read a.py"}]},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "ok"},
                {"type": "tool_use", "id": "tu1", "name": "read", "input": {"path": "a.py"}},
            ],
        },
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "tu1", "content": "data"}],
        },
    ),
    tools=(ToolSpec(name="read", description="read a file", input_schema={"type": "object"}),),
)


def test_openai_translation_maps_system_tool_use_and_tool_result() -> None:
    """The Anthropic content-block shape the loop builds becomes the Chat Completions array: a
    leading system message, tool_use → assistant tool_calls with JSON-string arguments, tool_result
    → a tool message keyed by the same id (§11.5), and tools → the function wrapper."""
    body = openai_request_body(_OPENAI_CONVERSATION, max_tokens=256)
    assert body["model"] == "gpt-x"
    assert body["max_tokens"] == 256
    messages = body["messages"]
    assert messages[0] == {"role": "system", "content": "be helpful"}
    assert messages[1] == {"role": "user", "content": "read a.py"}
    assistant = messages[2]
    assert assistant["role"] == "assistant"
    assert assistant["content"] == "ok"
    call = assistant["tool_calls"][0]
    assert call["id"] == "tu1"
    assert call["type"] == "function"
    assert call["function"]["name"] == "read"
    assert json.loads(call["function"]["arguments"]) == {"path": "a.py"}
    assert messages[3] == {"role": "tool", "tool_call_id": "tu1", "content": "data"}
    assert body["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "read",
                "description": "read a file",
                "parameters": {"type": "object"},
            },
        }
    ]


def test_openai_assistant_content_is_null_when_only_tool_calls() -> None:
    """OpenAI accepts a null content on an assistant turn that is purely tool calls; the loop's
    text-free assistant block must not become an empty-string content."""
    request = ModelRequest(
        model_id="m",
        system="",
        messages=(
            {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t", "name": "read", "input": {}}],
            },
        ),
    )
    body = openai_request_body(request, max_tokens=8)
    assert "system" not in {m["role"] for m in body["messages"]}  # empty system omitted
    assert "tools" not in body
    assert body["messages"][0]["content"] is None


def test_parse_openai_response_reads_text_tool_calls_usage_and_model() -> None:
    payload = {
        "model": "gpt-x-served",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "write", "arguments": '{"path": "b.py"}'},
                        }
                    ],
                },
            }
        ],
        "usage": {
            "prompt_tokens": 11,
            "completion_tokens": 7,
            "prompt_tokens_details": {"cached_tokens": 4},
        },
    }
    turn = parse_openai_response(payload)
    assert turn.text == ""  # null content is empty, not the string "None"
    assert turn.stop_reason == "tool_use"
    assert turn.model_id_reported == "gpt-x-served"
    assert (turn.tool_calls[0].id, turn.tool_calls[0].name) == ("call_1", "write")
    assert turn.tool_calls[0].input == {"path": "b.py"}
    assert (turn.usage.input, turn.usage.output) == (11, 7)
    assert (turn.usage.cache_read, turn.usage.cache_write) == (4, 0)


def test_openai_finish_reasons_map_and_unknown_becomes_other() -> None:
    def stop(reason: str) -> str:
        return parse_openai_response(
            {"choices": [{"finish_reason": reason, "message": {"content": "x"}}]}
        ).stop_reason

    assert stop("stop") == "end_turn"
    assert stop("length") == "max_tokens"
    assert stop("content_filter") == "other"
    assert stop("something_new") == "other"


def test_openai_empty_string_arguments_decode_to_an_empty_object() -> None:
    payload = {
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "tool_calls": [{"id": "c", "function": {"name": "list", "arguments": ""}}]
                },
            }
        ]
    }
    assert parse_openai_response(payload).tool_calls[0].input == {}


def test_openai_invalid_tool_arguments_are_a_controlled_error() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [{"id": "c", "function": {"name": "x", "arguments": "{not json"}}]
                }
            }
        ]
    }
    with pytest.raises(BellwetherError, match="not valid JSON"):
        parse_openai_response(payload)


def test_openai_empty_choices_is_a_controlled_error() -> None:
    with pytest.raises(BellwetherError, match="choices"):
        parse_openai_response({"choices": []})


def test_openai_client_posts_to_chat_completions_with_bearer_auth() -> None:
    transport = _RecordingTransport(
        _ok({"choices": [{"finish_reason": "stop", "message": {"content": "hi"}}]})
    )
    client = OpenAiCompatibleClient(
        api_key="sk-secret", base_url="https://api.openai.com/v1", transport=transport
    )
    turn = client.complete(_OPENAI_CONVERSATION)
    assert turn.text == "hi"
    assert transport.url == "https://api.openai.com/v1/chat/completions"
    assert transport.headers["authorization"] == "Bearer sk-secret"
    assert transport.headers["content-type"] == "application/json"


def test_openai_client_maps_a_non_200_and_a_non_json_body() -> None:
    err = OpenAiCompatibleClient(
        api_key="k",
        base_url="https://h/v1",
        transport=_RecordingTransport(HttpResponse(429, b'{"e":"rate"}')),
    )
    with pytest.raises(BellwetherError, match="HTTP 429"):
        err.complete(_OPENAI_CONVERSATION)
    html = OpenAiCompatibleClient(
        api_key="k",
        base_url="https://h/v1",
        transport=_RecordingTransport(HttpResponse(200, b"<html>")),
    )
    with pytest.raises(BellwetherError, match="non-JSON"):
        html.complete(_OPENAI_CONVERSATION)


def test_openai_client_repr_does_not_leak_the_key() -> None:
    client = OpenAiCompatibleClient(api_key="sk-super-secret-value", base_url="https://h/v1")
    assert "sk-super-secret-value" not in repr(client)
    assert client.api_key == "sk-super-secret-value"


# ---------------------------------------------------------------------------
# response validation — malformed bodies become controlled errors
# ---------------------------------------------------------------------------


def test_content_that_is_not_a_list_is_a_controlled_error() -> None:
    with pytest.raises(BellwetherError, match="content"):
        parse_anthropic_response({"content": "surprise"})


def test_a_non_object_content_block_is_a_controlled_error() -> None:
    with pytest.raises(BellwetherError, match="not an object"):
        parse_anthropic_response({"content": ["just a string"]})


def test_a_non_numeric_token_count_is_a_controlled_error() -> None:
    with pytest.raises(BellwetherError, match="not a number"):
        parse_anthropic_response({"content": [], "usage": {"input_tokens": "lots"}})


def test_a_non_object_tool_input_is_a_controlled_error() -> None:
    with pytest.raises(BellwetherError, match="input"):
        parse_anthropic_response(
            {"content": [{"type": "tool_use", "id": "t", "name": "read", "input": "not-an-object"}]}
        )
