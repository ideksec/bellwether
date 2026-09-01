"""Harness adapters: the agent runtimes under which a skill executes (§9.4, §9.5).

Responsibility
    The ``HarnessAdapter`` protocol and its implementations — ``api-loop`` (the offline
    reference and golden-trace generator) and ``claude-code`` (a real CLI, needed
    because trigger and coexistence metrics are meaningless on ``api-loop``). Each
    adapter declares ``HarnessCapabilities``, including ``egress_observable`` and
    ``infrastructure_endpoints``.

MUST NOT
    Know about assertions. An adapter reports what happened; it does not judge it.

Built by WP-6 and WP-17. Every trigger-derived metric from ``api-loop`` carries
``harness-specific: not portable`` — wire that label in when the adapter lands, not
afterwards. Never hard-code a model identifier: aliases resolve through config.
"""

from __future__ import annotations

from bellwether.harness.api_loop import ApiLoopAdapter, OfferedSkill
from bellwether.harness.claude_code import (
    CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS,
    CLAUDE_CODE_TELEMETRY_ENV,
    ClaudeCodeAdapter,
    HookReconciliation,
    LaunchedProcess,
    Launcher,
    LaunchResult,
    ScriptedLaunch,
    SessionFacts,
    claude_code_argv,
    claude_code_environment,
    hook_settings,
)
from bellwether.harness.live_client import (
    AnthropicClient,
    HttpResponse,
    HttpTransport,
    anthropic_request_body,
    build_model_client,
    parse_anthropic_response,
)
from bellwether.harness.protocol import (
    HarnessAdapter,
    HarnessCapabilities,
    RawHarnessEvent,
    RunLimits,
)
from bellwether.harness.provider import (
    ModelClient,
    ModelRequest,
    ModelTurn,
    ScriptedClient,
    ToolCallRequest,
    ToolSpec,
    TurnUsage,
    resolve_model,
)
from bellwether.harness.tools import ExecResult, SandboxExec, SandboxToolset, ToolOutcome

__all__ = [
    "CLAUDE_CODE_INFRASTRUCTURE_ENDPOINTS",
    "CLAUDE_CODE_TELEMETRY_ENV",
    "AnthropicClient",
    "ApiLoopAdapter",
    "ClaudeCodeAdapter",
    "ExecResult",
    "HarnessAdapter",
    "HarnessCapabilities",
    "HookReconciliation",
    "HttpResponse",
    "HttpTransport",
    "LaunchResult",
    "LaunchedProcess",
    "Launcher",
    "ModelClient",
    "ModelRequest",
    "ModelTurn",
    "OfferedSkill",
    "RawHarnessEvent",
    "RunLimits",
    "SandboxExec",
    "SandboxToolset",
    "ScriptedClient",
    "ScriptedLaunch",
    "SessionFacts",
    "ToolCallRequest",
    "ToolOutcome",
    "ToolSpec",
    "TurnUsage",
    "anthropic_request_body",
    "build_model_client",
    "claude_code_argv",
    "claude_code_environment",
    "hook_settings",
    "parse_anthropic_response",
    "resolve_model",
]
