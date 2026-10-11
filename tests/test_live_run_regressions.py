"""Two defects the first paid run of the live-test skills disclosed (PR #102), pinned.

Neither was reachable by an existing test: one needs a shape-refused flow to reach the executor's
body-scan pairing, the other a caller whose stdin holds something worth stealing.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bellwether.capture.egress import EgressFlow
from bellwether.cli.execution import _body_hit_sources
from bellwether.sandbox import DockerBackend
from bellwether.trace import egress_actions, provider_endpoint_actions

_TS = "2026-10-11T12:44:00+00:00"


def _flows() -> list[EgressFlow]:
    model_call = EgressFlow(
        ts=_TS,
        method="POST",
        scheme="https",
        host="api.anthropic.com",
        port=443,
        path="/v1/messages?beta=true",
        egress_class="model_api",
        blocked=False,
    )
    refused = EgressFlow(
        ts=_TS,
        method="POST",
        scheme="https",
        host="api.anthropic.com",
        port=443,
        path="/v1/files",
        egress_class="model_api",
        blocked=True,
        block_reason="not a model call",
        shape_violation="path /v1/files is not a model endpoint",
    )
    return [model_call, refused]


def test_a_shape_refused_request_does_not_break_the_body_scan_pairing() -> None:
    """The executor paired every Plane D action with a flow by position — but Plane D also holds
    the provider-endpoint findings derived from the flows, so the first run with a shape refusal
    raised `zip() argument 2 is shorter than argument 1` on every repetition, before any trace was
    written (all three live-test skills on claude-code)."""
    flows = _flows()
    flow_actions = egress_actions(flows)
    findings = provider_endpoint_actions(flow_actions, start_seq=len(flow_actions))
    assert findings, "the refusal must still produce its §10.5.2 finding"
    plane_d = flow_actions + findings

    pairs = _body_hit_sources(flow_actions, flows)
    assert [action.seq for action, _ in pairs] == [a.seq for a in flow_actions]
    # What the executor used to do, kept here so the reason for the split is executable.
    with pytest.raises(ValueError, match="shorter"):
        list(zip(plane_d, (flow.canary_hits for flow in flows), strict=True))


def test_exec_in_never_hands_the_callers_stdin_to_the_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`docker exec --interactive` with `input=None` forwards the caller's stdin. In the live
    workflow that was the list of skills still to evaluate: the first skill's tool call read it,
    and every skill after the first went unevaluated (reproduced on a real container: the tool's
    `cat` printed the remaining skill names). With nothing to send, the exec gets an empty stdin."""
    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs, command=command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("bellwether.sandbox.docker.subprocess.run", fake_run)
    prepared = SimpleNamespace(
        identifiers=SimpleNamespace(workspace_root="/work/x", container_name="bw-x")
    )
    backend = DockerBackend(image="img")
    backend.exec_in(prepared, ["sh", "-c", "true"])  # type: ignore[arg-type]
    assert "--interactive" in seen["command"] and seen["input"] == ""
    backend.exec_in(prepared, ["cat"], stdin="given")  # type: ignore[arg-type]
    assert seen["input"] == "given"
