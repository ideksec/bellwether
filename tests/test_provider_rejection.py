"""A provider refusal is infrastructure on both harnesses (§13.2, live run on PR #91).

The first labelled run on PR #91 used a key the provider refused (HTTP 400, "not scoped to a
workspace"). The two harnesses reported the same refusal as two different things:

- ``api-loop`` makes the model call itself; the non-200 raised and ``bellwether run`` exited 3,
  infrastructure — correct;
- ``claude-code`` lets the CLI make the call, and the CLI reports the status on its result line
  (``api_error_status``). The adapter records that as a ``harness_error``, which §12.7 scores a
  *fail* — so the verdict read ``not_ready``, "consistently failing", functional 0/6, with
  "6/6 runs evaluable". The operator's key was blamed on the skill.

The result line below is the shape the real CLI emitted in every one of those six runs (read
back from the uploaded evidence). The executor now asks
:func:`~bellwether.trace.provider_rejection_from_events` of every run and stops the evaluation
the way ``api-loop`` does; the container half of that wiring is exercised against the real CLI
in ``tests/test_execution_claude_code_docker.py`` (CI-only).
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from bellwether.harness import ClaudeCodeAdapter, RawHarnessEvent, RunLimits, ScriptedLaunch
from bellwether.trace import exit_reason_from_events, provider_rejection_from_events

_START = dt.datetime(2026, 9, 23, 21, 54, tzinfo=dt.UTC)

#: The real CLI's result line on a provider refusal: `subtype` is "success", `is_error` is true,
#: and the status rides in `api_error_status`.
_REFUSED = json.dumps(
    {
        "type": "result",
        "subtype": "success",
        "is_error": True,
        "api_error_status": 400,
        "num_turns": 1,
        "result": (
            "API Error: 400 This API key is not scoped to a workspace, so this request must "
            "include the anthropic-workspace-id header"
        ),
        "session_id": "s",
        "permission_denials": [],
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }
)


def _clock():  # type: ignore[no-untyped-def]
    state = {"tick": 0}

    def clock() -> dt.datetime:
        state["tick"] += 1
        return _START + dt.timedelta(milliseconds=state["tick"])

    return clock


def _events(*lines: str) -> list[RawHarnessEvent]:
    adapter = ClaudeCodeAdapter(ScriptedLaunch(list(lines)), clock=_clock())
    return list(adapter.run("p", model_id="m", limits=RunLimits()))


def test_the_real_cli_refusal_shape_is_named_a_provider_rejection() -> None:
    events = _events(_REFUSED)
    # Still a harness_error on the trace — the event is recorded as it happened...
    assert exit_reason_from_events(events) == "harness_error"
    # ...but it is recognised as the provider's refusal, with the status and the reason.
    rejection = provider_rejection_from_events(events)
    assert rejection is not None
    assert "HTTP 400" in str(rejection)
    assert "not scoped to a workspace" in str(rejection)
    # A refusal is final: §13.2 retries rate limits and server errors, not a rejected key.
    assert rejection.retryable is False


def test_a_rate_limit_or_overload_is_retryable() -> None:
    for status in (429, 500, 529):
        refused = _REFUSED.replace('"api_error_status": 400', f'"api_error_status": {status}')
        rejection = provider_rejection_from_events(_events(refused))
        assert rejection is not None and rejection.retryable, status


def test_a_run_that_completed_is_not_a_rejection() -> None:
    ok = json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "num_turns": 1,
            "result": "done",
            "session_id": "s",
            "permission_denials": [],
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
    )
    assert provider_rejection_from_events(_events(ok)) is None


def test_error_text_alone_is_not_a_rejection() -> None:
    """Only the numeric status the harness reported counts. A model can be induced to write
    "API Error: 400" into its own output; that must stay the skill's failure, not become the
    operator's infrastructure error."""
    echoed = RawHarnessEvent(
        ts=_START,
        kind="harness_error",
        turn=1,
        data={"exit_reason": "harness_error", "detail": "API Error: 400 not scoped"},
    )
    assert provider_rejection_from_events([echoed]) is None
    boolean = RawHarnessEvent(
        ts=_START,
        kind="harness_error",
        turn=1,
        data={"exit_reason": "harness_error", "api_error_status": True},
    )
    assert provider_rejection_from_events([boolean]) is None


def test_the_executor_asks_the_question_of_every_run() -> None:
    """Test the wiring, not only the helper: the executor raises on a rejection, inside the
    ``try`` whose ``finally`` tears the sandbox and sidecars down. Pinned on the source because
    the executor needs a Docker daemon; the CI container test drives it against the real CLI."""
    source = (
        Path(__file__).resolve().parents[1] / "src" / "bellwether" / "cli" / "execution.py"
    ).read_text(encoding="utf-8")
    call = source.index("rejection = provider_rejection_from_events(events)")
    assert "raise rejection" in source[call : call + 200]
    # Before the planes are read, and inside the try that the teardown `finally` closes.
    assert call < source.index("observed_at = dt.datetime.now(dt.UTC)")
    assert source.rfind("try:", 0, call) > source.rfind("finally:", 0, call)
