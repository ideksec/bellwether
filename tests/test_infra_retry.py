"""§13.2 retries: `execution.retry_on_infra_error` is read, and only for transient causes.

The setting shipped in every config (default 2) and nothing read it: a provider 529 or a dropped
connection stopped the whole evaluation on the first try, and the knob an operator turned did
nothing — the "accepted and inert" control CLAUDE.md names as a defect class. It now drives a retry
loop in :func:`drive_evaluation`, where it is harness-agnostic and testable offline:

- only an :class:`InfrastructureError` marked ``retryable`` is retried (rate limit, overload, 5xx,
  a connection that never answered); a refusal such as the rejected key on PR #91 is final;
- the retry keeps the repetition and records ``attempt`` / ``retry_of`` (§13.2), with backoff;
- a repetition that exhausts its budget stops the evaluation as infrastructure.
"""

from __future__ import annotations

import urllib.error
from pathlib import Path

import pytest

from bellwether.cli.orchestrator import RunPlan, TargetInfo, drive_evaluation, plan_matrix
from bellwether.errors import InfrastructureError, transient_http_status
from bellwether.harness.live_client import AnthropicClient, HttpResponse
from tests.test_driver import _executed_run, _firstlight_profile, _scenario

_TARGET = TargetInfo("api-loop", "p", "frontier")


class _FlakyExecutor:
    """Fails the first ``failures`` calls for repetition 1 with ``error``, then behaves."""

    def __init__(self, tmp_path: Path, error: InfrastructureError, failures: int) -> None:
        self.tmp_path = tmp_path
        self.error = error
        self.failures = failures
        self.plans: list[RunPlan] = []

    def execute(self, plan: RunPlan):  # type: ignore[no-untyped-def]
        self.plans.append(plan)
        if plan.repetition == 1 and self.failures > 0:
            self.failures -= 1
            raise self.error
        return _executed_run(plan, self.tmp_path, len(self.plans))


def _plans() -> list[RunPlan]:
    return plan_matrix([_scenario("alpha")], [_TARGET], repetitions=6)


def test_a_transient_error_is_retried_and_the_attempt_is_recorded(tmp_path: Path) -> None:
    executor = _FlakyExecutor(tmp_path, InfrastructureError("HTTP 529", retryable=True), 2)
    slept: list[float] = []
    notes: list[str] = []
    readings = drive_evaluation(
        _plans(),
        executor,
        profile=_firstlight_profile(),
        retry_on_infra_error=2,
        sleep=slept.append,
        on_retry=notes.append,
    )
    assert len(readings) == 1 and len(readings[0].runs) == 6
    first = [p for p in executor.plans if p.repetition == 1]
    assert [p.attempt for p in first] == [1, 2, 3]
    assert first[-1].run_id.endswith("-001-attempt3")
    assert first[-1].first_run_id.endswith("-001")
    assert slept == [2.0, 4.0]
    assert len(notes) == 2 and "HTTP 529" in notes[0] and "§13.2" in notes[0]


def test_a_refusal_is_never_retried(tmp_path: Path) -> None:
    """The PR #91 case: a rejected key answers the same way every time."""
    refusal = InfrastructureError("HTTP 400 not scoped to a workspace", retryable=False)
    executor = _FlakyExecutor(tmp_path, refusal, 5)
    with pytest.raises(InfrastructureError, match="HTTP 400"):
        drive_evaluation(
            _plans(), executor, profile=_firstlight_profile(), retry_on_infra_error=2, sleep=print
        )
    assert len(executor.plans) == 1


def test_an_exhausted_budget_stops_the_evaluation(tmp_path: Path) -> None:
    executor = _FlakyExecutor(tmp_path, InfrastructureError("HTTP 503", retryable=True), 9)
    with pytest.raises(InfrastructureError, match="still failing after 3 attempt"):
        drive_evaluation(
            _plans(),
            executor,
            profile=_firstlight_profile(),
            retry_on_infra_error=2,
            sleep=lambda _s: None,
        )
    assert [p.attempt for p in executor.plans] == [1, 2, 3]


def test_a_zero_budget_does_not_retry(tmp_path: Path) -> None:
    executor = _FlakyExecutor(tmp_path, InfrastructureError("HTTP 503", retryable=True), 1)
    with pytest.raises(InfrastructureError):
        drive_evaluation(_plans(), executor, profile=_firstlight_profile(), sleep=print)
    assert len(executor.plans) == 1


def test_only_transient_statuses_are_retryable() -> None:
    assert all(transient_http_status(s) for s in (429, 500, 502, 503, 529))
    assert not any(transient_http_status(s) for s in (400, 401, 403, 404, 413, 422))


def _client(response: HttpResponse | Exception) -> AnthropicClient:
    def transport(_url, _headers, _body, _timeout):  # type: ignore[no-untyped-def]
        if isinstance(response, Exception):
            raise response
        return response

    return AnthropicClient(api_key="k", base_url="https://api.example", transport=transport)


def test_the_api_loop_client_classifies_what_it_raises() -> None:
    """Test the wiring: the class the driver retries on is the class the live client raises."""
    from bellwether.harness import ModelRequest

    request = ModelRequest(model_id="m", system="", messages=())
    with pytest.raises(InfrastructureError) as overloaded:
        _client(HttpResponse(529, b"overloaded")).complete(request)
    assert overloaded.value.retryable
    with pytest.raises(InfrastructureError) as refused:
        _client(HttpResponse(400, b"bad key")).complete(request)
    assert not refused.value.retryable


def test_a_dropped_connection_is_transient() -> None:
    from bellwether.harness.live_client import _urllib_post

    with pytest.raises(InfrastructureError) as error:
        # A closed port on localhost: refused at once, no network needed.
        _urllib_post("http://127.0.0.1:9/v1/messages", {}, b"{}", 2.0)
    assert error.value.retryable
    assert isinstance(error.value.__cause__, (urllib.error.URLError, OSError))
