"""`--deterministic-sampling` (§20, §9.3): sampling pinned only when asked, and marked everywhere.

Bellwether records the provider's own defaults rather than imposing its own. When the operator
pins sampling, the request bodies carry it (temperature for both providers, the seed only where
the API takes one), the run header records the values and the `deterministic_sampling` flag,
the summary marks the matrix, and the verdict carries a note — because a temperature-0 run
understates real variance and must never read as the realistic condition.
"""

from __future__ import annotations

from bellwether.harness import ModelRequest, SamplingSpec
from bellwether.harness.live_client import anthropic_request_body, openai_request_body
from bellwether.report import Summary, render_pr_comment
from bellwether.report.markdown import Figures


def _request(sampling: SamplingSpec | None) -> ModelRequest:
    return ModelRequest(
        model_id="m",
        system="",
        messages=({"role": "user", "content": [{"type": "text", "text": "hi"}]},),
        sampling=sampling,
    )


def test_no_spec_sends_the_providers_defaults() -> None:
    assert "temperature" not in anthropic_request_body(_request(None), max_tokens=10)
    body = openai_request_body(_request(None), max_tokens=10)
    assert "temperature" not in body and "seed" not in body


def test_a_pinned_spec_reaches_both_wire_shapes_and_the_seed_only_where_accepted() -> None:
    spec = SamplingSpec(temperature=0.0, seed=7)
    anthropic = anthropic_request_body(_request(spec), max_tokens=10)
    assert anthropic["temperature"] == 0.0
    assert "seed" not in anthropic  # the Messages API takes no seed
    openai = openai_request_body(_request(spec), max_tokens=10)
    assert openai["temperature"] == 0.0
    assert openai["seed"] == 7


def test_is_deterministic_means_temperature_zero() -> None:
    assert SamplingSpec(temperature=0.0).is_deterministic
    assert not SamplingSpec(temperature=0.7).is_deterministic
    assert not SamplingSpec(seed=1).is_deterministic


def test_the_pr_comment_renders_the_verdict_notes() -> None:
    from tests.test_report import make_summary

    base = make_summary()
    noted = base.model_copy(
        update={
            "verdict": base.verdict.model_copy(
                update={"notes": ("deterministic sampling: temperature was pinned to 0",)}
            )
        }
    )
    assert isinstance(noted, Summary)
    text = render_pr_comment(noted, Figures())
    assert "> deterministic sampling: temperature was pinned to 0" in text
    assert "temperature was pinned" not in render_pr_comment(base, Figures())


def test_the_api_loop_pins_sampling_on_every_request() -> None:
    from bellwether.harness import (
        ApiLoopAdapter,
        ExecResult,
        ModelTurn,
        RunLimits,
        SandboxToolset,
        ScriptedClient,
        TurnUsage,
    )

    class _Exec:
        def __call__(
            self, argv: list[str], *, stdin: str | None = None, timeout: float
        ) -> ExecResult:
            return ExecResult(exit_code=0, stdout="", stderr="")

    client = ScriptedClient([ModelTurn(text="done", usage=TurnUsage(input=1, output=1))])
    spec = SamplingSpec(temperature=0.0, seed=3)
    adapter = ApiLoopAdapter(client, SandboxToolset(_Exec()), sampling=spec)
    list(adapter.run("go", model_id="m", limits=RunLimits()))
    assert client.requests and all(request.sampling == spec for request in client.requests)

    plain = ScriptedClient([ModelTurn(text="done", usage=TurnUsage(input=1, output=1))])
    list(ApiLoopAdapter(plain, SandboxToolset(_Exec())).run("go", model_id="m", limits=RunLimits()))
    assert all(request.sampling is None for request in plain.requests)
