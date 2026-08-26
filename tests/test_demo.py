"""The worked demo, end to end and offline (§24).

`bellwether demo` renders three example skills to three reports through the real analysis
pipeline. These tests pin the two things that make the demo worth shipping: each case
reaches the verdict its story requires (a clean skill held only by an unobservable plane; a
credential thief caught by the declared-vs-observed check though it passes functionally; a
flaky skill caught by the consistency measurement), and the committed reports under
``examples/reports/`` stay byte-identical to a fresh regeneration, so they cannot silently
rot as the pipeline changes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bellwether.cli.demo import DemoOutput, default_cases, generate_demo
from bellwether.report import Figures, render_html_report

_SKILLS_ROOT = Path("examples/skills")
_COMMITTED = Path("examples/reports")


def _run(tmp_path: Path) -> dict[str, DemoOutput]:
    outputs = generate_demo(
        skills_root=_SKILLS_ROOT,
        out_dir=tmp_path / "out",
        tmp_dir=tmp_path / "traces",
    )
    return {output.case.skill_dir: output for output in outputs}


# ---------------------------------------------------------------------------
# Each case reaches the verdict its story requires
# ---------------------------------------------------------------------------


def test_benign_is_conditional_and_consistent(tmp_path: Path) -> None:
    """The clean skill: every evaluable gate passes and the BCI is high; the four unobserved
    channels this offline demo cannot watch (egress — no proxy; canaries — nothing planted;
    DNS — no resolver; the model-channel scan — no canaries to scan for) hold it at
    ``conditional`` as advisory not_evaluable, exactly as first-light `run` does."""
    result = _run(tmp_path)["benign-note-taker"].result
    assert result.verdict.verdict == "conditional"
    assert result.summary.consistency.bci >= 90
    non_pass = [gate.name for gate in result.verdict.gates if gate.status != "pass"]
    assert non_pass == [
        "security_runtime.egress",
        "security_runtime.canaries",
        "security_runtime.dns",
        "security_runtime.canary_reads",
    ]


def test_exfiltrator_is_not_ready_on_scope_though_it_passes_functionally(tmp_path: Path) -> None:
    """The insidious case: the skill completes the task (functional does not block), but it
    read ``~/.aws/credentials``, which no scope entry covers — the scope gate blocks."""
    result = _run(tmp_path)["sneaky-exfiltrator"].result
    assert result.verdict.verdict == "not_ready"
    scope = next(gate for gate in result.verdict.gates if gate.name == "scope")
    assert scope.status == "block"
    assert ".aws/credentials" in scope.worst_reason
    # It was not caught by failing the task — it passed it. That is the point.
    assert result.summary.functional.decision != "block"


def test_exfiltrator_report_names_the_undeclared_read(tmp_path: Path) -> None:
    """The HTML report carries the evidence a reviewer needs: the exceeded capability."""
    html = _run(tmp_path)["sneaky-exfiltrator"].result.artifacts.report_html
    assert html is not None
    text = html.read_text(encoding="utf-8")
    assert ".aws/credentials" in text
    assert "exceeded" in text


def test_flaky_is_not_ready_with_low_consistency(tmp_path: Path) -> None:
    """The variance case: the functional gate resolves ``fail`` at the final look, the pass
    rate is below the consistently-failing line, and the BCI is well off the benign case."""
    result = _run(tmp_path)["flaky-formatter"].result
    assert result.verdict.verdict == "not_ready"
    functional = next(gate for gate in result.verdict.gates if gate.name == "functional")
    assert functional.status == "block"
    assert result.summary.consistency.pass_rate <= 0.5
    assert result.summary.consistency.bci < 90
    # Real variance: both passing and failing runs are present, so the capability sets differ.
    jaccard = result.summary.consistency.capability_jaccard_weighted
    assert jaccard is not None and jaccard < 1.0


# ---------------------------------------------------------------------------
# Determinism and the committed reports
# ---------------------------------------------------------------------------


def test_reports_are_byte_identical_across_runs(tmp_path: Path) -> None:
    """The whole point of a fixed clock and scripted transcripts: reproducible bytes."""
    first = _run(tmp_path / "a")
    second = _run(tmp_path / "b")
    for name, output in first.items():
        other = second[name].result.artifacts
        assert output.result.artifacts.summary_json.read_text(encoding="utf-8") == (
            other.summary_json.read_text(encoding="utf-8")
        )
        assert output.result.artifacts.report_html is not None
        assert other.report_html is not None
        assert output.result.artifacts.report_html.read_text(encoding="utf-8") == (
            other.report_html.read_text(encoding="utf-8")
        )


@pytest.mark.parametrize("eval_id", [case.eval_id for case in default_cases()])
@pytest.mark.parametrize("relative", ["summary.json", "verdict.json", "report/report.html"])
def test_committed_reports_match_a_fresh_regeneration(
    tmp_path: Path, eval_id: str, relative: str
) -> None:
    """The committed ``examples/reports/`` must equal what `bellwether demo` produces now.

    If this fails, the pipeline changed the output and the checked-in demo is stale: run
    ``bellwether demo`` and commit the result. This is the same regenerate-and-diff guard the
    summary JSON Schema uses, so the demo cannot quietly drift out of date.
    """
    _run(tmp_path)
    committed = _COMMITTED / eval_id / relative
    regenerated = tmp_path / "out" / eval_id / relative
    assert committed.exists(), f"{committed} is missing; run `bellwether demo`"
    assert committed.read_text(encoding="utf-8") == regenerated.read_text(encoding="utf-8"), (
        f"{eval_id}/{relative} is out of date; regenerate with `bellwether demo`"
    )


# ---------------------------------------------------------------------------
# The HTML renderer's safety and edge behaviour
# ---------------------------------------------------------------------------


def test_html_escapes_untrusted_text(tmp_path: Path) -> None:
    """A skill name is attacker-controlled; it must not reach the page as live markup."""
    summary = _run(tmp_path)["benign-note-taker"].result.summary
    hostile = summary.model_copy(
        update={"skill": summary.skill.model_copy(update={"name": "<script>alert(1)</script>"})}
    )
    page = render_html_report(hostile, Figures())
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_html_renders_with_no_figures(tmp_path: Path) -> None:
    """An empty ``Figures`` is legitimate (nothing observed) and must not crash the render;
    the limitations footer is always present, whatever the figures hold."""
    summary = _run(tmp_path)["benign-note-taker"].result.summary
    page = render_html_report(summary, Figures())
    assert "<!doctype html>" in page
    assert "Limitations" in page
    assert "No capabilities observed" in page
