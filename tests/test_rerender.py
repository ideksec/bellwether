"""`bellwether report` re-renders a stored tree from summary.json + metrics/figures.json (§20).

The point is byte-fidelity: the run wrote the report from a Summary and a Figures; the tree
now carries both, so re-rendering must produce the same bytes. A tree without the figures
file is refused, never rendered from the summary alone.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bellwether.cli import ExitCode, app
from bellwether.cli.rerender import rerender_tree
from bellwether.errors import BellwetherError
from bellwether.report import FIGURES_VERSION, Figures, figures_from_json, render_figures_json
from bellwether.report.figures import CapabilityRow, StripRow, TrajectoryCluster
from bellwether.report.markdown import ScopeRow

_ROOT = Path(__file__).resolve().parent.parent
_REPORTS = _ROOT / "examples" / "reports"
_BENIGN = "demo-benign-note-taker"
_SNEAKY = "demo-sneaky-exfiltrator"

runner = CliRunner()


def test_figures_round_trip_through_json() -> None:
    figures = Figures(
        strip=(
            StripRow(
                label="s/frontier",
                cells=("pass", "fail", "timeout"),
                n_evaluable=3,
                look_boundaries=(6, 12),
                stopped_at_look=1,
                lower_bound=0.4,
            ),
        ),
        clusters=(TrajectoryCluster("c1", 2, ("a", "b"), 0.125),),
        heatmap=(CapabilityRow("core", "tool:skill", (True, False), high_risk=True),),
        run_labels=("r1", "r2"),
        declared_vs_observed=(
            ScopeRow("x", declared=False, observed=True, disposition="exceeded"),
        ),
    )
    text = render_figures_json(figures)
    assert json.loads(text)["figures_version"] == FIGURES_VERSION
    assert figures_from_json(text) == figures
    assert render_figures_json(figures_from_json(text)) == text


def test_figures_of_another_version_are_refused() -> None:
    payload = json.loads(render_figures_json(Figures()))
    payload["figures_version"] = "0"
    with pytest.raises(BellwetherError, match="figures_version '0'"):
        figures_from_json(json.dumps(payload))
    with pytest.raises(BellwetherError, match="not valid JSON"):
        figures_from_json("{")
    with pytest.raises(BellwetherError, match="malformed"):
        figures_from_json(json.dumps({"figures_version": FIGURES_VERSION, "strip": [{"x": 1}]}))


@pytest.mark.parametrize("eval_id", [_BENIGN, _SNEAKY])
def test_rerender_reproduces_the_committed_report_bytes(tmp_path: Path, eval_id: str) -> None:
    """The committed demo trees carry metrics/figures.json; re-rendering into a scratch
    directory yields exactly the committed pr_comment.md and report.html."""
    written = rerender_tree(eval_id, out_dir=_REPORTS, to=tmp_path)
    assert [path.name for path in written] == ["pr_comment.md", "report.html"]
    for path in written:
        committed = _REPORTS / eval_id / "report" / path.name
        assert path.read_text(encoding="utf-8") == committed.read_text(encoding="utf-8")


def test_rerender_writes_only_the_requested_format(tmp_path: Path) -> None:
    assert [p.name for p in rerender_tree(_BENIGN, out_dir=_REPORTS, fmt="md", to=tmp_path)] == [
        "pr_comment.md"
    ]
    assert not (tmp_path / "report.html").exists()
    with pytest.raises(BellwetherError, match="--format"):
        rerender_tree(_BENIGN, out_dir=_REPORTS, fmt="pdf", to=tmp_path)


def test_a_tree_without_figures_is_refused(tmp_path: Path) -> None:
    tree = tmp_path / "old-eval"
    tree.mkdir()
    (tree / "summary.json").write_text(
        (_REPORTS / _BENIGN / "summary.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    with pytest.raises(BellwetherError, match=r"no metrics/figures\.json"):
        rerender_tree(str(tree), out_dir=tmp_path)
    assert not (tree / "report").exists()


def test_report_command_end_to_end(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["report", _BENIGN, "--out", str(_REPORTS), "--to", str(tmp_path), "--json"]
    )
    assert result.exit_code == ExitCode.OK, result.output
    written = json.loads(result.output)["written"]
    assert len(written) == 2 and all(Path(p).is_file() for p in written)
    missing = runner.invoke(app, ["report", "nope", "--out", str(_REPORTS)])
    assert missing.exit_code == ExitCode.INFRASTRUCTURE
