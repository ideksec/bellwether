"""``bellwether report`` — re-render a stored artifact tree (§17.1, §20).

A tree holds ``summary.json`` (the rollup) and, since the figures were persisted,
``metrics/figures.json`` (the rendering inputs computed from the readings). Both renderers
are pure functions of those two, so re-rendering is deterministic: the same tree yields the
same ``report/pr_comment.md``, ``report/report.html`` and ``findings.sarif`` the run wrote.
``--format all`` renders all three whatever ``reporting.html`` / ``reporting.sarif`` said at
run time: re-rendering is an explicit request for the file. A tree without the
figures file predates persistence and is refused with that reason — a report rendered from
a summary alone would silently lose the strip chart, the heatmap, and the scope table.
"""

from __future__ import annotations

from pathlib import Path

from bellwether.cli.diff import load_summary, resolve_summary
from bellwether.errors import BellwetherError
from bellwether.report import (
    figures_from_json,
    render_html_report,
    render_pr_comment,
    render_sarif,
)

__all__ = ["FORMATS", "rerender_tree", "resolve_tree"]

FORMATS = ("md", "html", "sarif", "all")


def resolve_tree(ref: str, *, out_dir: Path) -> Path:
    """The evaluation directory ``ref`` names: a directory, or an eval id under ``out_dir``."""
    return resolve_summary(ref, out_dir=out_dir).parent


def rerender_tree(
    ref: str, *, out_dir: Path, fmt: str = "all", to: Path | None = None
) -> list[Path]:
    """Render the tree's report again; return the files written, in a fixed order.

    The comment and the HTML report go to ``report/`` and ``findings.sarif`` to the tree root,
    where the run put them (§17.1); ``to`` puts all of them in one directory instead.
    """
    if fmt not in FORMATS:
        raise BellwetherError(f"--format must be one of {', '.join(FORMATS)}, not {fmt!r}")
    tree = resolve_tree(ref, out_dir=out_dir)
    summary = load_summary(tree / "summary.json")
    figures_path = tree / "metrics" / "figures.json"
    if not figures_path.is_file():
        raise BellwetherError(
            f"{tree} has no metrics/figures.json: the tree was written before the report "
            "figures were persisted, so its strip chart, heatmap and scope table cannot be "
            "rebuilt from the summary alone — re-run the evaluation to get a re-renderable tree"
        )
    figures = figures_from_json(figures_path.read_text(encoding="utf-8"), where=str(figures_path))
    target = to if to is not None else tree / "report"
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if fmt in {"md", "all"}:
        path = target / "pr_comment.md"
        path.write_text(_newline(render_pr_comment(summary, figures)), encoding="utf-8")
        written.append(path)
    if fmt in {"html", "all"}:
        path = target / "report.html"
        path.write_text(_newline(render_html_report(summary, figures)), encoding="utf-8")
        written.append(path)
    if fmt in {"sarif", "all"}:
        path = (to if to is not None else tree) / "findings.sarif"
        path.write_text(_newline(render_sarif(summary, figures)), encoding="utf-8")
        written.append(path)
    return written


def _newline(text: str) -> str:
    """The artifact writer ends every text file in a newline; match it byte for byte."""
    return text if text.endswith("\n") else text + "\n"
