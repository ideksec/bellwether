"""The on-disk artifact tree (§17.1).

One evaluation produces one directory, ``.bellwether-out/<eval_id>/``, laid out exactly as
§17.1 prescribes so that ``bellwether report`` and downstream tooling can find each piece
by path. This module writes that tree and nothing else — the *content* of every file was
rendered upstream (`report`) or captured upstream (`trace`); here it is only placed.

Determinism carries through to the filesystem: paths are built from the run's own
identifiers (scenario, target slug, repetition), directories are created in sorted order,
and every text file ends in a newline. Two runs over the same evaluation write the same
tree, which is what makes the byte-identical artifact test of §17.1 meaningful.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ArtifactTree", "RunKey", "target_slug", "write_artifact_tree"]

_SLUG_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def target_slug(harness: str, provider: str, model_alias: str) -> str:
    """A filesystem-legal slug for a matrix target — ``harness/provider/alias`` flattened.

    Slashes and other characters a path segment cannot hold collapse to ``-`` so the slug
    is one path segment; the three parts stay readable and, being derived only from the
    target's own identifiers, stay stable across runs.
    """
    raw = f"{harness}-{provider}-{model_alias}"
    return _SLUG_UNSAFE.sub("-", raw).strip("-")


@dataclass(frozen=True)
class RunKey:
    """Where one repetition sits in the matrix — the coordinate its artifacts file under."""

    scenario_id: str
    target: str
    repetition: int

    def relative(self, suffix: str) -> Path:
        """The path, relative to a top-level artifact subdir, for this run's file."""
        return Path(self.scenario_id) / self.target / f"{self.repetition}{suffix}"


@dataclass(frozen=True)
class ArtifactTree:
    """The paths written for one evaluation, for a caller that needs to point at them."""

    root: Path
    summary_json: Path
    verdict_json: Path
    pr_comment: Path
    traces: tuple[Path, ...]
    canonicals: tuple[Path, ...]
    #: The rendered HTML report (``report/report.html``), when one was produced. Optional
    #: because a caller may want only the machine-readable artifacts.
    report_html: Path | None = None


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = text if text.endswith("\n") else text + "\n"
    path.write_text(body, encoding="utf-8")
    return path


def write_artifact_tree(
    out_dir: Path,
    eval_id: str,
    *,
    summary_json: str,
    verdict_json: str,
    pr_comment: str,
    traces: Mapping[RunKey, str],
    canonicals: Mapping[RunKey, str],
    report_html: str | None = None,
) -> ArtifactTree:
    """Write ``<out_dir>/<eval_id>/`` per §17.1 and return the paths.

    ``traces`` and ``canonicals`` map each run to its already-serialised JSONL / JSON text;
    this function only places them. Keys are written in sorted order so the walk is stable.
    ``report_html``, when given, is placed at ``report/report.html`` beside the PR comment.
    """
    root = out_dir / eval_id
    root.mkdir(parents=True, exist_ok=True)

    summary_path = _write_text(root / "summary.json", summary_json)
    verdict_path = _write_text(root / "verdict.json", verdict_json)
    pr_comment_path = _write_text(root / "report" / "pr_comment.md", pr_comment)
    report_html_path = (
        _write_text(root / "report" / "report.html", report_html)
        if report_html is not None
        else None
    )

    trace_paths: list[Path] = []
    for key in sorted(traces, key=lambda k: (k.scenario_id, k.target, k.repetition)):
        trace_paths.append(_write_text(root / "traces" / key.relative(".arf.jsonl"), traces[key]))

    canon_paths: list[Path] = []
    for key in sorted(canonicals, key=lambda k: (k.scenario_id, k.target, k.repetition)):
        canon_paths.append(
            _write_text(root / "canonical" / key.relative(".canon.json"), canonicals[key])
        )

    return ArtifactTree(
        root=root,
        summary_json=summary_path,
        verdict_json=verdict_path,
        pr_comment=pr_comment_path,
        traces=tuple(trace_paths),
        canonicals=tuple(canon_paths),
        report_html=report_html_path,
    )
