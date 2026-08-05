"""The report's figures, as deterministic text (§13.8, §17.4).

Three figures carry most of the report's meaning, and all three render here as monospace
text so the PR comment and the HTML report draw from one source:

- the **per-scenario strip chart** — pass / fail / timeout / not_evaluable /
  excluded_quality across repetitions, the five states visually distinct and the look
  boundaries marked. §17.4 is firm that a timeout must not be drawn like an assertion
  failure even though §12.7 scores it as one: *how* a run failed is evidence, and flattening
  it away loses that;
- the **trajectory cluster list** — each cluster with its run count, representative step
  sequence, and mean intra-cluster distance;
- the **capability heatmap** — tier-3 capabilities grouped under their tier-1 class, runs
  across the top, a cell filled where the capability was exercised. It is the flagship
  visual because it makes a peripheral capability impossible to miss.

This module renders; it does not decide. Every input is a value the metrics layer already
computed. What it *does* own is order: anything without a semantically fixed order is
sorted, so the same evidence yields the same bytes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, Literal

from bellwether.determinism import format_float

__all__ = [
    "STRIP_GLYPHS",
    "CapabilityRow",
    "StripCell",
    "StripRow",
    "TrajectoryCluster",
    "render_capability_heatmap",
    "render_strip_chart",
    "render_trajectory_clusters",
]

#: One repetition's outcome in the strip chart. Kept distinct from the verdict vocabulary:
#: these are per-run observations, not gate dispositions.
StripCell = Literal["pass", "fail", "timeout", "not_evaluable", "excluded_quality"]

#: Glyph per outcome. Five distinct shapes, not five shades — the distinction survives a
#: greyscale render and a colour-blind reader (§17.4 accessibility). A timeout (``⧖``) and
#: an assertion failure (``✗``) are deliberately unalike.
STRIP_GLYPHS: Final[dict[StripCell, str]] = {
    "pass": "✓",
    "fail": "✗",
    "timeout": "⧖",
    "not_evaluable": "·",
    "excluded_quality": "~",
}

#: The order the legend lists the states in — fixed, so the legend is byte-stable.
_STRIP_ORDER: Final[tuple[StripCell, ...]] = (
    "pass",
    "fail",
    "timeout",
    "not_evaluable",
    "excluded_quality",
)


@dataclass(frozen=True)
class StripRow:
    """One scenario/target's repetition outcomes, with the design that produced them.

    ``look_boundaries`` are cumulative repetition counts at which a sequential look fell
    (``(6, 12)`` marks a boundary after the 6th and 12th run). ``stopped_at_look`` and
    ``n_evaluable`` travel because §13.8 forbids presenting a figure without them — a set
    that stopped at look 1 is a weaker claim than one that ran to look 3.
    """

    label: str
    cells: tuple[StripCell, ...]
    n_evaluable: int
    look_boundaries: tuple[int, ...] = ()
    stopped_at_look: int | None = None
    lower_bound: float | None = None


def _strip_line(row: StripRow) -> str:
    boundaries = set(row.look_boundaries)
    out: list[str] = []
    for index, cell in enumerate(row.cells):
        if index in boundaries and index != 0:
            out.append("|")
        out.append(STRIP_GLYPHS[cell])
    strip = "".join(out)
    tail = f"n={row.n_evaluable}"
    if row.stopped_at_look is not None:
        tail += f", stopped at look {row.stopped_at_look}"
    if row.lower_bound is not None:
        tail += f", LB {format_float(row.lower_bound)}"
    return f"{strip}  ({tail})"


def render_strip_chart(rows: Sequence[StripRow]) -> str:
    """Render the per-scenario strip chart as an aligned monospace block (§13.8).

    Rows keep the caller's order — scenario order is meaningful and must not be sorted
    away. A legend precedes the rows because the glyphs are only legible with one.
    """
    if not rows:
        return "_No repetition sets to display._"

    legend = " ".join(f"{STRIP_GLYPHS[state]} {state}" for state in _STRIP_ORDER)
    width = max(len(row.label) for row in rows)
    lines = [f"{row.label.ljust(width)}  {_strip_line(row)}" for row in rows]
    body = "\n".join(lines)
    return f"Legend: {legend}   ( | marks a sequential look boundary )\n\n```\n{body}\n```"


@dataclass(frozen=True)
class TrajectoryCluster:
    """One trajectory cluster (§13.4): the runs that took the same shape of path."""

    cluster_id: str
    run_count: int
    representative: tuple[str, ...]
    mean_intra_distance: float


def render_trajectory_clusters(clusters: Sequence[TrajectoryCluster]) -> str:
    """Render the cluster list, largest cluster first (§13.8).

    Ties on run count break on ``cluster_id`` so the order is total and stable.
    """
    if not clusters:
        return "_No trajectory clusters (single run, or trajectory not evaluable)._"

    ordered = sorted(clusters, key=lambda c: (-c.run_count, c.cluster_id))
    lines: list[str] = []
    for cluster in ordered:
        steps = " → ".join(cluster.representative) if cluster.representative else "(empty)"
        lines.append(
            f"- **{cluster.cluster_id}** — {cluster.run_count} run(s), "
            f"mean intra-cluster distance {format_float(cluster.mean_intra_distance)}\n"
            f"  `{steps}`"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class CapabilityRow:
    """One tier-3 capability and, per run, whether it was exercised.

    ``tier1_class`` is the scope class this capability rolls up under (§4.1); the heatmap
    groups by it. ``exercised`` is aligned to the run labels passed to the renderer.
    """

    tier1_class: str
    capability: str
    exercised: tuple[bool, ...]
    #: Marks a capability the risk weighting treats as high-risk, so the heatmap can flag
    #: it without the reader cross-referencing the weights table.
    high_risk: bool = field(default=False)


_FILLED: Final[str] = "█"
_EMPTY: Final[str] = "·"


def render_capability_heatmap(rows: Sequence[CapabilityRow], run_labels: Sequence[str]) -> str:
    """Render the capability heatmap: capabilities down, runs across (§13.8, the flagship).

    Rows are grouped by tier-1 class (classes sorted, capabilities sorted within a class),
    so the same profile always draws the same grid. A filled cell means the capability was
    exercised on that run; a high-risk capability is marked with ``!``.
    """
    if not rows:
        return "_No capabilities observed._"

    grouped: dict[str, list[CapabilityRow]] = {}
    for row in rows:
        grouped.setdefault(row.tier1_class, []).append(row)

    label_width = max(len(f"{r.capability}") for r in rows) + 2
    header_cols = "".join(str((i + 1) % 10) for i in range(len(run_labels)))
    lines = [f"{'capability'.ljust(label_width)} {header_cols}"]

    for tier1 in sorted(grouped):
        lines.append(f"{tier1}/")
        for row in sorted(grouped[tier1], key=lambda r: r.capability):
            grid = "".join(_FILLED if hit else _EMPTY for hit in row.exercised)
            mark = " !" if row.high_risk else ""
            lines.append(f"  {row.capability.ljust(label_width - 2)} {grid}{mark}")

    body = "\n".join(lines)
    runs_note = f"{len(run_labels)} run(s); columns are runs left-to-right"
    return f"```\n{body}\n```\n_{runs_note}. `!` marks a high-risk capability._"
