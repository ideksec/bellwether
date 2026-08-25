"""The PR comment: the report as Markdown (§17.4, §18.2).

The comment is assembled here from a :class:`~bellwether.report.summary.Summary` and the
figure inputs — nothing is computed, everything is placement. Four placement rules have
teeth, because each is a way the report could mislead while looking complete:

- the **BCI is never rendered without the pass rate beside it** (§13.3). A high BCI on a
  skill that fails most runs is consistency of *failure*; shown alone it reads as quality;
- a **"consistently failing" annotation** appears wherever the pass rate is below 0.5;
- **every figure carries ``n_evaluable`` and the look** it stopped at (handled in
  :mod:`~bellwether.report.figures`), so a weak claim cannot be mistaken for a strong one;
- the **§2 limitations footer is rendered verbatim and whole** from
  :data:`~bellwether.constants.REPORT_LIMITATIONS` — collapsed into a ``<details>`` so the
  comment stays scannable, but present in full, because a report that drops the caveats
  oversells by omission.

Layout favours the reviewer skimming a diff: the verdict, the headline numbers, the gate
table, and the two flagship figures sit at the top level; the mechanical detail (trajectory
clusters, sequential design) and the boilerplate limitations collapse into ``<details>``.

Hand-rolled rather than templated on purpose: the rules above are conditional logic, and
keeping them in Python — where they are unit-tested — beats hiding them in template
branches. The output is deterministic: given the same summary and figures, the same bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bellwether.determinism import format_float
from bellwether.report.figures import (
    CapabilityRow,
    StripRow,
    TrajectoryCluster,
    render_capability_heatmap,
    render_strip_chart,
    render_trajectory_clusters,
)
from bellwether.report.summary import Summary

__all__ = ["Figures", "ScopeRow", "render_pr_comment"]

#: The consistently-failing threshold (§13.3, §13.7): at or below this pass rate the BCI is
#: annotated, because it is measuring the stability of a failure.
_CONSISTENTLY_FAILING_AT = 0.5

#: One-line neutral gloss per verdict word. Deliberately free of the assurance vocabulary
#: the language lint bans — a verdict is a disposition on the evidence, not a warranty.
_VERDICT_GLOSS: dict[str, str] = {
    "ready": "met the configured gates on the evidence collected",
    "conditional": "met the blocking gates; see the warnings below",
    "not_ready": "failed one or more blocking gates",
}

#: The verdict word as a coloured dot, so the disposition is legible at a glance in a diff.
_VERDICT_GLYPH: dict[str, str] = {
    "ready": "🟢",
    "conditional": "🟡",
    "not_ready": "🔴",
}

_GATE_GLYPH: dict[str, str] = {
    "pass": "🟢",
    "warn": "🟡",
    "block": "🔴",
    "not_evaluable": "⚪",
}

#: The order gate tallies are listed in the at-a-glance line — worst last is deliberately
#: avoided; the eye should land on what blocked first, so blocks lead.
_GATE_TALLY_ORDER: tuple[str, ...] = ("block", "warn", "not_evaluable", "pass")


@dataclass(frozen=True)
class ScopeRow:
    """One row of the Declared vs Observed table (§12.6): what the manifest claimed against
    what the runs showed, and how the scope gate scored the pair."""

    capability: str
    declared: bool
    observed: bool
    disposition: str


@dataclass(frozen=True)
class Figures:
    """The figure inputs the comment renders. All already decided upstream."""

    strip: tuple[StripRow, ...] = ()
    clusters: tuple[TrajectoryCluster, ...] = ()
    heatmap: tuple[CapabilityRow, ...] = ()
    run_labels: tuple[str, ...] = ()
    declared_vs_observed: tuple[ScopeRow, ...] = field(default_factory=tuple)


def _yesno(value: bool) -> str:
    return "yes" if value else "—"


def _collapsible(label: str, body: str) -> str:
    """A ``<details>`` block. The blank lines around ``body`` are load-bearing: GitHub only
    renders the Markdown inside a ``<details>`` when it is separated from the tags."""
    return f"<details>\n<summary>{label}</summary>\n\n{body}\n\n</details>"


def _bci_line(summary: Summary) -> str:
    """The BCI, with the pass rate beside it and the annotation where it is failing."""
    consistency = summary.consistency
    pass_rate = consistency.pass_rate
    annotation = consistency.annotation
    if annotation is None and pass_rate < _CONSISTENTLY_FAILING_AT:
        annotation = "consistently failing"
    suffix = f" — **{annotation}**" if annotation else ""
    return (
        f"**Consistency (BCI): {format_float(consistency.bci)}** "
        f"(pass rate {format_float(pass_rate)}, n={summary.functional.n_evaluable})"
        f"{suffix}"
    )


def _trajectory_line(summary: Summary) -> str | None:
    """The §13.4 trajectory dispersion, reported against the calibrated noise floor.

    At or below the floor the precise figure is absent from the summary by construction,
    so this renders the qualitative label instead — the instrument produces that dispersion
    on identical input, and printing it as a measurement of the skill would fabricate a
    precision the tool does not have. ``None`` (nothing to render) only where no dispersion
    was measured at all.
    """
    consistency = summary.consistency
    floor = summary.noise_floor
    floor_note = (
        f" (floor {format_float(floor.trajectory)}, calibrated {floor.calibrated_at})"
        if floor is not None
        else ""
    )
    if consistency.trajectory_at_noise_floor:
        return f"**Trajectory dispersion:** at noise floor{floor_note}."
    if consistency.trajectory_dispersion is None:
        return None
    return (
        f"**Trajectory dispersion:** {format_float(consistency.trajectory_dispersion)}{floor_note}."
    )


def _gate_tally(summary: Summary) -> str:
    """A compact count of gates by disposition — the at-a-glance line under the verdict."""
    counts: dict[str, int] = {}
    for gate in summary.verdict.gates:
        counts[gate.status] = counts.get(gate.status, 0) + 1
    parts = [
        f"{_GATE_GLYPH.get(status, '')} {counts[status]} {status}"
        for status in _GATE_TALLY_ORDER
        if counts.get(status)
    ]
    return "**Gates:** " + " · ".join(parts) if parts else "**Gates:** none evaluated"


def _verdict_header(summary: Summary) -> str:
    status = summary.verdict.status
    glyph = _VERDICT_GLYPH.get(status, "")
    gloss = _VERDICT_GLOSS.get(status, "")
    lines = [
        f"## {glyph} Bellwether verdict: `{status}`",
        "",
        f"_{gloss}._ · profile **{summary.policy.profile}** · "
        f"skill **{summary.skill.name}** (`{summary.skill.criticality}` criticality)",
        "",
        _bci_line(summary),
        "",
    ]
    functional = summary.functional
    lines.append(
        f"**Functional:** pass-rate lower bound {format_float(functional.lower_bound)} "
        f"vs threshold {format_float(functional.threshold)} → `{functional.decision}` "
        f"(n={functional.n_evaluable})."
    )
    trajectory = _trajectory_line(summary)
    if trajectory is not None:
        lines.append(trajectory)
    if summary.matrix.descriptive_only:
        lines.append(
            "> Fixed-N run (`descriptive_only`): the verdict ceiling is `conditional`, "
            "however clean the gates — the design does not support a sequential `ready`."
        )
    lines += ["", _gate_tally(summary)]
    return "\n".join(lines)


def _gate_table(summary: Summary) -> str:
    header = "| Gate | Status | Observed | Threshold | Reason |\n|---|---|---|---|---|"
    rows = [
        f"| {g.name} | {_GATE_GLYPH.get(g.status, '')} `{g.status}` | {g.observed or '—'} "
        f"| {g.threshold or '—'} | {g.reason or '—'} |"
        for g in summary.verdict.gates
    ]
    if not rows:
        return "### Gates\n\n_No gates evaluated._"
    return "### Gates\n\n" + header + "\n" + "\n".join(rows)


def _sequential_design(summary: Summary) -> str:
    matrix = summary.matrix
    if matrix.design != "sequential":
        return f"Fixed-N design; {matrix.runs_evaluable} evaluable runs."
    looks = ", ".join(str(look) for look in matrix.looks) if matrix.looks else "—"
    stopped = ", ".join(
        f"look {look}: {count}" for look, count in sorted(matrix.sets_stopped_at_look.items())
    )
    boundary = format_float(matrix.boundary_z) if matrix.boundary_z is not None else "—"
    lines = [
        f"- Looks: {looks} (boundary z = {boundary})",
        f"- Sets stopped at each look: {stopped or 'none recorded'}",
        f"- Sets held open by the capability rule: {matrix.sets_held_open_for_capability}",
    ]
    if matrix.escalation_truncated:
        lines.append(
            "- ⚠️ Escalation truncated: the matrix hit its budget before the design finished."
        )
    return "\n".join(lines)


def _declared_vs_observed(figures: Figures) -> str:
    if not figures.declared_vs_observed:
        return "### Declared vs observed\n\n_No manifest scope to compare._"
    header = "| Capability | Declared | Observed | Disposition |\n|---|---|---|---|"
    rows = [
        f"| `{r.capability}` | {_yesno(r.declared)} | {_yesno(r.observed)} | {r.disposition} |"
        for r in sorted(figures.declared_vs_observed, key=lambda r: r.capability)
    ]
    return "### Declared vs observed\n\n" + header + "\n" + "\n".join(rows)


def _limitations_body(summary: Summary) -> str:
    return "\n".join(f"- {line}" for line in summary.limitations)


def render_pr_comment(summary: Summary, figures: Figures) -> str:
    """Render the full PR comment (§17.4, §18.2).

    Deterministic: the same ``summary`` and ``figures`` render the same bytes. The
    limitations footer is always present and always whole — collapsed for scannability, but
    every caveat is in the rendered text.
    """
    sections = [
        _verdict_header(summary),
        _gate_table(summary),
        "### Repetition outcomes\n\n" + render_strip_chart(figures.strip),
        "### Capability heatmap\n\n"
        + render_capability_heatmap(figures.heatmap, figures.run_labels),
        _declared_vs_observed(figures),
        _collapsible("Trajectory clusters", render_trajectory_clusters(figures.clusters)),
        _collapsible("Sequential design", _sequential_design(summary)),
        _collapsible(
            "⚠️ Limitations — read before relying on this verdict", _limitations_body(summary)
        ),
    ]
    return "\n\n".join(sections) + "\n"
