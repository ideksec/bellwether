"""The report as a self-contained HTML page (§17.4).

The PR comment (:mod:`bellwether.report.markdown`) is the terse surface a reviewer reads in
a diff; this is the one they open in a browser. Both render from the same
:class:`~bellwether.report.summary.Summary` and :class:`~bellwether.report.markdown.Figures`
— *renders, never computes*, the package rule — so the two can never disagree about a
number. What HTML adds is layout: the verdict as a banner, the strip chart and capability
heatmap as real grids rather than monospace, and the Declared-vs-Observed table where an
exceeded row can be coloured without losing the glyph a colour-blind reader needs.

The page is deliberately one file with inline CSS and no script or external asset: an
artifact that has to survive being copied out of ``.bellwether-out/`` and opened from disk,
attached to a CI job, or published as-is cannot depend on a stylesheet host being reachable.
It is theme-aware through ``prefers-color-scheme`` only — there is no toggle, because there
is no script. Every visual state pairs a colour with a glyph or a label, so the meaning
survives greyscale and colour blindness (the §17.4 accessibility rule the figures already
follow).

The output is deterministic: the same summary and figures produce the same bytes, so a
committed example report has a stable git diff and the regeneration test can byte-compare.
"""

from __future__ import annotations

import html

from bellwether.determinism import format_float
from bellwether.report.figures import CapabilityRow, StripCell, StripRow
from bellwether.report.markdown import Figures, ScopeRow
from bellwether.report.summary import Summary

__all__ = ["render_html_report"]

#: The consistently-failing threshold (§13.3), mirrored from the Markdown renderer: at or
#: below this pass rate the BCI is annotated, because it is measuring the stability of a
#: failure rather than of success.
_CONSISTENTLY_FAILING_AT = 0.5

#: Neutral one-line gloss per verdict word — the same wording the PR comment uses, kept
#: free of the assurance vocabulary the language lint bans.
_VERDICT_GLOSS: dict[str, str] = {
    "ready": "met the configured gates on the evidence collected",
    "conditional": "met the blocking gates; see the warnings below",
    "not_ready": "failed one or more blocking gates",
}

#: Gate/verdict status → (glyph, css class). The glyph carries the meaning without colour.
_STATUS_STYLE: dict[str, tuple[str, str]] = {
    "ready": ("●", "ok"),
    "conditional": ("◐", "warn"),
    "not_ready": ("○", "block"),
    "pass": ("✓", "ok"),
    "warn": ("!", "warn"),
    "block": ("✗", "block"),
    "not_evaluable": ("·", "muted"),
}

#: One strip-chart outcome → (glyph, label, css class). The glyph is the figures module's,
#: so the HTML and the monospace strip agree cell for cell.
_CELL_STYLE: dict[StripCell, tuple[str, str, str]] = {
    "pass": ("✓", "pass", "ok"),
    "fail": ("✗", "fail", "block"),
    "timeout": ("⧖", "timeout", "warn"),
    "not_evaluable": ("·", "not evaluable", "muted"),
    "excluded_quality": ("~", "excluded (quality)", "muted"),
}


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def render_html_report(summary: Summary, figures: Figures) -> str:
    """Render the full HTML report page (§17.4).

    Deterministic: the same ``summary`` and ``figures`` render the same bytes. The
    limitations footer is always present and always whole, exactly as in the PR comment —
    a report that drops the §2 caveats oversells by omission.
    """
    sections = [
        _banner(summary),
        _headline_stats(summary),
        _gate_table(summary),
        _strip_section(figures),
        _heatmap_section(figures),
        _declared_vs_observed(figures),
        _limitations(summary),
        _provenance(summary),
    ]
    body = "\n".join(sections)
    return _document(summary, body)


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _banner(summary: Summary) -> str:
    status = summary.verdict.status
    glyph, css = _STATUS_STYLE.get(status, ("", "muted"))
    gloss = _VERDICT_GLOSS.get(status, "")
    return (
        f'<header class="banner {css}">\n'
        f'  <div class="verdict-glyph" aria-hidden="true">{glyph}</div>\n'
        f"  <div>\n"
        f'    <div class="eyebrow">Bellwether verdict</div>\n'
        f'    <h1 class="verdict">{_esc(status)}</h1>\n'
        f"    <p>{_esc(gloss)}. Policy profile <strong>{_esc(summary.policy.profile)}</strong>; "
        f"skill <strong>{_esc(summary.skill.name)}</strong> "
        f"(<code>{_esc(summary.skill.criticality)}</code> criticality).</p>\n"
        f"  </div>\n"
        f"</header>"
    )


def _headline_stats(summary: Summary) -> str:
    functional = summary.functional
    consistency = summary.consistency
    matrix = summary.matrix

    annotation = consistency.annotation
    if annotation is None and consistency.pass_rate < _CONSISTENTLY_FAILING_AT:
        annotation = "consistently failing"
    bci_note = f'<span class="chip block">{_esc(annotation)}</span>' if annotation else ""

    cards = [
        _stat_card(
            "Functional",
            f"{format_float(functional.lower_bound)}",
            f"pass-rate lower bound vs {format_float(functional.threshold)} "
            f"&rarr; <code>{_esc(functional.decision)}</code> "
            f"(n={functional.n_evaluable})",
        ),
        _stat_card(
            "Consistency (BCI)",
            f"{format_float(consistency.bci)} {bci_note}",
            f"pass rate {format_float(consistency.pass_rate)}, n={functional.n_evaluable}",
        ),
        _stat_card(
            "Runs",
            f"{matrix.runs_evaluable}/{matrix.runs_completed}",
            f"evaluable of completed &middot; {matrix.scenarios} scenario(s) "
            f"&times; {matrix.targets} target(s) &middot; {_esc(matrix.design)} design",
        ),
    ]
    return '<section class="stats">\n' + "\n".join(cards) + "\n</section>"


def _stat_card(label: str, value: str, detail: str) -> str:
    return (
        '  <div class="card">\n'
        f'    <div class="card-label">{_esc(label)}</div>\n'
        f'    <div class="card-value">{value}</div>\n'
        f'    <div class="card-detail">{detail}</div>\n'
        "  </div>"
    )


def _gate_table(summary: Summary) -> str:
    rows = []
    for gate in summary.verdict.gates:
        glyph, css = _STATUS_STYLE.get(gate.status, ("", "muted"))
        required = "required" if gate.required else "advisory"
        rows.append(
            "    <tr>\n"
            f"      <td><code>{_esc(gate.name)}</code></td>\n"
            f'      <td><span class="chip {css}">{glyph} {_esc(gate.status)}</span></td>\n'
            f"      <td>{_esc(gate.observed) or '&mdash;'}</td>\n"
            f"      <td>{_esc(gate.threshold) or '&mdash;'}</td>\n"
            f'      <td class="muted-text">{_esc(required)}</td>\n'
            f"      <td>{_esc(gate.reason) or '&mdash;'}</td>\n"
            "    </tr>"
        )
    body = "\n".join(rows) if rows else '    <tr><td colspan="6">No gates evaluated.</td></tr>'
    return (
        '<section class="block-section">\n'
        "  <h2>Gates</h2>\n"
        '  <div class="table-wrap">\n'
        '  <table class="gates">\n'
        "    <thead><tr>"
        "<th>Gate</th><th>Status</th><th>Observed</th>"
        "<th>Threshold</th><th>Kind</th><th>Reason</th>"
        "</tr></thead>\n"
        "    <tbody>\n"
        f"{body}\n"
        "    </tbody>\n"
        "  </table>\n"
        "  </div>\n"
        "</section>"
    )


def _strip_section(figures: Figures) -> str:
    if not figures.strip:
        return (
            '<section class="block-section">\n  <h2>Repetition outcomes</h2>\n'
            "  <p>No repetition sets to display.</p>\n</section>"
        )
    rows = "\n".join(_strip_row(row) for row in figures.strip)
    return (
        '<section class="block-section">\n'
        "  <h2>Repetition outcomes</h2>\n"
        f"  {_strip_legend()}\n"
        f'  <div class="strip-rows">\n{rows}\n  </div>\n'
        "</section>"
    )


def _strip_legend() -> str:
    parts = []
    for glyph, label, css in _CELL_STYLE.values():
        parts.append(f'<span class="chip {css}">{glyph} {_esc(label)}</span>')
    return '<div class="legend">' + " ".join(parts) + "</div>"


def _strip_row(row: StripRow) -> str:
    boundaries = set(row.look_boundaries)
    cells: list[str] = []
    for index, cell in enumerate(row.cells):
        if index in boundaries and index != 0:
            cells.append('<span class="look-boundary" aria-hidden="true"></span>')
        glyph, label, css = _CELL_STYLE[cell]
        cells.append(f'<span class="cell {css}" title="{_esc(label)}">{glyph}</span>')
    tail = f"n={row.n_evaluable}"
    if row.stopped_at_look is not None:
        tail += f", stopped at look {row.stopped_at_look}"
    if row.lower_bound is not None:
        tail += f", LB {format_float(row.lower_bound)}"
    return (
        '    <div class="strip-row">\n'
        f'      <div class="strip-label">{_esc(row.label)}</div>\n'
        f'      <div class="strip-cells">{"".join(cells)}</div>\n'
        f'      <div class="strip-tail muted-text">{_esc(tail)}</div>\n'
        "    </div>"
    )


def _heatmap_section(figures: Figures) -> str:
    if not figures.heatmap:
        return (
            '<section class="block-section">\n  <h2>Capability heatmap</h2>\n'
            "  <p>No capabilities observed.</p>\n</section>"
        )
    grouped: dict[str, list[CapabilityRow]] = {}
    for row in figures.heatmap:
        grouped.setdefault(row.tier1_class, []).append(row)

    labels = figures.run_labels or tuple(
        f"r{i + 1}" for i in range(len(figures.heatmap[0].exercised))
    )
    header_cells = "".join(f"<th>{_esc(label)}</th>" for label in labels)
    body_rows: list[str] = []
    for tier1 in sorted(grouped):
        body_rows.append(
            f'    <tr class="group"><td colspan="{len(labels) + 1}">'
            f"<code>{_esc(tier1)}/</code></td></tr>"
        )
        for row in sorted(grouped[tier1], key=lambda r: r.capability):
            flag = ' <span class="chip block" title="high-risk">!</span>' if row.high_risk else ""
            cells = "".join(
                (
                    '<td class="hit" title="exercised">&#9608;</td>'
                    if hit
                    else '<td class="miss" title="not exercised">&middot;</td>'
                )
                for hit in row.exercised
            )
            body_rows.append(
                f"    <tr><td><code>{_esc(row.capability)}</code>{flag}</td>{cells}</tr>"
            )
    return (
        '<section class="block-section">\n'
        "  <h2>Capability heatmap</h2>\n"
        f'  <p class="muted-text">{len(labels)} run(s); a filled cell means the '
        "capability was exercised on that run. <code>!</code> marks a high-risk capability.</p>\n"
        '  <div class="table-wrap">\n'
        '  <table class="heatmap">\n'
        f"    <thead><tr><th>capability</th>{header_cells}</tr></thead>\n"
        "    <tbody>\n" + "\n".join(body_rows) + "\n    </tbody>\n"
        "  </table>\n"
        "  </div>\n"
        "</section>"
    )


def _declared_vs_observed(figures: Figures) -> str:
    if not figures.declared_vs_observed:
        return (
            '<section class="block-section">\n  <h2>Declared vs observed</h2>\n'
            "  <p>No manifest scope to compare, or nothing observed outside it.</p>\n</section>"
        )
    rows = "\n".join(
        _scope_row(row)
        for row in sorted(figures.declared_vs_observed, key=lambda r: (r.disposition, r.capability))
    )
    return (
        '<section class="block-section">\n'
        "  <h2>Declared vs observed</h2>\n"
        '  <div class="table-wrap">\n'
        '  <table class="scope">\n'
        "    <thead><tr><th>Capability</th><th>Declared</th>"
        "<th>Observed</th><th>Disposition</th></tr></thead>\n"
        f"    <tbody>\n{rows}\n    </tbody>\n"
        "  </table>\n"
        "  </div>\n"
        "</section>"
    )


def _scope_row(row: ScopeRow) -> str:
    css = {
        "exceeded": "block",
        "supported": "ok",
        "unused": "warn",
        "not_evaluable": "muted",
    }.get(row.disposition, "muted")
    return (
        "    <tr>\n"
        f"      <td><code>{_esc(row.capability)}</code></td>\n"
        f"      <td>{'yes' if row.declared else '&mdash;'}</td>\n"
        f"      <td>{'yes' if row.observed else '&mdash;'}</td>\n"
        f'      <td><span class="chip {css}">{_esc(row.disposition)}</span></td>\n'
        "    </tr>"
    )


def _limitations(summary: Summary) -> str:
    items = "\n".join(f"    <li>{_esc(line)}</li>" for line in summary.limitations)
    return (
        '<section class="block-section limitations">\n'
        "  <h2>Limitations</h2>\n"
        f"  <ul>\n{items}\n  </ul>\n"
        "</section>"
    )


def _provenance(summary: Summary) -> str:
    return (
        '<footer class="provenance muted-text">\n'
        f"  <div>eval <code>{_esc(summary.eval_id)}</code> &middot; "
        f"generated {_esc(summary.created_at)} &middot; "
        f"bellwether {_esc(summary.bellwether_version)} &middot; "
        f"summary schema {_esc(summary.schema_version)}</div>\n"
        f"  <div>package <code>{_esc(summary.skill.package_digest)}</code></div>\n"
        f"  <div>policy <code>{_esc(summary.policy.digest)}</code></div>\n"
        "</footer>"
    )


# ---------------------------------------------------------------------------
# Document shell
# ---------------------------------------------------------------------------


def _document(summary: Summary, body: str) -> str:
    title = f"Bellwether — {summary.skill.name} — {summary.verdict.status}"
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n"
        f"<style>\n{_CSS}\n</style>\n"
        "</head>\n"
        '<body>\n<main class="report">\n'
        f"{body}\n"
        "</main>\n</body>\n</html>\n"
    )


#: All styling, inlined. Palette is defined on bare ``:root`` (light) and swapped whole
#: under ``prefers-color-scheme: dark`` so no colour has its only definition in a media
#: block. Every semantic colour (ok/warn/block/muted) has a light and a dark value.
_CSS = """\
:root {
  --bg: #f7f7f8; --panel: #ffffff; --ink: #1c1d21; --muted: #6b6d76;
  --line: #e2e3e8; --accent: #3b4bd8;
  --ok-bg: #e6f4ea; --ok-fg: #1a7f37; --ok-line: #a6d8b5;
  --warn-bg: #fdf3e1; --warn-fg: #9a6700; --warn-line: #eccf9a;
  --block-bg: #fce8e8; --block-fg: #b0281a; --block-line: #f0b3ac;
  --muted-bg: #eeeff2; --muted-fg: #6b6d76; --muted-line: #d7d9df;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #16171b; --panel: #1e2025; --ink: #e8e9ec; --muted: #9aa0ad;
    --line: #2c2f36; --accent: #8f9bff;
    --ok-bg: #14301f; --ok-fg: #52c882; --ok-line: #285e3d;
    --warn-bg: #33280f; --warn-fg: #e2b25a; --warn-line: #5c4a20;
    --block-bg: #3a1a17; --block-fg: #f08a7e; --block-line: #6b2f28;
    --muted-bg: #24262c; --muted-fg: #9aa0ad; --muted-line: #363942;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.9em; }
.report { max-width: 880px; margin: 0 auto; padding: 24px 20px 64px; }
h1, h2 { margin: 0; font-weight: 650; }
h2 { font-size: 1.05rem; margin-bottom: 12px; letter-spacing: 0.01em; }
p { margin: 0.4em 0; }
.banner {
  display: flex; gap: 18px; align-items: center; padding: 20px 22px;
  border: 1px solid var(--line); border-left-width: 6px; border-radius: 12px;
  background: var(--panel); margin-bottom: 20px;
}
.banner.ok { border-left-color: var(--ok-fg); }
.banner.warn { border-left-color: var(--warn-fg); }
.banner.block { border-left-color: var(--block-fg); }
.verdict-glyph { font-size: 2.6rem; line-height: 1; }
.banner.ok .verdict-glyph { color: var(--ok-fg); }
.banner.warn .verdict-glyph { color: var(--warn-fg); }
.banner.block .verdict-glyph { color: var(--block-fg); }
.eyebrow { text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.7rem; color: var(--muted); }
.verdict { font-size: 1.9rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 24px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
.card-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
.card-value { font-size: 1.5rem; font-weight: 650; margin: 4px 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.card-detail { font-size: 0.82rem; color: var(--muted); }
.block-section { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; margin-bottom: 18px; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: none; }
.chip { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; border: 1px solid transparent; white-space: nowrap; }
.chip.ok { background: var(--ok-bg); color: var(--ok-fg); border-color: var(--ok-line); }
.chip.warn { background: var(--warn-bg); color: var(--warn-fg); border-color: var(--warn-line); }
.chip.block { background: var(--block-bg); color: var(--block-fg); border-color: var(--block-line); }
.chip.muted { background: var(--muted-bg); color: var(--muted-fg); border-color: var(--muted-line); }
.muted-text { color: var(--muted); }
.legend { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.strip-rows { display: flex; flex-direction: column; gap: 8px; }
.strip-row { display: grid; grid-template-columns: minmax(120px, 1fr) auto; gap: 4px 14px; align-items: center; }
.strip-label { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; }
.strip-cells { grid-column: 1 / -1; display: flex; flex-wrap: wrap; gap: 3px; align-items: center; }
.strip-tail { grid-column: 1 / -1; font-size: 0.78rem; }
.cell { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 5px; font-size: 0.8rem; border: 1px solid transparent; }
.cell.ok { background: var(--ok-bg); color: var(--ok-fg); border-color: var(--ok-line); }
.cell.warn { background: var(--warn-bg); color: var(--warn-fg); border-color: var(--warn-line); }
.cell.block { background: var(--block-bg); color: var(--block-fg); border-color: var(--block-line); }
.cell.muted { background: var(--muted-bg); color: var(--muted-fg); border-color: var(--muted-line); }
.look-boundary { width: 2px; height: 22px; background: var(--accent); border-radius: 2px; margin: 0 2px; opacity: 0.7; }
.heatmap tr.group td { background: var(--muted-bg); font-weight: 600; }
.heatmap td.hit { color: var(--accent); text-align: center; font-size: 1rem; }
.heatmap td.miss { color: var(--muted); text-align: center; }
.limitations ul { margin: 0; padding-left: 20px; color: var(--muted); font-size: 0.86rem; }
.limitations li { margin: 3px 0; }
.provenance { margin-top: 22px; font-size: 0.76rem; line-height: 1.7; word-break: break-all; }
"""
