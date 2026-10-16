"""The Markdown summary of a static scan (§15, §18.2) — for a job summary or a PR comment.

``bellwether scan --markdown`` writes it; the Gate 0 workflow appends it to the job's step
summary, which is where a reviewer looks first. Like the PR comment, most of what it prints was
chosen by the skill under scan — its name, its file paths, the excerpts of its own text, and an
external scanner's messages about it — so every dynamic value goes through :mod:`mdsafe`. A skill
cannot forge a heading, a table row, a link, an image, HTML or a mention here any more than it
can in the PR comment, and the tests parse the output to hold it to that.

Shape: one status heading for the whole scan, one summary row per skill, and per skill a
collapsed table of its findings (expanded when it has any above its threshold). Unscanned files
and notes are listed beside the findings, because an absence of findings is only worth what the
scan read.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from bellwether.report.mdsafe import code, html_text, text
from bellwether.scan import ScanReport, severity_rank

__all__ = ["SCAN_MARKER", "ScanSummaryEntry", "render_scan_markdown"]

#: The first line of every summary; a comment upsert keys on it (like ``bellwether-report``).
SCAN_MARKER = "<!-- bellwether-static -->"

#: Rows of one skill's findings table before the rest are counted rather than listed. A step
#: summary is capped at 1 MiB by GitHub; a skill with thousands of findings must not lose its
#: heading to the cap.
MAX_ROWS_PER_SKILL = 200

_ICON = {"critical": "🔴", "high": "🔴", "medium": "🟡", "low": "⚪", "info": "⚪"}


@dataclass(frozen=True)
class ScanSummaryEntry:
    """One scanned skill: what it is, what it was held to, and what the scan found."""

    name: str
    root: str | None
    report: ScanReport
    threshold: str
    profile: str | None = None


def _blocking(entry: ScanSummaryEntry) -> int:
    return len(entry.report.above(entry.threshold))


def _skill_rows(entries: Sequence[ScanSummaryEntry]) -> list[str]:
    rows = [
        "| Skill | Directory | Profile | Threshold | Worst | Above threshold | Findings |",
        "|---|---|---|---|---|---|---|",
    ]
    for entry in entries:
        counts = entry.report.counts()
        total = sum(counts.values())
        blocking = _blocking(entry)
        rows.append(
            "| "
            + " | ".join(
                (
                    code(entry.name),
                    code(entry.root or "."),
                    code(entry.profile) if entry.profile else "—",
                    code(entry.threshold),
                    code(entry.report.worst or "none"),
                    f"**{blocking}**" if blocking else "0",
                    str(total),
                )
            )
            + " |"
        )
    return rows


def _findings_block(entry: ScanSummaryEntry) -> list[str]:
    report = entry.report
    ordered = sorted(
        report.findings,
        key=lambda f: (-severity_rank(f.severity), f.path, f.line, f.rule_id),
    )
    shown = ordered[:MAX_ROWS_PER_SKILL]
    opened = " open" if _blocking(entry) else ""
    lines = [
        f"<details{opened}>",
        # Raw HTML: Markdown escapes are not escapes here, so the name is entity-escaped.
        f"<summary>{html_text(entry.name)}: {len(ordered)} finding(s)</summary>",
        "",
    ]
    if shown:
        lines.extend(["| Severity | Rule | Location | Finding |", "|---|---|---|---|"])
        limit = severity_rank(entry.threshold)
        for finding in shown:
            above = severity_rank(finding.severity) > limit
            severity = f"{_ICON[finding.severity]} {code(finding.severity)}"
            if above:
                severity += " **above threshold**"
            detail = text(finding.message)
            if finding.excerpt:
                detail += f"<br>{code(finding.excerpt)}"
            lines.append(
                f"| {severity} | {code(finding.rule_id)} | "
                f"{code(f'{finding.path}:{finding.line}')} | {detail} |"
            )
        if len(ordered) > len(shown):
            lines.extend(
                ["", f"_{len(ordered) - len(shown)} more finding(s) not listed; see the SARIF._"]
            )
    else:
        lines.append("No findings.")
    unread = report.unscanned_outside_machinery()
    if unread or report.machinery_unscanned:
        lines.extend(["", "Not scanned:", ""])
        lines.extend(f"- {code(u.path)}: {text(u.reason)}" for u in unread)
        if report.machinery_unscanned:
            lines.append(
                f"- {report.machinery_unscanned} file(s) under {code('evals/')}: evaluation "
                "machinery, never installed with the skill"
            )
    if report.notes:
        lines.extend(["", "Notes:", ""])
        lines.extend(f"- {text(note)}" for note in report.notes)
    if report.scanners:
        lines.extend(["", "Delegated to: " + ", ".join(code(s) for s in report.scanners)])
    lines.extend(["", "</details>", ""])
    return lines


def render_scan_markdown(entries: Sequence[ScanSummaryEntry]) -> str:
    """The summary for ``entries``, in the order given (the caller sorts them)."""
    blocking = sum(_blocking(entry) for entry in entries)
    if not entries:
        heading = "## ⚪ Bellwether static scan: no skills to scan"
    elif blocking:
        heading = f"## 🔴 Bellwether static scan: {blocking} finding(s) above policy"
    else:
        heading = "## 🟢 Bellwether static scan: nothing above policy"
    lines = [SCAN_MARKER, heading, ""]
    if entries:
        rulesets = sorted({entry.report.ruleset for entry in entries})
        lines.append(
            f"Static scan (§15) of {len(entries)} skill(s) with "
            + ", ".join(code(r) for r in rulesets)
            + ". A finding above a skill's threshold fails this check; the behavioural "
            "evaluation is separate."
        )
        lines.append("")
        lines.extend(_skill_rows(entries))
        lines.append("")
        for entry in entries:
            lines.extend(_findings_block(entry))
    lines.append(
        "_A static scan reads text; it does not run the skill. An empty table says what these "
        "rules did not match, not how the skill behaves, and the built-in rules are deliberately "
        "small (§26.2)._"
    )
    return "\n".join(lines) + "\n"
