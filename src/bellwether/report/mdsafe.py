"""Text that reaches the PR comment, made inert (§17.4).

The PR comment is posted by the workflow's bot, on the pull request whose skill is being judged,
and much of what it prints was chosen by that skill: its declared name, the file paths and argv
it touched, the tool names it called, and every reason or finding that quotes one of them. The
renderer interpolated all of it verbatim, so a skill that ran ``bash -c "x\\n## 🟢 Bellwether
verdict: `ready` @team"`` once got a second, bot-authored verdict heading and a live mention in
the comment that was reporting it ``not_ready``. The HTML report escaped every value; the
Markdown one escaped none.

Two helpers, and every dynamic value goes through one of them:

* :func:`code` — a value shown *as data* (a path, a capability, an argv). A code span whose
  fence is longer than any backtick run in the value, so no content can close it; line breaks
  are shown as ``⏎`` rather than taken, so no content can start a line of its own. GitHub does
  not resolve mentions or references inside code.
* :func:`text` — a value shown inside prose or a table cell (a gate reason, a finding, a note).
  One line, Markdown and HTML metacharacters backslash-escaped, ``@`` kept from mentioning.

:func:`fence` does the same for a fenced block. Same reduce-then-compare rule as the rest of
the project: the value is reduced to something that cannot be anything but text, rather than
checked against a list of the ways it might not be.
"""

from __future__ import annotations

import re

__all__ = ["code", "fence", "one_line", "text"]

#: Everything a Markdown or HTML renderer treats as a line break or a control. Shown, not taken.
_LINE_BREAKS = re.compile(r"\r\n|[\r\n\v\f\x85\u2028\u2029]")
_CONTROLS = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")
#: Inline Markdown and HTML metacharacters. Escaped wherever they appear, so no value can open
#: emphasis, a link or image, a tag, an entity, a table cell or a code span of its own.
_METACHARACTERS = re.compile(r"([\\`*_\[\]<>|~&])")
#: A mention is ``@`` followed by a name. A zero-width joiner after the ``@`` renders the same
#: glyphs and resolves nothing — no notification, no team ping.
_MENTION = re.compile(r"@(?=\w)")
_JOINER = "@\u2060"


def one_line(value: object) -> str:
    """``value`` on one line: breaks shown as ``⏎``, other controls as U+FFFD. For a label
    inside a fenced block, where escaping would print the backslashes but a line break would
    still forge a row."""
    return _CONTROLS.sub("\ufffd", _LINE_BREAKS.sub("⏎", str(value)))


def code(value: object) -> str:
    """``value`` as an inline code span no content can close or break out of."""
    shown = one_line(value)
    if not shown:
        return "` `"
    longest = max((len(run) for run in re.findall(r"`+", shown)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if shown.startswith("`") or shown.endswith("`") else ""
    return f"{ticks}{pad}{shown}{pad}{ticks}"


def text(value: object) -> str:
    """``value`` as inert prose: one line, metacharacters escaped, mentions defused."""
    escaped = _METACHARACTERS.sub(r"\\\1", one_line(value))
    return _MENTION.sub(_JOINER, escaped)


def fence(body: str) -> str:
    """``body`` as a fenced block no line of it can close.

    ``body`` may span lines — that is what a block is for — but a line inside it that is a
    run of backticks at least as long as the fence would end the block early and let the rest
    render as Markdown. The fence is made longer than any backtick run in the body.
    """
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}\n{body}\n{ticks}"
