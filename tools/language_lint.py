#!/usr/bin/env python3
"""Language discipline lint (spec §16.3).

The verdict vocabulary must not imply proof. Bellwether reports ``ready`` /
``conditional`` / ``not_ready``, meaning "met the configured gates on the evidence
collected" — not that anything was proven about the skill. N runs produce a distribution.

§16.3 requires this to be enforced by a lint rule over user-facing strings in CI, not by
convention alone, and requires the rule to fail the build. Templates, docstrings, report
templates, and CLI help text are all in scope.

Scope and the escape hatch
--------------------------
Scanned: string literals (including docstrings and f-string parts) in the package, and
every line of the shipped templates and report assets.

Not scanned: prose documentation and tests. §2 *requires* the README and the report
footer to say Bellwether does not prove a skill is safe — a rule that forbade the word
everywhere would forbid the disclaimer, which is the opposite of the intent. The rule
guards the strings Bellwether emits about a *result*.

Where a banned word genuinely belongs in a scanned file, mark the line::

    "... does not prove a skill is safe"  # bw-lang-ok: quoting the §2 limitation

A marker without a reason is itself an error: the point is that someone had to think.

Usage::

    python tools/language_lint.py [PATH ...]
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

RULE = "BW001"

#: Words that claim more than a distribution over N runs can support (§16.3).
BANNED_WORDS: tuple[str, ...] = (
    "safe",  # bw-lang-ok: this is the rule's own word list
    "secure",  # bw-lang-ok: this is the rule's own word list
    "verified",  # bw-lang-ok: this is the rule's own word list
    "approved",  # bw-lang-ok: this is the rule's own word list
    "certified",  # bw-lang-ok: this is the rule's own word list
)

_BANNED_RE = re.compile(r"\b(" + "|".join(BANNED_WORDS) + r")\b", re.IGNORECASE)
_ALLOW_RE = re.compile(r"bw-lang-ok\s*:\s*(?P<reason>\S.*)$")
_ALLOW_BARE_RE = re.compile(r"bw-lang-ok\b")

#: Default roots. The package's own strings and everything it ships as a template.
DEFAULT_ROOTS: tuple[str, ...] = ("src/bellwether",)

#: Extensions scanned line-by-line rather than through the Python AST.
TEXT_SUFFIXES: frozenset[str] = frozenset({".yaml", ".yml", ".j2", ".jinja", ".html", ".txt"})


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    column: int
    word: str
    context: str

    def render(self, root: Path) -> str:
        try:
            shown = self.path.relative_to(root)
        except ValueError:
            shown = self.path
        return (
            f"{shown}:{self.line}:{self.column}: {RULE} "
            f"the word {self.word!r} implies proof and must not appear in a user-facing "
            f"string (§16.3) — {self.context}"
        )


def _line_is_allowed(line: str) -> tuple[bool, str | None]:
    """Return ``(allowed, error)`` for a line carrying an allow marker."""
    if not _ALLOW_BARE_RE.search(line):
        return False, None
    match = _ALLOW_RE.search(line)
    if match is None:
        return False, "a 'bw-lang-ok' marker must give a reason, e.g. 'bw-lang-ok: quoting §2'"
    return True, None


def check_text(path: Path, text: str, *, context: str) -> Iterator[Finding]:
    for number, line in enumerate(text.splitlines(), start=1):
        allowed, marker_error = _line_is_allowed(line)
        if marker_error:
            yield Finding(path, number, 1, "bw-lang-ok", marker_error)
            continue
        if allowed:
            continue
        for match in _BANNED_RE.finditer(line):
            yield Finding(path, number, match.start() + 1, match.group(0), context)


def check_python(path: Path, source: str) -> Iterator[Finding]:
    lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:  # ruff and mypy will report this properly; do not double up
        yield Finding(path, exc.lineno or 1, exc.offset or 1, "?", f"could not be parsed: {exc}")
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        matches = list(_BANNED_RE.finditer(node.value))
        if not matches:
            continue
        start = node.lineno
        end = node.end_lineno or start
        for number in range(start, min(end, len(lines)) + 1):
            allowed, marker_error = _line_is_allowed(lines[number - 1])
            if marker_error:
                yield Finding(path, number, 1, "bw-lang-ok", marker_error)
            if allowed or marker_error:
                break
        else:
            for match in matches:
                yield Finding(
                    path,
                    _line_of_offset(node, match.start()),
                    1,
                    match.group(0),
                    "in a string literal",
                )


def _line_of_offset(node: ast.Constant, offset: int) -> int:
    """Best-effort line for a match inside a possibly multi-line literal."""
    text = node.value
    if not isinstance(text, str):
        return node.lineno
    return node.lineno + text.count("\n", 0, offset)


def iter_files(roots: Iterable[Path]) -> Iterator[Path]:
    for root in roots:
        if root.is_file():
            yield root
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix == ".py" or path.suffix in TEXT_SUFFIXES:
                yield path


def check_paths(roots: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(roots):
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".py":
            findings.extend(check_python(path, text))
        else:
            findings.extend(check_text(path, text, context="in a shipped template"))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("paths", nargs="*", type=Path, help="files or directories to check")
    args = parser.parse_args(argv)

    root = Path.cwd()
    roots = args.paths or [root / part for part in DEFAULT_ROOTS]
    findings = check_paths(roots)

    for finding in findings:
        print(finding.render(root), file=sys.stderr)

    if findings:
        count = len(findings)
        noun = "problem" if count == 1 else "problems"
        print(
            f"\n{count} language-discipline {noun}. Bellwether reports ready / conditional / "
            "not_ready; it does not vouch. See spec §16.3.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
