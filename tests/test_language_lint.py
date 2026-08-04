"""The §16.3 language-discipline rule, and the package's compliance with it.

The verdict vocabulary must not imply proof. This rule is enforced in CI rather than by
convention, and it fails the build.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from language_lint import DEFAULT_ROOTS, check_paths, main

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_the_package_itself_is_clean() -> None:
    roots = [REPO_ROOT / part for part in DEFAULT_ROOTS]
    findings = check_paths(roots)
    assert findings == [], "\n".join(finding.render(REPO_ROOT) for finding in findings)


def test_main_returns_zero_for_the_package() -> None:
    assert main([str(REPO_ROOT / part) for part in DEFAULT_ROOTS]) == 0


@pytest.mark.parametrize("word", ["safe", "secure", "verified", "approved", "certified"])
def test_each_banned_word_is_caught_in_a_string_literal(tmp_path: Path, word: str) -> None:
    path = _write(tmp_path, "m.py", f'MESSAGE = "this skill is {word}"\n')
    findings = check_paths([path])
    assert [finding.word for finding in findings] == [word]


def test_a_banned_word_is_caught_in_a_docstring(tmp_path: Path) -> None:
    path = _write(tmp_path, "m.py", '"""Render the verdict as approved."""\n')
    assert len(check_paths([path])) == 1


def test_a_banned_word_is_caught_in_a_shipped_template(tmp_path: Path) -> None:
    path = _write(tmp_path, "t.yaml", "note: the result is secure\n")
    assert len(check_paths([path])) == 1


def test_matching_is_whole_word_so_ordinary_vocabulary_survives(tmp_path: Path) -> None:
    """``security_runtime`` is a gate name and ``verify`` is what doctor does."""
    path = _write(
        tmp_path,
        "m.py",
        'A = "security_runtime gate"\nB = "doctor will verify interception"\nC = "safety margin"\n',
    )
    assert check_paths([path]) == []


def test_comments_are_not_user_facing(tmp_path: Path) -> None:
    path = _write(tmp_path, "m.py", "# this note is safe to ignore\nX = 1\n")
    assert check_paths([path]) == []


def test_an_allow_marker_with_a_reason_suppresses_the_finding(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "m.py",
        'LIMIT = "Bellwether does not prove a skill is safe"  # bw-lang-ok: quoting §2\n',
    )
    assert check_paths([path]) == []


def test_an_allow_marker_without_a_reason_is_itself_an_error(tmp_path: Path) -> None:
    path = _write(tmp_path, "m.py", 'LIMIT = "a safe result"  # bw-lang-ok\n')
    findings = check_paths([path])
    assert len(findings) == 1
    assert "must give a reason" in findings[0].context


def test_a_multiline_literal_is_suppressed_by_a_marker_on_any_of_its_lines(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        "m.py",
        'TEXT = """\nnot safe\n"""  # bw-lang-ok: quoting the §2 limitations verbatim\n',
    )
    assert check_paths([path]) == []


def test_findings_render_with_path_line_and_rule(tmp_path: Path) -> None:
    path = _write(tmp_path, "m.py", 'X = 1\nY = "certified"\n')
    rendered = check_paths([path])[0].render(tmp_path)
    assert rendered.startswith("m.py:2:")
    assert "BW001" in rendered
    assert "§16.3" in rendered
