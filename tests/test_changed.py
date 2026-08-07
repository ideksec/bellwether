"""Attributing changed files to skills (§18) — so CI evaluates only what a PR touched.

The property that matters: a change *inside* a skill (its SKILL.md, its manifest, a reference
file) counts as that skill; a change *outside* every skill counts as nothing; a deleted skill
is never handed back. Getting this wrong means either re-running every skill on every push
(burning budget and attaching verdicts to untouched skills) or missing a changed one.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from bellwether.cli.changed import changed_skills, skill_dir_for


def _make_skill(root: Path, rel: str) -> None:
    directory = root / rel
    (directory / "evals").mkdir(parents=True, exist_ok=True)
    (directory / "SKILL.md").write_text(
        "---\nname: s\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    (directory / "evals" / "manifest.yaml").write_text("kind: SkillManifest\n", encoding="utf-8")


def test_a_change_to_skill_md_is_that_skill(tmp_path: Path) -> None:
    _make_skill(tmp_path, "skills/alpha")
    assert changed_skills(["skills/alpha/SKILL.md"], root=tmp_path) == [
        PurePosixPath("skills/alpha")
    ]


def test_a_change_under_the_skill_is_attributed_to_it(tmp_path: Path) -> None:
    """The manifest and progressive-disclosure files live beside SKILL.md; touching them
    changes the skill's declared scope or behaviour, so they count."""
    _make_skill(tmp_path, "skills/alpha")
    assert changed_skills(["skills/alpha/evals/manifest.yaml"], root=tmp_path) == [
        PurePosixPath("skills/alpha")
    ]


def test_a_change_outside_every_skill_touches_nothing(tmp_path: Path) -> None:
    _make_skill(tmp_path, "skills/alpha")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("x", encoding="utf-8")
    assert changed_skills(["docs/guide.md", "README.md"], root=tmp_path) == []


def test_multiple_changes_in_one_skill_collapse(tmp_path: Path) -> None:
    _make_skill(tmp_path, "skills/alpha")
    changed = changed_skills(
        ["skills/alpha/SKILL.md", "skills/alpha/evals/manifest.yaml"], root=tmp_path
    )
    assert changed == [PurePosixPath("skills/alpha")]


def test_a_new_skill_is_detected(tmp_path: Path) -> None:
    """A PR that adds a skill lists its new SKILL.md; the file exists on disk, so it counts."""
    _make_skill(tmp_path, "skills/brandnew")
    assert changed_skills(["skills/brandnew/SKILL.md"], root=tmp_path) == [
        PurePosixPath("skills/brandnew")
    ]


def test_a_deleted_skill_is_not_returned(tmp_path: Path) -> None:
    """The diff still names the removed SKILL.md, but it is gone on disk — there is nothing
    left to evaluate, so it must not come back as work."""
    assert changed_skills(["skills/gone/SKILL.md"], root=tmp_path) == []
    assert skill_dir_for("skills/gone/SKILL.md", root=tmp_path) is None


def test_result_is_sorted_and_deduplicated(tmp_path: Path) -> None:
    for name in ("skills/charlie", "skills/alpha", "skills/bravo"):
        _make_skill(tmp_path, name)
    changed = changed_skills(
        [
            "skills/charlie/SKILL.md",
            "skills/alpha/evals/manifest.yaml",
            "skills/bravo/SKILL.md",
            "skills/alpha/SKILL.md",
        ],
        root=tmp_path,
    )
    assert [str(skill) for skill in changed] == ["skills/alpha", "skills/bravo", "skills/charlie"]


def test_blank_and_whitespace_paths_are_ignored(tmp_path: Path) -> None:
    _make_skill(tmp_path, "skills/alpha")
    assert changed_skills(["", "   ", "skills/alpha/SKILL.md"], root=tmp_path) == [
        PurePosixPath("skills/alpha")
    ]
