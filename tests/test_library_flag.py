"""The §19.3 coexistence flag: a pull request that changes a skill's description flags the
library for the next scheduled coexistence run, and the PR comment says so.

The comparison, its Markdown, the command, the comment key, and the `bellwether.yml` step
executed in the harness against a two-commit repository.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bellwether.cli.app import app
from bellwether.cli.library_flag import (
    FLAG_MARKER,
    SCHEDULE_HINT,
    DescriptionChange,
    description_changed,
    render_flag_markdown,
)
from bellwether.cli.pr import COEXISTENCE_FLAG_KEY, STATIC_SCAN_KEY, comment_marker
from bellwether.errors import BellwetherError
from tests.test_live_workflow_statuses import _run
from tests.workflow_harness import Event, FakeGitHub

_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


@pytest.fixture
def api() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    yield fake
    fake.close()


def _skill(root: Path, name: str, description: str, body: str = "x") -> None:
    directory = root / "examples" / "skills" / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n{body}\n", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# The comparison
# ---------------------------------------------------------------------------


def test_a_changed_description_flags_and_a_body_change_does_not(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    _skill(base, "a", "Counts lines.")
    _skill(head, "a", "Counts lines and words.")
    _skill(base, "b", "Compiles changelogs.", body="old body")
    _skill(head, "b", "Compiles changelogs.", body="new body")
    changes = description_changed(["examples/skills/a", "examples/skills/b"], head=head, base=base)
    assert changes == [
        DescriptionChange("examples/skills/a", "changed"),
        DescriptionChange("examples/skills/b", "unchanged"),
    ]


def test_a_reflow_of_the_same_description_is_not_a_change(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    _skill(base, "a", "Counts lines   in Markdown files.")
    _skill(head, "a", "Counts lines in Markdown   files.")
    [change] = description_changed(["examples/skills/a"], head=head, base=base)
    assert change.status == "unchanged"


def test_an_added_or_removed_skill_flags(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    _skill(head, "new", "Brand new.")
    _skill(base, "gone", "Was here.")
    changes = description_changed(
        ["examples/skills/new", "examples/skills/gone"], head=head, base=base
    )
    assert [c.status for c in changes] == ["added", "removed"]
    # No base tree at all: a first commit, where every skill is new.
    assert description_changed(["examples/skills/new"], head=head, base=None)[0].status == "added"


def test_a_directory_that_is_a_skill_in_neither_tree_is_refused(tmp_path: Path) -> None:
    (tmp_path / "head").mkdir()
    (tmp_path / "base").mkdir()
    with pytest.raises(BellwetherError, match="not a skill in either"):
        description_changed(["examples/skills/x"], head=tmp_path / "head", base=tmp_path / "base")


def test_a_skill_md_without_frontmatter_compares_as_an_empty_description(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    for root in (base, head):
        (root / "examples" / "skills" / "bare").mkdir(parents=True)
    (base / "examples/skills/bare/SKILL.md").write_text("no frontmatter\n", encoding="utf-8")
    (head / "examples/skills/bare/SKILL.md").write_text("still none\n", encoding="utf-8")
    [change] = description_changed(["examples/skills/bare"], head=head, base=base)
    assert change.status == "unchanged"


# ---------------------------------------------------------------------------
# The comment
# ---------------------------------------------------------------------------


def test_the_markdown_names_the_flagged_skills_and_when_the_schedule_resolves_it() -> None:
    text = render_flag_markdown(
        [
            DescriptionChange("examples/skills/a", "changed"),
            DescriptionChange("examples/skills/b", "unchanged"),
            DescriptionChange("examples/skills/c <img>", "added"),
        ]
    )
    assert text.startswith(FLAG_MARKER + "\n")
    assert "flagged for a coexistence re-run" in text
    assert "`examples/skills/a` changed its description" in text
    assert "`examples/skills/c <img>` is new" in text
    assert "examples/skills/b" not in text
    assert "does **not** run on a pull request" in text and "BELLWETHER_COEXISTENCE" in text
    # §19.3: the comment says *when* the scheduled run resolves the flag.
    assert SCHEDULE_HINT in text and "Bellwether coexistence" in text


def test_the_markdown_says_not_flagged_when_nothing_changed() -> None:
    text = render_flag_markdown([DescriptionChange("examples/skills/a", "unchanged")])
    assert text.startswith(FLAG_MARKER + "\n")
    assert "not flagged" in text


def test_the_flag_comment_has_its_own_key() -> None:
    assert COEXISTENCE_FLAG_KEY != STATIC_SCAN_KEY
    assert comment_marker(COEXISTENCE_FLAG_KEY) != comment_marker(STATIC_SCAN_KEY)


def test_pr_comment_recognises_the_flag_by_its_first_line(tmp_path: Path) -> None:
    flag = tmp_path / "flag.md"
    flag.write_text(render_flag_markdown([DescriptionChange("s", "changed")]), encoding="utf-8")
    result = runner.invoke(app, ["pr-comment", str(flag), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert result.output.rstrip().endswith(comment_marker(COEXISTENCE_FLAG_KEY))


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


def test_the_command_is_advisory_and_writes_the_comment(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    _skill(base, "a", "Counts lines.")
    _skill(head, "a", "Counts lines and words.")
    _skill(base, "b", "Same.")
    _skill(head, "b", "Same.")
    listing = tmp_path / "skills.txt"
    listing.write_text("examples/skills/a\nexamples/skills/b\n", encoding="utf-8")
    out = tmp_path / "flag.md"
    result = runner.invoke(
        app,
        [
            "description-changed",
            "--skills-from",
            str(listing),
            "--base",
            str(base),
            "--head",
            str(head),
            "--markdown",
            str(out),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "flagged": True,
        "changes": [
            {"skill": "examples/skills/a", "status": "changed"},
            {"skill": "examples/skills/b", "status": "unchanged"},
        ],
    }
    assert "flagged for a coexistence re-run" in out.read_text(encoding="utf-8")
    quiet = runner.invoke(
        app, ["description-changed", "examples/skills/b", "--base", str(base), "--head", str(head)]
    )
    assert quiet.exit_code == 0 and "not flagged" in quiet.output


def test_the_command_refuses_an_unreadable_listing(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["description-changed", "--skills-from", str(tmp_path / "missing.txt")]
    )
    assert result.exit_code == 3


# ---------------------------------------------------------------------------
# The workflow step
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _two_commits(
    tmp_path: Path, *, base_desc: str, head_desc: str, body_only: bool = False
) -> tuple[Path, str, str]:
    """A base commit with skill `a`, then a head commit changing its description (or body)."""
    import shutil

    repo = tmp_path / "repo"
    shutil.copytree(_ROOT / "examples" / "live", repo / "examples" / "live")
    _skill(repo, "a", base_desc)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _skill(repo, "a", base_desc if body_only else head_desc, body="changed body")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "head")
    return repo, base, _git(repo, "rev-parse", "HEAD")


def test_a_changed_description_posts_the_flag_comment(api: FakeGitHub, tmp_path: Path) -> None:
    repo, base, head = _two_commits(tmp_path, base_desc="Counts lines.", head_desc="Counts words.")
    runner_ = _run("bellwether.yml", repo, tmp_path, api, event=Event(base_sha=base, head_sha=head))
    assert not runner_.failed, [(r.name, r.output[-400:]) for r in runner_.results if r.returncode]
    assert "Coexistence flag" in runner_.ran()
    flag = [c for c in api.comments if c["body"].startswith(FLAG_MARKER)]
    assert len(flag) == 1
    assert "`examples/skills/a` changed its description" in flag[0]["body"]
    assert flag[0]["body"].rstrip().endswith(comment_marker(COEXISTENCE_FLAG_KEY))
    assert "flagged for a coexistence re-run" in runner_.summary.read_text(encoding="utf-8")


def test_a_body_only_change_posts_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    repo, base, head = _two_commits(
        tmp_path, base_desc="Counts lines.", head_desc="Counts lines.", body_only=True
    )
    runner_ = _run("bellwether.yml", repo, tmp_path, api, event=Event(base_sha=base, head_sha=head))
    assert not runner_.failed, [(r.name, r.output[-400:]) for r in runner_.results if r.returncode]
    assert "Coexistence flag" in runner_.ran()
    # --update-only: never red before, so no comment is created.
    assert not [c for c in api.comments if c["body"].startswith(FLAG_MARKER)]
    assert "not flagged" in runner_.summary.read_text(encoding="utf-8")


def test_a_fork_gets_no_flag_comment(api: FakeGitHub, tmp_path: Path) -> None:
    repo, base, head = _two_commits(tmp_path, base_desc="Counts lines.", head_desc="Counts words.")
    runner_ = _run(
        "bellwether.yml", repo, tmp_path, api, event=Event(base_sha=base, head_sha=head, fork=True)
    )
    assert "Coexistence flag" not in runner_.ran()
    assert api.comments == []
