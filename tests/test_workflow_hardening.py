"""The CI workflows' own inputs cannot hide a skill or spend without the label (release review).

Four workflow defects the review reproduced, each pinned here at the two places they live — the
``changed-skills`` command the workflow pipes the diff into, and the workflow files themselves:

* ``git diff --name-only`` C-quotes a path with a non-ASCII byte (``"caf\\303\\251/SKILL.md"``);
  ``changed-skills`` attributed the quoted line to nothing, so a skill under such a directory was
  never evaluated and the job reported "no skills changed";
* ``$GITHUB_OUTPUT`` used the fixed heredoc delimiter ``EOF``, which a skill directory named
  ``EOF`` terminates early;
* the ``labeled`` trigger had no filter, so adding *any* label re-ran the paid evaluation, and the
  workflow-level concurrency group cancelled the one in flight;
* ``actions/checkout`` left the job token in ``.git/config`` on a runner that then runs evaluated
  skill content.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from bellwether.cli.app import app

_ROOT = Path(__file__).resolve().parents[1]
_LIVE = (".github/workflows/bellwether.yml", ".github/workflows/bellwether-claude-code.yml")
_SKILL = "---\nname: s\ndescription: d\n---\nbody\n"
runner = CliRunner()


def _skills(tmp_path: Path, *names: str) -> None:
    for name in names:
        (tmp_path / name).mkdir(parents=True)
        (tmp_path / name / "SKILL.md").write_text(_SKILL, encoding="utf-8")


def _git_diff(tmp_path: Path, *extra: str) -> bytes:
    def git(*args: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(tmp_path), *args], check=True, capture_output=True
        ).stdout

    git("init", "-q")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "b")
    git("add", "-A")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "a")
    return git("diff", "--name-only", *extra, "HEAD~1", "HEAD")


def test_a_non_ascii_skill_directory_is_found_through_the_nul_separated_diff(
    tmp_path: Path,
) -> None:
    _skills(tmp_path, "café", "plain")
    diff = _git_diff(tmp_path, "-z")
    result = runner.invoke(
        app, ["changed-skills", "-z", "--root", str(tmp_path)], input=diff.decode("utf-8")
    )
    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == ["café", "plain"]


def test_a_c_quoted_path_is_refused_not_dropped(tmp_path: Path) -> None:
    _skills(tmp_path, "café", "plain")
    diff = _git_diff(tmp_path)  # no -z: git quotes the non-ASCII path
    assert b'"caf' in diff
    result = runner.invoke(
        app, ["changed-skills", "--root", str(tmp_path)], input=diff.decode("utf-8")
    )
    assert result.exit_code == 3
    assert "C-quoted" in result.output


def test_a_skill_name_with_a_line_break_is_refused(tmp_path: Path) -> None:
    _skills(tmp_path, "evil\nforged")
    result = runner.invoke(
        app, ["changed-skills", "-z", "--root", str(tmp_path)], input="evil\nforged/SKILL.md\0"
    )
    assert result.exit_code == 3
    assert "line break" in result.output


@pytest.mark.parametrize("workflow", _LIVE)
def test_the_live_workflow_diffs_nul_separated_and_uses_a_random_delimiter(workflow: str) -> None:
    detect = next(
        step
        for step in yaml.safe_load((_ROOT / workflow).read_text(encoding="utf-8"))["jobs"][
            "evaluate"
        ]["steps"]
        if step.get("id") == "detect"
    )["run"]
    assert "git diff --name-only -z" in detect
    assert "changed-skills -z" in detect
    assert "<<EOF" not in detect and "openssl rand" in detect


@pytest.mark.parametrize("workflow", _LIVE)
def test_only_the_run_label_starts_or_cancels_a_paid_evaluation(workflow: str) -> None:
    document = yaml.safe_load((_ROOT / workflow).read_text(encoding="utf-8"))
    job = document["jobs"]["evaluate"]
    assert "github.event.label.name == 'bellwether-run'" in job["if"]
    assert "concurrency" not in document, "workflow-level concurrency cancels from skipped runs"
    assert job["concurrency"]["cancel-in-progress"] is True


def test_no_checkout_leaves_the_token_on_disk() -> None:
    for workflow in sorted((_ROOT / ".github" / "workflows").glob("*.yml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        for name, job in document["jobs"].items():
            for step in job.get("steps", []):
                if "actions/checkout@" in str(step.get("uses", "")):
                    assert step.get("with", {}).get("persist-credentials") is False, (
                        f"{workflow.name}:{name} persists the job token in .git/config"
                    )
