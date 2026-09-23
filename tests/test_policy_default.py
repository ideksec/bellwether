"""``--policy`` defaults to the policy beside ``--config`` (release review, 2026-09).

The README's quickstart runs ``bellwether doctor --config /path/to/skills-repo/.bellwether/
config.yaml`` — from anywhere. The policy default was ``.bellwether/policy.yaml`` relative to the
*working directory*, so the first command a newcomer types failed with "file not found" (exit 3)
unless run from inside the skills repository. ``init`` writes the two files side by side, so that
is where the default now looks.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from bellwether.cli.app import app

runner = CliRunner()


def test_the_quickstart_doctor_reads_the_policy_beside_the_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "skills-repo"
    assert runner.invoke(app, ["init", str(repo)]).exit_code == 0
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    result = runner.invoke(
        app, ["doctor", "--config", str(repo / ".bellwether" / "config.yaml"), "--json"]
    )

    assert result.exit_code == 0, result.output
    assert '"policy.yaml parses"' in result.output
    assert "file not found" not in result.output


def test_an_explicit_policy_still_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "skills-repo"
    assert runner.invoke(app, ["init", str(repo)]).exit_code == 0
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(repo / ".bellwether" / "config.yaml"),
            "--policy",
            str(tmp_path / "missing.yaml"),
        ],
    )
    assert result.exit_code != 0
