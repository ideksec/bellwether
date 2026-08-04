"""CLI surface and exit codes (§20). Everything here runs offline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bellwether.cli import ExitCode, app
from bellwether.config import load_config, load_policy

runner = CliRunner()


def test_help_runs() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "bellwether" in result.output


@pytest.mark.parametrize(
    "command",
    ["version", "init", "doctor", "run", "scan", "probe", "coexistence", "diff", "report", "trace"],
)
def test_every_command_has_help(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0


def test_version_json_is_machine_readable() -> None:
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == ExitCode.OK
    payload = json.loads(result.output)
    assert payload["arf_version"] and payload["bellwether"]


def test_init_writes_a_scaffold_that_loads(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == ExitCode.OK

    config_path = tmp_path / ".bellwether" / "config.yaml"
    policy_path = tmp_path / ".bellwether" / "policy.yaml"
    assert load_config(config_path).sandbox.backend == "docker"
    assert sorted(load_policy(policy_path).profiles) == ["high", "low", "medium"]
    assert (tmp_path / ".bellwether" / "platform-baseline.yaml").exists()
    assert (tmp_path / ".bellwether" / "baselines" / ".gitkeep").exists()


def test_init_does_not_overwrite_without_force(tmp_path: Path) -> None:
    runner.invoke(app, ["init", str(tmp_path)])
    config_path = tmp_path / ".bellwether" / "config.yaml"
    config_path.write_text("# edited by the repository owner\n", encoding="utf-8")

    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == ExitCode.OK
    assert config_path.read_text(encoding="utf-8") == "# edited by the repository owner\n"

    forced = runner.invoke(app, ["init", str(tmp_path), "--force"])
    assert forced.exit_code == ExitCode.OK
    assert "apiVersion" in config_path.read_text(encoding="utf-8")


def test_doctor_passes_on_a_fresh_scaffold(tmp_path: Path) -> None:
    runner.invoke(app, ["init", str(tmp_path)])
    result = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(tmp_path / ".bellwether" / "config.yaml"),
            "--policy",
            str(tmp_path / ".bellwether" / "policy.yaml"),
            "--json",
        ],
    )
    assert result.exit_code == ExitCode.OK
    payload = json.loads(result.output)
    assert payload["blocking_problems"] == 0
    statuses = {check["check"]: check["status"] for check in payload["checks"]}
    assert statuses["config.yaml parses"] == "ok"
    # The environment probes are listed as pending with the package that brings them,
    # rather than silently absent — a doctor that omits a check it cannot run reads as
    # a doctor that ran it (§20).
    assert any(check["status"] == "pending" for check in payload["checks"])


def test_doctor_refuses_a_disabled_enforced_setting(tmp_path: Path) -> None:
    runner.invoke(app, ["init", str(tmp_path)])
    config_path = tmp_path / ".bellwether" / "config.yaml"
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "  mode: controlled_resolver", "  mode: 'off'"
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config_path),
            "--policy",
            str(tmp_path / ".bellwether" / "policy.yaml"),
        ],
    )
    assert result.exit_code == ExitCode.INFRASTRUCTURE
    assert "UDP/53" in result.output


def test_doctor_reports_a_bad_config_as_an_infrastructure_error(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("apiVersion: bellwether/v1\nkind: Config\n", encoding="utf-8")
    result = runner.invoke(app, ["doctor", "--config", str(config_path)])
    assert result.exit_code == ExitCode.INFRASTRUCTURE


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("run", []),
        ("scan", []),
        ("probe", ["./somewhere"]),
        ("coexistence", []),
        ("init-manifest", ["a-skill"]),
        ("trace", ["run-1"]),
        ("report", ["eval-1"]),
        ("diff", ["a", "b"]),
    ],
)
def test_unimplemented_commands_exit_three_and_name_their_work_package(
    command: str, args: list[str]
) -> None:
    """Exit 3 is "could not evaluate". An empty result would read as a clean run."""
    result = runner.invoke(app, [command, *args])
    assert result.exit_code == ExitCode.INFRASTRUCTURE
    assert "not implemented" in result.output


def test_exit_codes_follow_the_spec() -> None:
    """§20: 0 covers ready and conditional; 2 is not_ready; 3 is infrastructure."""
    assert (ExitCode.OK, ExitCode.NOT_READY, ExitCode.INFRASTRUCTURE) == (0, 2, 3)
    assert 1 not in {int(code) for code in ExitCode}
