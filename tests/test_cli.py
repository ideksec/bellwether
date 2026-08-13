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
    [
        "version",
        "init",
        "doctor",
        "run",
        "demo",
        "pr-comment",
        "changed-skills",
        "scan",
        "probe",
        "coexistence",
        "diff",
        "report",
        "trace",
    ],
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


def test_doctor_actually_probes_docker_and_overlayfs(tmp_path: Path) -> None:
    """§20: doctor "MUST actively verify — not assume".

    `DockerBackend.available()` and `overlay_available()` were written with reason strings
    shaped for this output and then not called from it, leaving the two checks listed as
    pending long after the machinery existed.
    """
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
    checks = {check["check"]: check for check in json.loads(result.output)["checks"]}

    for name in ("docker daemon reachable", "host-side overlay upper dir obtainable"):
        assert name in checks, f"{name} is not probed"
        assert checks[name]["status"] in ("ok", "warn")
        # Whether or not it is available, the reason must be actionable — never an enum
        # on its own (§10.7).
        assert checks[name]["detail"].strip()
        assert checks[name]["status"] != "pending"


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


def test_doctor_warns_that_most_runtime_dispositions_do_not_gate_yet(tmp_path: Path) -> None:
    """§16.2 / BW-49: only `egress_outside_allowlist` drives the scored verdict in this version. The
    scaffold policy sets `canary_leak: block`, `dns_outside_allowlist: block`, and more — controls
    that read as active but do not gate. Doctor must surface exactly which are inert, the same way it
    surfaces require_scan, so a `block` there is never mistaken for enforcement (a silent no-op is how
    a control that does nothing looks like one that works)."""
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
    checks = {check["check"]: check for check in json.loads(result.output)["checks"]}
    assert "runtime security dispositions (§16.2)" in checks
    runtime = checks["runtime security dispositions (§16.2)"]
    assert runtime["status"] == "warn"
    # The comma-separated list of inert dispositions sits between "not_ready: " and ". Treat".
    inert_list = runtime["detail"].split("not_ready: ", 1)[1].split(". ", 1)[0]
    for inert in ("canary_leak", "dns_outside_allowlist", "credential_read_undeclared"):
        assert inert in inert_list
    # The one disposition that *does* gate is not listed as inert.
    assert "egress_outside_allowlist" not in inert_list
    # It is advisory, not a blocking problem — the gap is disclosed, not treated as a failure.
    assert json.loads(result.output)["blocking_problems"] == 0


def test_doctor_performs_the_precondition_check_per_profile(tmp_path: Path) -> None:
    """§16.4 / BW-51: doctor evaluates the precondition check for real — one row per profile,
    against that profile's own matrix targets and the planes the config wires — instead of
    listing it as pending. A fresh scaffold warns truthfully: its policy names claude-code
    targets (the WP-17 adapter does not ship), and the high profile requires planes that are
    not built. `run` refuses these same combinations; doctor's job is to say so earlier."""
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
    payload = json.loads(result.output)
    checks = {check["check"]: check for check in payload["checks"]}

    # One real row per profile; the old pending row is gone.
    for profile in ("low", "medium", "high"):
        name = f"precondition check (§16.4) — profile '{profile}'"
        assert name in checks, f"missing precondition row for {profile}"
        assert checks[name]["status"] in ("ok", "warn")
    assert not any("§16.4 precondition check passes" in name for name in checks)

    # The scaffold policy names claude-code targets → warn, naming the missing adapter.
    low = checks["precondition check (§16.4) — profile 'low'"]
    assert low["status"] == "warn"
    assert "no adapter for harness 'claude-code'" in low["detail"]
    # The high profile additionally requires planes this version has not built.
    high = checks["precondition check (§16.4) — profile 'high'"]
    assert "capture_planes[process]" in high["detail"]
    # Advisory, not blocking: an unsatisfiable profile is a policy fact, and `run` refuses it
    # with the same failures — doctor stays exit 0 on a fresh scaffold.
    assert payload["blocking_problems"] == 0


def test_doctor_reports_a_bad_config_as_an_infrastructure_error(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("apiVersion: bellwether/v1\nkind: Config\n", encoding="utf-8")
    result = runner.invoke(app, ["doctor", "--config", str(config_path)])
    assert result.exit_code == ExitCode.INFRASTRUCTURE


@pytest.mark.parametrize(
    ("command", "args"),
    [
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


def test_run_without_a_skill_refuses(tmp_path: Path) -> None:
    """`run` with no skill argument is an infrastructure refusal, not an empty clean run."""
    result = runner.invoke(app, ["run"])
    assert result.exit_code == ExitCode.INFRASTRUCTURE
    assert "at least one skill" in result.output


def test_run_with_a_missing_config_refuses(tmp_path: Path) -> None:
    """A run whose config.yaml is absent fails loudly before any container starts."""
    skill = tmp_path / "a-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: a-skill\ndescription: d\n---\nb\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["run", str(skill), "--config", str(tmp_path / "nope.yaml")])
    assert result.exit_code == ExitCode.INFRASTRUCTURE


def test_pr_comment_dry_run_prints_without_a_token(tmp_path: Path) -> None:
    """`pr-comment --dry-run` needs no token or network: it prints the marked comment. This is
    how a contributor previews what would land on the PR."""
    comment = tmp_path / "pr_comment.md"
    comment.write_text("## Bellwether — `conditional`\n", encoding="utf-8")
    result = runner.invoke(app, ["pr-comment", str(comment), "--dry-run"])
    assert result.exit_code == ExitCode.OK
    assert "conditional" in result.output
    assert "bellwether-report" in result.output  # the idempotence marker


def test_pr_comment_without_a_token_refuses(tmp_path: Path) -> None:
    """A real post with no token in the environment fails loudly, not silently."""
    comment = tmp_path / "pr_comment.md"
    comment.write_text("## report\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["pr-comment", str(comment), "--repo", "octo/skills", "--pr", "3", "--token-env", "NOPE"],
    )
    assert result.exit_code == ExitCode.INFRASTRUCTURE


def test_exit_codes_follow_the_spec() -> None:
    """§20: 0 covers ready and conditional; 2 is not_ready; 3 is infrastructure."""
    assert (ExitCode.OK, ExitCode.NOT_READY, ExitCode.INFRASTRUCTURE) == (0, 2, 3)
    assert 1 not in {int(code) for code in ExitCode}
