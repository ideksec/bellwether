"""The ``bellwether`` command-line application (§20).

Design rules from §20 that are load-bearing:

* every command supports ``--json`` for machine consumption;
* exit code 0 covers ``ready`` **and** ``conditional``, 2 is ``not_ready``, 3 is an
  infrastructure error. Revision 1 mapped ``conditional`` to 1, which — since every CI
  system treats non-zero as failure — made it block by default, the opposite of the
  documented recommendation. The nuance belongs in per-gate commit statuses;
* ``--strict`` promotes ``conditional`` to exit 2.

Commands whose work package has not landed exit 3 and name the package, rather than
printing an empty result that reads like a clean run.
"""

from __future__ import annotations

import enum
from pathlib import Path
from typing import Annotated, Any

import typer

from bellwether import __version__
from bellwether.config import (
    CONFIG_FILE,
    POLICY_FILE,
    load_config,
    load_policy,
    write_scaffold,
)
from bellwether.determinism import canonical_json
from bellwether.errors import BellwetherError, ConfigurationError
from bellwether.sandbox import DockerBackend, overlay_available

__all__ = ["ExitCode", "app", "main"]


class ExitCode(enum.IntEnum):
    """§20 exit codes."""

    OK = 0
    """``ready`` or ``conditional``."""

    NOT_READY = 2
    """One or more blocking gates failed."""

    INFRASTRUCTURE = 3
    """Could not evaluate: the environment, not the skill, is the problem."""


app = typer.Typer(
    name="bellwether",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help=(
        "Run agent skills many times in an instrumented sandbox, record what they did, "
        "measure how much it varies, and render a release verdict against your policy.\n\n"
        "Bellwether warns; it does not vouch. N runs produce a distribution, not a proof."
    ),
)

JsonFlag = Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")]


def _emit(payload: dict[str, Any], *, as_json: bool, lines: list[str]) -> None:
    if as_json:
        typer.echo(canonical_json(payload, indent=2))
    else:
        for line in lines:
            typer.echo(line)


def _not_yet(command: str, work_package: str, what: str) -> None:
    """Refuse a command whose implementation has not landed, naming the work package."""
    typer.echo(
        f"'bellwether {command}' is not implemented in this build.\n"
        f"  {what}\n"
        f"  Lands in {work_package} — see docs/BUILDPLAN.md.",
        err=True,
    )
    raise typer.Exit(ExitCode.INFRASTRUCTURE)


@app.command()
def version(json_output: JsonFlag = False) -> None:
    """Print the Bellwether version."""
    from bellwether import ARF_VERSION, CANON_VERSION, SUMMARY_SCHEMA_VERSION

    _emit(
        {
            "bellwether": __version__,
            "arf_version": ARF_VERSION,
            "summary_schema_version": SUMMARY_SCHEMA_VERSION,
            "canon_version": CANON_VERSION,
        },
        as_json=json_output,
        lines=[
            f"bellwether {__version__}",
            f"  ARF trace schema      {ARF_VERSION}",
            f"  summary.json schema   {SUMMARY_SCHEMA_VERSION}",
            f"  canonicalization      {CANON_VERSION}",
        ],
    )


@app.command()
def init(
    directory: Annotated[
        Path, typer.Argument(help="Repository root to scaffold.", show_default=".")
    ] = Path(),
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
    json_output: JsonFlag = False,
) -> None:
    """Scaffold .bellwether/ in a repository."""
    written, skipped = write_scaffold(directory, force=force)
    lines = [f"wrote    {path}" for path in written]
    lines += [f"skipped  {path} (already exists; --force to overwrite)" for path in skipped]
    if written:
        lines += [
            "",
            "Next: fill in the model ids under providers in "
            f"{directory / CONFIG_FILE}. Bellwether ships none of its own — model names "
            "change, and a stale one is the most likely first-run failure.",
        ]
    _emit(
        {
            "written": [str(path) for path in written],
            "skipped": [str(path) for path in skipped],
        },
        as_json=json_output,
        lines=lines,
    )


@app.command()
def doctor(
    config: Annotated[Path, typer.Option("--config", help="Path to config.yaml.")] = CONFIG_FILE,
    policy: Annotated[Path, typer.Option("--policy", help="Path to policy.yaml.")] = POLICY_FILE,
    json_output: JsonFlag = False,
) -> None:
    """Check the environment before a run rather than after it.

    The failure modes of this tool are mostly environmental, and several of them fail
    silently in the direction that looks clean: a proxy whose certificate is not trusted
    produces traces with zero egress, which reads as a skill that made no network calls.
    So doctor verifies actively rather than assuming, and prints the coverage block the
    runner would produce, so a user learns before a forty-minute run which planes will
    be missing.

    Environment probes are performed where the machinery for them exists. The rest are
    listed as pending with the work package that brings them, rather than omitted — a
    doctor that silently leaves out a check it cannot run reads as a doctor that ran it.
    """
    checks: list[dict[str, str]] = []
    problems = 0

    try:
        loaded_config = load_config(config)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    checks.append({"check": "config.yaml parses", "status": "ok", "detail": str(config)})

    try:
        loaded_policy = load_policy(policy)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    profiles = ", ".join(sorted(loaded_policy.profiles)) or "defaults only"
    checks.append({"check": "policy.yaml parses", "status": "ok", "detail": profiles})

    for violation in loaded_config.enforced_setting_violations():
        problems += 1
        checks.append(
            {"check": "enforced settings (§21)", "status": "critical", "detail": violation.render()}
        )
    if not loaded_config.enforced_setting_violations():
        checks.append(
            {
                "check": "enforced settings (§21)",
                "status": "ok",
                "detail": "no setting is disabled that would make a result unearned",
            }
        )

    for advisory in loaded_config.advisories():
        checks.append({"check": "advisory", "status": "warn", "detail": advisory})

    # The sandbox probes that WP-4 made real. Reported as `warn` rather than `critical`:
    # without them the filesystem plane degrades to unavailable, which the coverage block
    # records with a reason (§10.7) — it does not silently pass.
    backend_usable, backend_reason = DockerBackend().available()
    checks.append(
        {
            "check": "docker daemon reachable",
            "status": "ok" if backend_usable else "warn",
            "detail": backend_reason,
        }
    )
    overlay_usable, overlay_reason = overlay_available()
    checks.append(
        {
            "check": "host-side overlay upper dir obtainable",
            "status": "ok" if overlay_usable else "warn",
            "detail": overlay_reason,
        }
    )

    for pending, work_package in _PENDING_DOCTOR_CHECKS:
        checks.append({"check": pending, "status": "pending", "detail": work_package})

    lines = [f"[{entry['status']:>8}] {entry['check']}: {entry['detail']}" for entry in checks]
    if problems:
        lines.append("")
        lines.append(f"{problems} setting(s) must be corrected before a run above profile 'low'.")

    _emit(
        {"checks": checks, "blocking_problems": problems},
        as_json=json_output,
        lines=lines,
    )
    if problems:
        raise typer.Exit(ExitCode.INFRASTRUCTURE)


#: Environment probes doctor must perform, and the package that implements each (§20).
_PENDING_DOCTOR_CHECKS: tuple[tuple[str, str], ...] = (
    ("sandbox image pullable by digest", "WP-20"),
    ("proxy CA trusted by every mechanism in §9.2, checked by a real request", "WP-14"),
    ("internal bridge blocks direct UDP/53 to a public resolver", "WP-15"),
    ("fanotify markable; eBPF loadable by the host agent", "WP-5"),
    ("provider keys resolve; model aliases map to live model ids", "WP-6"),
    ("harness versions match version_pin", "WP-6"),
    ("§16.4 precondition check passes for the configured profile", "WP-11"),
)


@app.command()
def run(
    skills: Annotated[list[str] | None, typer.Argument(help="Skills to evaluate.")] = None,
    profile: Annotated[str | None, typer.Option("--profile", help="Policy profile.")] = None,
    n_max: Annotated[int | None, typer.Option("--n-max", help="Sequential ceiling.")] = None,
    json_output: JsonFlag = False,
) -> None:
    """Run a full evaluation: matrix, capture, metrics, verdict, artifacts."""
    _not_yet(
        "run",
        "WP-13 (the live model client)",
        "the whole pipeline — sandbox execution driver, capture, metrics, verdict, artifact "
        "tree — is built and reaches first-light end to end in tests; a CLI run of an "
        "arbitrary skill needs a live model client, which lands with the recording proxy",
    )


@app.command()
def scan(
    skills: Annotated[list[str] | None, typer.Argument(help="Skills to scan.")] = None,
    json_output: JsonFlag = False,
) -> None:
    """Static pre-flight scan only, no execution."""
    _not_yet("scan", "WP-20 (v0.1 corpus cases)", "static analysis has not landed")


@app.command()
def probe(
    target: Annotated[str, typer.Argument(help="Path or URL of a third-party skill.")],
    json_output: JsonFlag = False,
) -> None:
    """External mode: run the generic probe suite against a skill with no scenarios."""
    _not_yet("probe", "v0.2", "the generic probe suite of §7.6 has not landed")


@app.command()
def coexistence(json_output: JsonFlag = False) -> None:
    """Library-wide trigger-collision matrix."""
    _not_yet("coexistence", "v0.2", "coexistence runs on the schedule trigger, off the PR path")


@app.command(name="init-manifest")
def init_manifest(
    skill: Annotated[str, typer.Argument(help="Skill to infer a manifest for.")],
    json_output: JsonFlag = False,
) -> None:
    """Infer evals/manifest.yaml from an observed run, marked inferred-not-reviewed."""
    _not_yet("init-manifest", "WP-9", "inference needs an observed run to infer from")


@app.command(name="trace")
def show_trace(
    run_id: Annotated[str, typer.Argument(help="Run id.")],
    json_output: JsonFlag = False,
) -> None:
    """Pretty-print or filter one ARF trace."""
    _not_yet(
        "trace",
        "WP-12",
        "the ARF reader landed in WP-3, but nothing writes traces to an artifact tree yet",
    )


@app.command(name="report")
def render_report(
    eval_id: Annotated[str, typer.Argument(help="Evaluation id.")],
    json_output: JsonFlag = False,
) -> None:
    """Re-render a report from stored artifacts."""
    _not_yet("report", "WP-12", "the report renderer has not landed")


@app.command()
def diff(
    eval_a: Annotated[str, typer.Argument(help="Baseline evaluation id.")],
    eval_b: Annotated[str, typer.Argument(help="Candidate evaluation id.")],
    json_output: JsonFlag = False,
) -> None:
    """Diff two evaluations."""
    _not_yet("diff", "v0.2", "baseline diffing has not landed")


def main() -> None:
    """Console entry point for ``bellwether`` and ``bw``."""
    try:
        app()
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise SystemExit(ExitCode.INFRASTRUCTURE) from None
    except BellwetherError as exc:
        typer.echo(str(exc), err=True)
        raise SystemExit(ExitCode.INFRASTRUCTURE) from None
