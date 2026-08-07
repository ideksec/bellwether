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
import os
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
    skills: Annotated[
        list[str] | None, typer.Argument(help="Skill directories to evaluate.")
    ] = None,
    config: Annotated[Path, typer.Option("--config", help="Path to config.yaml.")] = CONFIG_FILE,
    policy_path: Annotated[
        Path, typer.Option("--policy", help="Path to policy.yaml.")
    ] = POLICY_FILE,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Override the policy profile.")
    ] = None,
    out: Annotated[Path, typer.Option("--out", help="Where artifact trees are written.")] = Path(
        "bellwether-runs"
    ),
    max_tokens: Annotated[
        int,
        typer.Option(
            "--max-tokens",
            help="Hard per-repetition token ceiling — the cost guard for a live run.",
        ),
    ] = 1_000_000,
    json_output: JsonFlag = False,
) -> None:
    """Run a full evaluation: matrix, capture, metrics, verdict, artifacts.

    Each skill argument is the directory of a skill to evaluate (the one containing ``SKILL.md``).
    The verdict's exit code is the worst across the skills run: 0 for ``ready``/``conditional``, 2
    if any target failed a blocking gate; a configuration or environment problem is exit 3.
    """
    import datetime as dt

    from bellwether.cli.run import run_evaluation, sandbox_executor_factory
    from bellwether.harness import RunLimits
    from bellwether.skill import load_skill

    if not skills:
        typer.echo("bellwether run: name at least one skill directory to evaluate.", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    try:
        loaded_config = load_config(config)
        loaded_policy = load_policy(policy_path)
    except (BellwetherError, ConfigurationError, OSError) as error:
        typer.echo(f"bellwether run: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

    daemon_ok, daemon_reason = DockerBackend(image=loaded_config.sandbox.image).available()
    if not daemon_ok:
        typer.echo(f"bellwether run: the sandbox is unavailable — {daemon_reason}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    worst = ExitCode.OK
    results: list[dict[str, Any]] = []
    for skill_arg in skills:
        try:
            package = load_skill(Path(skill_arg))
            eval_id = f"{package.name}-{dt.datetime.now(dt.UTC):%Y%m%dT%H%M%SZ}"
            fixture = _run_fixture(Path(skill_arg))
            result = run_evaluation(
                config=loaded_config,
                policy=loaded_policy,
                package=package,
                fixture=fixture,
                environ=os.environ,
                make_executor=sandbox_executor_factory(
                    loaded_config.sandbox.image,
                    out / eval_id / "runs",
                    eval_id,
                    limits=RunLimits(max_total_tokens=max_tokens),
                ),
                out_dir=out / eval_id,
                eval_id=eval_id,
                created_at=dt.datetime.now(dt.UTC).isoformat(),
                bellwether_version=__version__,
                profile_override=profile,
            )
        except (BellwetherError, ConfigurationError) as error:
            typer.echo(f"bellwether run [{skill_arg}]: {error}", err=True)
            raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

        if result.exit_code == 2:
            worst = ExitCode.NOT_READY
        results.append(
            {
                "skill": package.name,
                "verdict": result.verdict.verdict,
                "artifacts": str(result.artifacts.root),
            }
        )

    _emit(
        {"results": results},
        as_json=json_output,
        lines=[f"{r['skill']}: {r['verdict']} — {r['artifacts']}" for r in results],
    )
    raise typer.Exit(int(worst))


@app.command()
def demo(
    out: Annotated[
        Path, typer.Option("--out", help="Where the demo artifact trees are written.")
    ] = Path("examples/reports"),
    skills_root: Annotated[
        Path, typer.Option("--skills", help="Directory holding the example skills.")
    ] = Path("examples/skills"),
    json_output: JsonFlag = False,
) -> None:
    """Render the worked example reports offline — no container, no API key (§24).

    Drives the three example skills under ``examples/skills/`` (a clean note-taker, a
    credential exfiltrator, and a flaky formatter) through the real analysis pipeline with
    scripted transcripts, and writes an artifact tree — including the HTML report — for each.
    The point is to *see* a report: open ``<out>/<eval>/report/report.html``.
    """
    import tempfile

    from bellwether.cli.demo import generate_demo

    try:
        with tempfile.TemporaryDirectory() as tmp:
            outputs = generate_demo(
                skills_root=skills_root,
                out_dir=out,
                tmp_dir=Path(tmp),
            )
    except (BellwetherError, ConfigurationError, OSError) as error:
        typer.echo(f"bellwether demo: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

    # A demo is a rendering exercise, not a gate: it always exits 0, whatever the example
    # verdicts are (two of the three are deliberately not_ready).
    rows = [
        {
            "skill": o.case.skill_dir,
            "verdict": o.result.verdict.verdict,
            "report": str(o.result.artifacts.report_html),
        }
        for o in outputs
    ]
    _emit(
        {"reports": rows},
        as_json=json_output,
        lines=[f"{r['skill']}: {r['verdict']} — {r['report']}" for r in rows],
    )


@app.command(name="changed-skills")
def changed_skills_command(
    paths: Annotated[
        list[str] | None,
        typer.Argument(help="Changed file paths; if omitted, read newline-separated from stdin."),
    ] = None,
    root: Annotated[
        Path, typer.Option("--root", help="Repository root the SKILL.md presence is checked in.")
    ] = Path(),
    json_output: JsonFlag = False,
) -> None:
    """Print the skill directories a set of changed files touches (§18).

    Feed it a diff — ``git diff --name-only origin/main...HEAD | bellwether changed-skills`` —
    and it prints one skill directory per line (a skill is a directory with a ``SKILL.md``;
    a changed file is attributed to its nearest such ancestor). Empty output means the change
    touched no skill, so nothing needs evaluating. Always exits 0: "no skills changed" is a
    normal result, not an error.
    """
    import sys

    from bellwether.cli.changed import changed_skills

    candidates = paths or [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
    skills = [str(skill) for skill in changed_skills(candidates, root=root)]
    _emit({"changed_skills": skills}, as_json=json_output, lines=skills)


@app.command(name="pr-comment")
def pr_comment(
    report: Annotated[
        Path,
        typer.Argument(
            help="The rendered comment (report/pr_comment.md) or the eval directory holding it."
        ),
    ],
    repo: Annotated[
        str | None, typer.Option("--repo", help="owner/repo (default: $GITHUB_REPOSITORY).")
    ] = None,
    pr: Annotated[
        int | None, typer.Option("--pr", help="Pull request number (default: from the CI env).")
    ] = None,
    token_env: Annotated[
        str, typer.Option("--token-env", help="Env var holding the GitHub token.")
    ] = "GITHUB_TOKEN",
    api_root: Annotated[
        str, typer.Option("--api-root", help="GitHub API root (for Enterprise).")
    ] = "https://api.github.com",
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the comment instead of posting it.")
    ] = False,
    json_output: JsonFlag = False,
) -> None:
    """Post (or update in place) a Bellwether report comment on a pull request (§18.2).

    Reads the comment `bellwether run` already rendered and upserts it: a re-run edits the
    same comment rather than stacking a new one. Repo and PR default to the GitHub Actions
    environment; the token is read from ``--token-env`` and used only in the auth header.
    """
    from bellwether.cli.pr import (
        PrContext,
        github_transport,
        marked_body,
        resolve_pr_context,
        upsert_pr_comment,
    )

    source = report / "report" / "pr_comment.md" if report.is_dir() else report
    try:
        body = source.read_text(encoding="utf-8")
    except OSError as error:
        typer.echo(f"bellwether pr-comment: cannot read {source}: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

    if dry_run:
        typer.echo(marked_body(body))
        return

    try:
        if repo is not None and pr is not None:
            owner, repo_name = repo.split("/", 1) if "/" in repo else ("", repo)
            context = PrContext(owner=owner, repo=repo_name, number=pr)
        else:
            context = resolve_pr_context(os.environ)
        token = os.environ.get(token_env, "")
        if not token:
            raise BellwetherError(f"no GitHub token in ${token_env}; cannot post the comment")
        action = upsert_pr_comment(
            github_transport(), context, body, token=token, api_root=api_root
        )
    except (BellwetherError, ValueError) as error:
        typer.echo(f"bellwether pr-comment: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

    _emit(
        {"action": action, "repo": context.slug, "pr": context.number},
        as_json=json_output,
        lines=[f"{action} comment on {context.slug}#{context.number}"],
    )


def _run_fixture(skill_dir: Path) -> Path:
    """The workspace fixture materialised into the sandbox for this skill's runs.

    First cut: the skill's ``evals/fixtures/`` directory when it exists, else an empty workspace.
    Per-scenario fixtures (``scenario.fixture``) are a refinement — the executor takes one fixture
    per run today, so a skill whose scenarios need different starting trees is not yet expressible.
    """
    fixtures = skill_dir / "evals" / "fixtures"
    if fixtures.is_dir():
        return fixtures
    empty = skill_dir / "evals" / ".empty-workspace"
    empty.mkdir(parents=True, exist_ok=True)
    return empty


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
