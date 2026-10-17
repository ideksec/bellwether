"""The ``bellwether`` command-line application (§20).

Design rules from §20 that are load-bearing:

* every command supports ``--json`` for machine consumption;
* exit code 0 covers ``ready`` **and** ``conditional``, 2 is ``not_ready``, 3 is an
  infrastructure error, 4 is a declined §19.1 estimate. Revision 1 mapped ``conditional``
  to 1, which — since every CI system treats non-zero as failure — made it block by
  default, the opposite of the documented recommendation. The nuance belongs in per-gate
  commit statuses;
* ``--strict`` promotes ``conditional`` to exit 2.

Commands whose work package has not landed exit 3 and name the package, rather than
printing an empty result that reads like a clean run.
"""

from __future__ import annotations

import enum
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from bellwether import __version__
from bellwether.capture.fanotify import fanotify_available
from bellwether.cli.estimate import RunEstimate, render_estimate
from bellwether.cli.orchestrator import ENFORCED_SECURITY_RUNTIME_DISPOSITIONS, TargetInfo
from bellwether.cli.preflight import available_planes, preflight_failures
from bellwether.config import (
    CONFIG_FILE,
    POLICY_FILE,
    RUN_OUTPUT_DIR,
    load_config,
    load_platform_baseline,
    load_policy,
    write_scaffold,
)
from bellwether.determinism import canonical_json
from bellwether.errors import BellwetherError, ConfigurationError
from bellwether.sandbox import DockerBackend, overlay_available
from bellwether.skill import PluginBundle, slugify_name
from bellwether.verdict import validate_bci_weights

__all__ = ["ExitCode", "app", "main"]


class ExitCode(enum.IntEnum):
    """§20 exit codes."""

    OK = 0
    """``ready`` or ``conditional``."""

    NOT_READY = 2
    """One or more blocking gates failed."""

    INFRASTRUCTURE = 3
    """Could not evaluate: the environment, not the skill, is the problem."""

    DECLINED = 4
    """The operator declined the §19.1 pre-flight estimate. Nothing was executed — a choice,
    not a failure, so a script can tell it from a broken environment."""


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
    from bellwether import ARF_VERSION, CANON_VERSION

    # From the module that stamps it, so `version` cannot report a schema the tool does
    # not emit — it said 1.0 for as long as summaries had said 1.3.
    from bellwether.report.summary import SCHEMA_VERSION as SUMMARY_SCHEMA_VERSION

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


def _policy_beside(config: Path, policy: Path | None) -> Path:
    """The policy to load: the one named, else ``policy.yaml`` beside the config.

    ``init`` writes the two side by side, and the README's quickstart points ``--config`` at a
    repository elsewhere. The default used to be ``.bellwether/policy.yaml`` relative to the
    *working directory*, so that quickstart failed with "file not found" unless run from inside
    the skills repository — the first command a newcomer types.
    """
    return policy if policy is not None else config.parent / POLICY_FILE.name


@app.command()
def doctor(
    config: Annotated[Path, typer.Option("--config", help="Path to config.yaml.")] = CONFIG_FILE,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Path to policy.yaml (default: beside --config)."),
    ] = None,
    probe_interception: Annotated[
        bool,
        typer.Option(
            "--probe-interception",
            help="Confirm TLS interception with a real HTTPS request from inside a container "
            "(§9.2, WP-14). Stands the recording proxy up and tears it down; needs a Docker "
            "daemon and egress.image. Off by default because it costs a container standup.",
        ),
    ] = False,
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
        loaded_policy = load_policy(_policy_beside(config, policy))
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

    # A setting the schema accepts and this build does not act on reads, to anyone editing the
    # file, like one that is honoured. Say which, and why, rather than let the file promise it.
    not_built = loaded_config.not_built_settings()
    checks.append(
        {
            "check": "settings not built in this version",
            "status": "warn" if not_built else "ok",
            "detail": (
                "config.yaml sets these, and nothing in this build acts on them: "
                + "; ".join(f"{path} ({reason})" for path, reason in not_built)
                if not_built
                else "every setting in config.yaml is acted on"
            ),
        }
    )

    # §13.7: a BCI component weighted 0 does not disable the component — it silently drops it
    # from the composite (use metrics.components_excluded to disable one). The config model
    # already rejects a weight set that does not sum to 1.0, so what remains to catch here is a
    # zero weight, surfaced named to file and key before a run rather than discovered in a
    # quietly-wrong BCI after one.
    _bci_warnings = validate_bci_weights(
        loaded_config.metrics.bci_weights.model_dump(), source=str(config)
    )
    for _warning in _bci_warnings:
        checks.append(
            {"check": "BCI component weights (§13.7)", "status": "warn", "detail": _warning}
        )
    if not _bci_warnings:
        checks.append(
            {
                "check": "BCI component weights (§13.7)",
                "status": "ok",
                "detail": "five components sum to 1.0 with no zero weight",
            }
        )

    # §15: the built-in ruleset ships with every build. Say which one, and what the policy
    # does with it, so "a scan runs" and "a scan can block" are not confused.
    from bellwether.scan import BUILTIN_RULES, RULESET_ID

    _static_profiles = [loaded_policy.defaults, *loaded_policy.profiles.values()]
    _thresholds = sorted({p.gates.static.max_severity_allowed for p in _static_profiles})
    _required = sorted({s for p in _static_profiles for s in p.gates.static.required_scanners})
    _floors = sorted(
        {
            f"{tool}≥{floor}"
            for p in _static_profiles
            for tool, floor in p.gates.static.scanner_min_severity.items()
        }
    )
    if _required:
        checks.append(
            {
                "check": "external scanners (§15)",
                "status": "warn",
                "detail": (
                    f"policy requires SARIF from {', '.join(_required)} "
                    "(gates.static.required_scanners); `bellwether run` refuses unless each is "
                    "passed with --scanner-sarif. Bellwether reads scanner output and never runs "
                    "a scanner itself — run them in their own CI step"
                ),
            }
        )
    checks.append(
        {
            "check": "static scan (§15)",
            "status": "ok",
            "detail": (
                f"built-in ruleset {RULESET_ID} ({len(BUILTIN_RULES)} rules) scans every package "
                "before the matrix; findings above max_severity_allowed "
                f"({', '.join(_thresholds)}) block. Dedicated scanners are better at this "
                "specific job (§26.2) — run one in its own CI step and pass its SARIF with --scanner-sarif"
                + (f"; scanner severity floors: {', '.join(_floors)}" if _floors else "")
            ),
        }
    )

    # §16.2: only the dispositions in ENFORCED_SECURITY_RUNTIME_DISPOSITIONS are turned into
    # scored gates in this version. A policy that sets any other security_runtime disposition to
    # block/warn reads like an active control but does not yet drive the verdict — the same
    # silent-no-op trap as require_scan. Surface exactly which configured dispositions are inert
    # so a `block` there is never mistaken for enforcement. Both lists derive from the one
    # constant next to the gate assembly, so this message cannot drift from what actually gates.
    _inert_dispositions = sorted(
        {
            field
            for profile in _static_profiles
            for field in type(profile.gates.security_runtime).model_fields
            if field not in ENFORCED_SECURITY_RUNTIME_DISPOSITIONS
            and getattr(profile.gates.security_runtime, field) != "ignore"
        }
    )
    if _inert_dispositions:
        _enforced = ", ".join(sorted(ENFORCED_SECURITY_RUNTIME_DISPOSITIONS))
        checks.append(
            {
                "check": "runtime security dispositions (§16.2)",
                "status": "warn",
                "detail": (
                    f"only these security_runtime dispositions drive the scored verdict in this "
                    f"version: {_enforced}. These configured dispositions are captured as evidence "
                    "where their plane exists and shown in the report, but do not yet gate the "
                    "verdict, so a 'block' on them will not by itself make a verdict not_ready: "
                    f"{', '.join(_inert_dispositions)}. Treat their findings as advisory until the "
                    "matching gates land, or set them to 'ignore' to record that intent"
                ),
            }
        )

    # §16.2 / §19.1: the budget gate is composed from the run footers. The wall-clock half
    # (max_wall_clock_minutes) is always enforced — every run's duration is observed or bounded
    # by its per-run cap. The cost half (max_cost_usd) is enforced only where every target alias
    # in a profile's matrix has `providers.<name>.pricing`; an unpriced alias leaves it
    # uncomposed and the verdict says so. Report per profile which state it is in, so a
    # max_cost_usd in policy is never mistaken for a spending limit on an unpriced matrix.
    _unpriced_by_profile: dict[str, list[str]] = {}
    for _name, _profile in loaded_policy.profiles.items():
        _unpriced = sorted(
            {
                f"{target.provider}/{target.model_alias}"
                for target in _profile.matrix.required_targets
                if target.provider not in loaded_config.providers
                or loaded_config.providers[target.provider].pricing_for(target.model_alias) is None
            }
        )
        if _unpriced:
            _unpriced_by_profile[_name] = _unpriced
    _budgets = sorted(
        {
            f"max_cost_usd={profile.gates.budget.max_cost_usd:g}, "
            f"max_wall_clock_minutes={profile.gates.budget.max_wall_clock_minutes}"
            for profile in _static_profiles
        }
    )
    if _unpriced_by_profile:
        _listed = "; ".join(
            f"{name}: {', '.join(aliases)}"
            for name, aliases in sorted(_unpriced_by_profile.items())
        )
        checks.append(
            {
                "check": "budget gate (§16.2)",
                "status": "warn",
                "detail": (
                    "gates.budget.max_wall_clock_minutes is enforced from observed run durations, "
                    "but max_cost_usd does not gate the verdict for a matrix with an unpriced "
                    "target alias — the cost gate is composed only where every alias has "
                    "providers.<name>.pricing (USD per million tokens by kind). Unpriced: "
                    f"{_listed}. The per-repetition token ceiling ('bellwether run --max-tokens', "
                    "a budget_exceeded outcome) is enforced regardless. Configured: "
                    + "; ".join(_budgets)
                ),
            }
        )
    else:
        checks.append(
            {
                "check": "budget gate (§16.2)",
                "status": "ok",
                "detail": (
                    "gates.budget is enforced: max_wall_clock_minutes from observed run durations, "
                    "max_cost_usd from reported token usage at the configured pricing. "
                    "Configured: " + "; ".join(_budgets)
                ),
            }
        )

    # §9.2 / WP-14: the CA-in-the-loop probe. Opt-in because it stands a sidecar and a client
    # container up, but when asked for it *executes* rather than reporting a configured proxy
    # as though that settled anything — a container that rejects the CA produces zero-egress
    # traces that read as a clean skill, and nothing short of a real request rules that out.
    if probe_interception:
        checks.append(_interception_probe_check(loaded_config))
        if checks[-1]["status"] == "critical":
            problems += 1

    # §9.2/§12.7: the per-run bounds, stated before a forty-minute run rather than discovered
    # as a wave of "timeout" outcomes afterwards. A turn or tool-call ceiling is scored as a
    # failure, so a tight one turns the operator's choice into the skill's score — which is a
    # thing to say out loud, not a footnote in the config file.
    _limits = loaded_config.execution.limits
    checks.append(
        {
            "check": "per-run limits (§9.2)",
            "status": "ok",
            "detail": (
                f"execution.limits: max_turns={_limits.max_turns}, "
                f"max_tool_calls={_limits.max_tool_calls}, "
                f"max_total_tokens={_limits.max_total_tokens} "
                "(--max-tokens overrides the last). A run stopped by the first two records "
                "exit_reason 'timeout', which §12.7 scores as a failure; the token cap records "
                "'budget_exceeded', which is not_evaluable. The wall clock is the scenario's "
                "(§7.2 timeout_seconds, else the suite default), and every run's header carries "
                "the bounds it ran under."
            ),
        }
    )

    # §12.6: the platform baseline is applied only where it is keyed to the configured sandbox
    # image. Report which state it is in — absent, present-but-not-applicable (with the
    # document's own reason), or applied — so "no infrastructural access subtracted" is a
    # stated fact rather than an invisible one.
    _baseline_file = config.parent / "platform-baseline.yaml"
    if not _baseline_file.is_file():
        checks.append(
            {
                "check": "platform baseline (§12.6)",
                "status": "warn",
                "detail": (
                    f"{_baseline_file} is absent: no infrastructural allowlist is subtracted, so "
                    "every harness/toolchain path a run touches counts against the skill's "
                    "declared scope ('bellwether init' scaffolds one)"
                ),
            }
        )
    else:
        try:
            _platform = load_platform_baseline(_baseline_file)
            _applicable, _why = _platform.applicable_to(loaded_config.sandbox.image)
            checks.append(
                {
                    "check": "platform baseline (§12.6)",
                    "status": "ok" if _applicable else "warn",
                    "detail": (
                        f"version {_platform.version} applied to {loaded_config.sandbox.image}: "
                        f"{len(_platform.paths.read)} read / {len(_platform.paths.write)} write "
                        "entries subtracted from every run's capability sets"
                        if _applicable
                        else f"version {_platform.version} present but not applied: {_why}"
                    ),
                }
            )
        except (BellwetherError, ConfigurationError) as error:
            checks.append(
                {
                    "check": "platform baseline (§12.6)",
                    "status": "critical",
                    "detail": f"{_baseline_file} does not load: {error}",
                }
            )
            problems += 1

    # §16.4 / BW-51: the precondition check, evaluated for real — per profile, against that
    # profile's own matrix targets and the planes this config actually wires. Reported as
    # `warn`, not `critical`: an unsatisfiable profile is a fact about policy-vs-composition,
    # and `run` refuses it with the same failures before spending; doctor's job is to say it
    # earlier. A fresh scaffold warns truthfully here — its policy names claude-code targets
    # (WP-17) and blocks on egress while no proxy image is configured.
    _planes = available_planes(loaded_config)
    for _profile_name in sorted(loaded_policy.profiles):
        _profile = loaded_policy.profile(_profile_name)
        _targets = [
            TargetInfo(spec.harness, spec.provider, spec.model_alias)
            for spec in _profile.matrix.required_targets
        ]
        _failures = preflight_failures(loaded_config, _profile, _targets)
        if _failures:
            detail = "; ".join(
                f"{failure.gate} [{failure.target}]: {failure.remedy}" for failure in _failures
            )
            status = "warn"
        else:
            detail = (
                f"satisfiable: {len(_targets)} target(s) against available planes "
                f"({', '.join(sorted(_planes))})"
            )
            status = "ok"
        checks.append(
            {
                "check": f"precondition check (§16.4) — profile '{_profile_name}'",
                "status": status,
                "detail": detail,
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

    # §10.2/§10.3: read and process capture need a fanotify group. Without one the two planes
    # are recorded unavailable with this reason and their gates defer — never a clean read.
    if "fanotify" in (loaded_config.capture.filesystem_reads, loaded_config.capture.process):
        fanotify_usable, fanotify_reason = fanotify_available()
        checks.append(
            {
                "check": "fanotify group obtainable (read and process capture)",
                "status": "ok" if fanotify_usable else "warn",
                "detail": fanotify_reason,
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
#: Probes `doctor` does not yet perform, each with *why it is still absent* — not the work package
#: that introduced the surrounding feature. Naming a completed package here (this list previously
#: said WP-5, WP-6 and WP-11, all of which are done) reads as "that work has not landed", which is
#: both false and the wrong thing to act on: what is missing is the *probe*, not the capability.
_PENDING_DOCTOR_CHECKS: tuple[tuple[str, str], ...] = (
    ("sandbox image pullable by digest", "needs a registry round-trip; lands with WP-20"),
    (
        "proxy CA trusted by every mechanism in §9.2, checked by a real request",
        "run it with --probe-interception: it stands the proxy up and issues a real HTTPS "
        "request, so it is opt-in rather than part of every doctor",
    ),
    (
        "internal bridge blocks direct UDP/53 to a public resolver",
        "the §3.3 invariant-3 live probe is CI-only (WP-15's live half)",
    ),
    (
        "provider keys resolve; model aliases map to live model ids",
        "would spend a live API call; not run from doctor",
    ),
    (
        "harness versions match version_pin",
        "the claude-code CLI version is read from the sandbox image at run time and recorded "
        "in every trace; checking it against version_pin from doctor needs a container",
    ),
)


@app.command()
def run(
    skills: Annotated[
        list[str] | None,
        typer.Argument(help="Skill directories (or Agent Plugin roots) to evaluate."),
    ] = None,
    config: Annotated[Path, typer.Option("--config", help="Path to config.yaml.")] = CONFIG_FILE,
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="Path to policy.yaml (default: beside --config)."),
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Override the policy profile.")
    ] = None,
    out: Annotated[
        Path, typer.Option("--out", help="Where artifact trees are written.")
    ] = RUN_OUTPUT_DIR,
    max_tokens: Annotated[
        int,
        typer.Option(
            "--max-tokens",
            help="Hard per-repetition token ceiling — the cost guard for a live run.",
        ),
    ] = 1_000_000,
    scenario: Annotated[
        list[str] | None,
        typer.Option("--scenario", help="Run only this scenario id (repeatable)."),
    ] = None,
    tag: Annotated[
        list[str] | None,
        typer.Option("--tag", help="Run only scenarios carrying this tag (repeatable)."),
    ] = None,
    targets: Annotated[
        str | None,
        typer.Option(
            "--targets", help="Comma-separated model aliases to keep (e.g. frontier,small)."
        ),
    ] = None,
    n_max: Annotated[
        int | None,
        typer.Option("--n-max", help="Sequential ceiling, matrix-wide (must be a look point)."),
    ] = None,
    looks: Annotated[
        str | None,
        typer.Option("--looks", help="Comma-separated look points, matrix-wide (advanced, §13.1)."),
    ] = None,
    repetitions: Annotated[
        int | None,
        typer.Option(
            "--repetitions",
            help="Fixed-N mode: exactly N runs per set; the verdict is descriptive_only and "
            "cannot be ready (§13.1).",
        ),
    ] = None,
    strict: Annotated[
        bool, typer.Option("--strict", help="Promote a conditional verdict to a failing exit code.")
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Skip the confirmation after the pre-flight estimate (§19.1) — never the "
            "estimate itself. Without it, an interactive terminal is asked to proceed; a "
            "non-interactive run (CI) proceeds after printing the estimate.",
        ),
    ] = False,
    deterministic_sampling: Annotated[
        bool,
        typer.Option(
            "--deterministic-sampling",
            help="Pin temperature to 0 (and a seed where the provider takes one) for a "
            "low-variance comparison; marked on every run and in the report as not the "
            "realistic condition (§9.3). Refused on claude-code targets.",
        ),
    ] = False,
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache",
            help="Execute every repetition even where the run cache holds a matching trace "
            "(§19.2); the config's execution.cache and cache_ttl_days govern otherwise.",
        ),
    ] = False,
    depth: Annotated[
        str | None,
        typer.Option(
            "--depth",
            help="Preset: quick (one small target, fixed 3, descriptive only), standard "
            "(frontier+small, looks 6/12), deep (all targets, looks 6/12/20). Exclusive with "
            "the matrix options (§19.1).",
        ),
    ] = None,
    budget_usd: Annotated[
        float | None,
        typer.Option(
            "--budget-usd",
            help="Override the profile's max_cost_usd for this evaluation (§19.1); the cost gate "
            "is composed only where every target alias has providers.<name>.pricing.",
        ),
    ] = None,
    scanner_sarif: Annotated[
        list[Path] | None,
        typer.Option(
            "--scanner-sarif",
            help="SARIF 2.1.0 written by an external scanner (Semgrep, Gitleaks, …) to merge "
            "into the static scan (§15); repeatable. Bellwether reads it, never runs the tool.",
        ),
    ] = None,
    json_output: JsonFlag = False,
) -> None:
    """Run a full evaluation: matrix, capture, metrics, verdict, artifacts.

    Each skill argument is the directory of a skill to evaluate (the one containing ``SKILL.md``)
    — or an Agent Plugin root (a directory containing ``plugin.json``, agent-plugins.org), which
    expands to every skill under its ``skills/``. The verdict's exit code is the worst across the
    skills run: 0 for ``ready``/``conditional``, 2 if any target failed a blocking gate; a
    configuration or environment problem is exit 3.
    """
    import datetime as dt
    from dataclasses import replace

    from bellwether.cli.baselines import read_baseline_for
    from bellwether.cli.companions import companion_resolver
    from bellwether.cli.execution import isolation_from_config, zone_map_from_config
    from bellwether.cli.fixtures import fixture_resolver
    from bellwether.cli.run import (
        RunDeclinedError,
        build_proxy_provider,
        build_resolver_provider,
        claude_code_providers,
        run_evaluation,
        run_limits_from_config,
        sandbox_executor_factory,
    )
    from bellwether.cli.run_cache import CACHE_DIR_NAME, RunCache, require_cache_root
    from bellwether.determinism import stable_hash
    from bellwether.harness import SamplingSpec
    from bellwether.skill import load_skill

    if not skills:
        typer.echo("bellwether run: name at least one skill directory to evaluate.", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    try:
        work = _expand_skill_args(skills)
        parsed_looks = _parse_looks(looks)
    except BellwetherError as error:
        typer.echo(f"bellwether run: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

    try:
        loaded_config = load_config(config)
        loaded_policy = load_policy(_policy_beside(config, policy_path))
        # §12.6: the platform baseline lives beside the config; absent, nothing is subtracted
        # and the run says so. Present but keyed to another image, likewise — run_evaluation
        # applies it only where `applies_to_image` matches the configured sandbox image.
        baseline_file = config.parent / "platform-baseline.yaml"
        platform_baseline = (
            load_platform_baseline(baseline_file) if baseline_file.is_file() else None
        )
    except (BellwetherError, ConfigurationError, OSError) as error:
        typer.echo(f"bellwether run: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    applied_version = (
        platform_baseline.version
        if platform_baseline is not None
        and platform_baseline.applicable_to(loaded_config.sandbox.image)[0]
        else None
    )

    daemon_ok, daemon_reason = DockerBackend(image=loaded_config.sandbox.image).available()
    if not daemon_ok:
        typer.echo(f"bellwether run: the sandbox is unavailable — {daemon_reason}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    # §19.2: the run cache lives beside the artifact trees. Off by --no-cache or config.
    run_cache: RunCache | None = None
    if loaded_config.execution.cache and not no_cache:
        try:
            run_cache = RunCache(
                root=require_cache_root(out / CACHE_DIR_NAME / "runs"),
                ttl_days=loaded_config.execution.cache_ttl_days,
            )
        except (BellwetherError, OSError) as error:
            typer.echo(f"bellwether run: {error}", err=True)
            raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

    worst = ExitCode.OK
    results: list[dict[str, Any]] = []
    for skill_dir, bundle_notes, plugin in work:
        try:
            package = load_skill(skill_dir)
            if bundle_notes:
                # Observations about the *bundle* the skill arrived in (a manifest defect,
                # MCP servers this version never stands up) travel with each skill it
                # expanded to, and are said out loud — an unevaluated component that goes
                # unmentioned reads as one that ran clean.
                package = replace(package, problems=package.problems + bundle_notes)
                for note in bundle_notes:
                    typer.echo(f"bellwether run [{skill_dir}]: {note}", err=True)
            # The slug, never the declared name: the name is the skill author's, and ``eval_id``
            # becomes a directory under ``--out`` that root writes to on CI. ``name: ../../x``
            # (or an absolute path, which a join discards the prefix for) moved the whole
            # artifact tree out of ``--out``. ``load_skill`` already says when they differ.
            eval_id = f"{slugify_name(package.name)}-{dt.datetime.now(dt.UTC):%Y%m%dT%H%M%SZ}"
            fixture = _run_fixture(skill_dir)
            # §7.2: each scenario's `fixture:` (or the suite default) resolves to its own
            # directory — the skill's evals/fixtures/<name>/, the repository's shared
            # .bellwether/fixtures/<name>/, or `empty` — so scenarios that need different
            # starting trees are expressible; `fixture` above stays the default for plans
            # that name none.
            fixture_for = (
                fixture_resolver(
                    skill_dir, package.scenarios, shared_root=config.parent / "fixtures"
                )
                if package.scenarios is not None
                else None
            )
            # §17.5: the skill's stored baseline, beside the config, feeds the regression gate.
            baseline = read_baseline_for(config.parent / "baselines", package.name)
            result = run_evaluation(
                config=loaded_config,
                policy=loaded_policy,
                package=package,
                fixture=fixture,
                baseline=baseline,
                fixture_for=fixture_for,
                # §7.4: a scenario's also_load_skills resolve to sibling skill directories
                # beside this one and are offered alongside it.
                companions_for=companion_resolver(skill_dir),
                scenario_ids=tuple(scenario or ()),
                tags=tuple(tag or ()),
                target_aliases=_split_csv(targets),
                n_max_override=n_max,
                looks_override=parsed_looks,
                repetitions=repetitions,
                budget_usd=budget_usd,
                depth=depth,
                platform_baseline=platform_baseline,
                run_cache=run_cache,
                # §19.2: the bundle's content reaches the container, so it keys the cache.
                plugin=plugin,
                deterministic_sampling=deterministic_sampling,
                max_tokens_per_run=max_tokens,
                on_estimate=_estimate_gate(yes),
                scanner_sarif=tuple(scanner_sarif or ()),
                environ=os.environ,
                make_executor=sandbox_executor_factory(
                    loaded_config.sandbox.image,
                    out / eval_id / "runs",
                    eval_id,
                    # §9.2/§12.7: execution.limits, with --max-tokens overriding the
                    # token cap. Previously every run took the generic defaults whatever
                    # the operator configured.
                    limits=run_limits_from_config(loaded_config, max_total_tokens=max_tokens),
                    # §3.5: the whole artifact root, so a plugin bundle that is its own
                    # checkout never stages a previous evaluation's traces or verdicts. The
                    # same value keys the run cache, or the key would describe a different
                    # set of files from the one staged.
                    artifact_root=out,
                    # Wired only when egress.image is set (a live config); otherwise None and the
                    # sandbox runs networkless, exactly as first-light (§10.5). A key is brokered
                    # into the sidecar only for the providers a claude-code target names — the
                    # harness whose model calls originate inside the sandbox (§3.3).
                    proxy=build_proxy_provider(
                        loaded_config,
                        environ=os.environ,
                        brokered_providers=claude_code_providers(loaded_policy, package.manifest),
                        rng_seed=int(stable_hash(eval_id).removeprefix("sha256:")[:16], 16),
                    ),
                    provider_base_urls={
                        name: provider.base_url
                        for name, provider in loaded_config.providers.items()
                    },
                    # §9.3: the header records the sampling a provider actually sends, so the
                    # executor needs each provider's type, not just its endpoint.
                    provider_types={
                        name: provider.type for name, provider in loaded_config.providers.items()
                    },
                    # §5/§6/§18: where the skill came from an Agent Plugin, the bundle is
                    # installed whole and the CLI loads it with --plugin-dir, so the evaluated
                    # arrangement is the deployed one.
                    plugin=plugin,
                    # Wired only when dns.image is set; otherwise None and DNS stays not_evaluable
                    # (§10.6). When both are on, the resolver shares the proxy's internal bridge.
                    resolver=build_resolver_provider(loaded_config),
                    # Carry the configured sandbox profile (memory/cpus/pids/timeout/writable
                    # paths), zone map, and §3.5 identifier randomisation into the container.
                    isolation=isolation_from_config(loaded_config.sandbox),
                    zones=zone_map_from_config(loaded_config.capture.zones),
                    randomize_identifiers=loaded_config.sandbox.randomize_identifiers,
                    # Plant canaries and scan the observed planes for them when config enables it
                    # (§10.4); the env-var channel is delivered and scanned host-side today.
                    plant_canaries=loaded_config.canaries.enabled,
                    # §10.2/§10.3: host-side read and process capture for every run.
                    capture_reads=loaded_config.capture.filesystem_reads == "fanotify",
                    capture_processes=loaded_config.capture.process == "fanotify",
                    platform_baseline_version=applied_version,
                    sampling=(
                        SamplingSpec(temperature=0.0, seed=0) if deterministic_sampling else None
                    ),
                ),
                # The artifact writer appends <eval_id> itself, so the parent is `out`;
                # passing `out / eval_id` here doubled it and hid the report from pr-comment.
                out_dir=out,
                eval_id=eval_id,
                created_at=dt.datetime.now(dt.UTC).isoformat(),
                bellwether_version=__version__,
                profile_override=profile,
            )
        except RunDeclinedError as error:
            # §19.1: a decline is the operator's choice and nothing was executed, so it gets
            # its own code rather than reading as a broken environment.
            typer.echo(f"bellwether run [{skill_dir}]: {error}", err=True)
            raise typer.Exit(ExitCode.DECLINED) from None
        except (BellwetherError, ConfigurationError) as error:
            typer.echo(f"bellwether run [{skill_dir}]: {error}", err=True)
            raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

        if exit_code_for(result.exit_code, result.verdict.verdict, strict=strict) != ExitCode.OK:
            worst = ExitCode.NOT_READY
        results.append(
            {
                "skill": package.name,
                "verdict": result.verdict.verdict,
                "descriptive_only": result.verdict.descriptive_only,
                "runs_cached": result.summary.matrix.runs_cached,
                "runs_completed": result.summary.matrix.runs_completed,
                "artifacts": str(result.artifacts.root),
            }
        )

    # §19.1 / §16.2 rule 6: a fixed-N run (--repetitions, --depth quick) is descriptive only
    # and the output header says so, so a quick run is never mistaken for a release gate.
    _emit(
        {"results": results},
        as_json=json_output,
        lines=[
            f"{r['skill']}: {r['verdict']}"
            + (" (descriptive only — fixed-N, cannot be ready)" if r["descriptive_only"] else "")
            + (
                f" ({r['runs_cached']} of {r['runs_completed']} runs served from the run cache)"
                if r["runs_cached"]
                else ""
            )
            + f" — {r['artifacts']}"
            for r in results
        ],
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
    null: Annotated[
        bool,
        typer.Option(
            "-z",
            "--null",
            help="Read stdin as NUL-separated paths (pair with `git diff --name-only -z`).",
        ),
    ] = False,
    under: Annotated[
        list[str] | None,
        typer.Option(
            "--under",
            help="Only report skills inside this repository directory (repeatable) — the real "
            "skill roots, so skill-shaped test fixtures elsewhere are never evaluated.",
        ),
    ] = None,
    json_output: JsonFlag = False,
) -> None:
    """Print the skill directories a set of changed files touches (§18).

    Feed it a diff — ``git diff --name-only origin/main...HEAD | bellwether changed-skills`` —
    and it prints one skill directory per line (a skill is a directory with a ``SKILL.md``;
    a changed file is attributed to its nearest such ancestor). A plugin-level change inside
    an Agent Plugin bundle (a directory with a ``plugin.json``) is attributed to every skill
    the plugin carries. Empty output means the change touched no skill, so nothing needs
    evaluating, and exits 0: "no skills changed" is a normal result, not an error. A path it cannot
    attribute (git C-quoted it — pass `-z`) or a skill name the one-per-line output cannot carry
    is a refusal (exit 3), never a quiet omission.
    """
    import sys

    from bellwether.cli.changed import changed_skills

    if paths:
        candidates = list(paths)
    elif null:
        # NUL-separated: git's `-z` output, every path byte-for-byte — no quoting, no escaping.
        candidates = [path for path in sys.stdin.read().split("\0") if path]
    else:
        candidates = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
        # Without `-z`, git C-quotes a path containing a non-ASCII byte, a quote or a control
        # character (`"caf\303\251/SKILL.md"`). Such a line names no file on disk, so it was
        # attributed to no skill and dropped — "no skills changed" for a PR that added one, the
        # false green this command exists to prevent. Refused, not guessed at.
        quoted = [path for path in candidates if path.startswith('"') and path.endswith('"')]
        if quoted:
            typer.echo(
                "bellwether changed-skills: "
                f"{len(quoted)} path(s) arrived C-quoted by git ({quoted[0]}, …) and cannot be "
                "attributed; pipe `git diff --name-only -z` into `changed-skills -z`",
                err=True,
            )
            raise typer.Exit(ExitCode.INFRASTRUCTURE)
    try:
        found = changed_skills(candidates, root=root, under=tuple(under or ()))
    except ValueError as error:
        typer.echo(f"bellwether changed-skills: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    skills = [str(skill) for skill in found]
    # One skill per output line is the contract the CI workflow reads (and writes into
    # $GITHUB_OUTPUT); a directory name holding a line break would forge a second entry there.
    broken = [skill for skill in skills if any(ch in skill for ch in "\n\r\0")]
    if broken:
        typer.echo(
            f"bellwether changed-skills: skill directory {broken[0]!r} contains a line break, "
            "which the one-per-line output cannot carry; rename it to evaluate it",
            err=True,
        )
        raise typer.Exit(ExitCode.INFRASTRUCTURE)
    _emit({"changed_skills": skills}, as_json=json_output, lines=skills)


def _report_key_beside(comment: Path) -> str:
    """The comment key for the evaluation that rendered ``comment`` (§18.2).

    ``bellwether run`` writes ``<eval>/report/pr_comment.md`` beside ``<eval>/summary.json``; the
    key is the skill and the targets the summary records. A comment with no summary beside it is
    refused rather than posted under a guessed identity — a shared key is exactly how one
    evaluation's verdict came to overwrite another's.
    """
    from bellwether.cli.pr import report_key

    summary_path = comment.parent.parent / "summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BellwetherError(
            f"no summary.json at {summary_path}: pass the evaluation directory `bellwether run` "
            "wrote (or its report/pr_comment.md), so the comment can be keyed to what it reports"
        ) from None
    except (OSError, ValueError) as error:
        raise BellwetherError(f"cannot read {summary_path}: {error}") from None
    skill = summary.get("skill") if isinstance(summary, dict) else None
    matrix = summary.get("matrix") if isinstance(summary, dict) else None
    name = skill.get("name") if isinstance(skill, dict) else None
    slugs = matrix.get("target_slugs") if isinstance(matrix, dict) else None
    if not isinstance(name, str) or not isinstance(slugs, list):
        raise BellwetherError(f"{summary_path} records no skill.name and matrix.target_slugs")
    return report_key(name, [str(slug) for slug in slugs])


@app.command(name="commit-status")
def commit_status(
    evaluations: Annotated[
        list[Path] | None,
        typer.Argument(help="Evaluation directories (each holding summary.json) of one commit."),
    ] = None,
    sha: Annotated[
        str,
        typer.Option(
            "--sha",
            help="The pull request's head SHA (github.event.pull_request.head.sha) — not "
            "GITHUB_SHA, which on a pull request is the merge commit and never shows on the PR.",
        ),
    ] = "",
    state: Annotated[
        str | None,
        typer.Option(
            "--state",
            help="Post this state on every context instead of reading evaluations: success "
            "(nothing to evaluate), pending (waiting on a maintainer) or failure (the evaluation "
            "did not complete). Needs --reason.",
        ),
    ] = None,
    reason: Annotated[
        str | None, typer.Option("--reason", help="The description for --state.")
    ] = None,
    context_prefix: Annotated[
        str,
        typer.Option(
            "--context-prefix",
            help="Context prefix, e.g. bellwether → bellwether/security. Give each workflow "
            "its own, or two harnesses overwrite each other's statuses.",
        ),
    ] = "bellwether",
    repo: Annotated[
        str | None, typer.Option("--repo", help="owner/repo (default: $GITHUB_REPOSITORY).")
    ] = None,
    token_env: Annotated[
        str, typer.Option("--token-env", help="Env var holding the GitHub token.")
    ] = "GITHUB_TOKEN",
    api_root: Annotated[
        str, typer.Option("--api-root", help="GitHub API root (for Enterprise).")
    ] = "https://api.github.com",
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the statuses instead of posting them.")
    ] = False,
    json_output: JsonFlag = False,
) -> None:
    """Post a commit status per gate group, plus the verdict, for branch protection (§18.2).

    One context per gate group — ``<prefix>/static``, ``functional``, ``consistency``,
    ``security``, ``evidence``, ``budget``, ``regression``, ``review`` — failing when a gate in it
    blocks; ``<prefix>/verdict`` failing on ``not_ready``; ``<prefix>/ready`` failing unless every
    evaluation is ``ready``. A repository decides what blocks a merge by which contexts it
    requires. Several evaluations of one commit (several changed skills) report the worst.
    """
    from bellwether.cli.pr import github_transport
    from bellwether.cli.status import (
        check_prefix,
        check_sha,
        evaluation_statuses,
        post_statuses,
        run_url,
        uniform_statuses,
    )
    from bellwether.report.summary import Summary

    def refuse(message: str) -> NoReturn:
        typer.echo(f"bellwether commit-status: {message}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    try:
        prefix = check_prefix(context_prefix)
        if sha or not dry_run:
            check_sha(sha)
        if state is not None:
            if evaluations:
                refuse("--state posts one state everywhere; it takes no evaluation directories")
            if state not in ("success", "pending", "failure"):
                refuse(f"--state must be success, pending or failure, not {state!r}")
            if not reason:
                refuse(f"--state needs --reason: the description says why every context is {state}")
            statuses = uniform_statuses(state, reason, prefix=prefix)  # type: ignore[arg-type]
        else:
            if not evaluations:
                refuse("name the evaluation directories to report, or pass --state and --reason")
            summaries = []
            for directory in evaluations:
                path = directory / "summary.json"
                try:
                    summaries.append(Summary.model_validate_json(path.read_text(encoding="utf-8")))
                except (OSError, ValueError) as error:
                    refuse(f"cannot read {path}: {type(error).__name__}: {error}")
            statuses = evaluation_statuses(summaries, prefix=prefix)
    except BellwetherError as error:
        refuse(str(error))

    lines = [f"{s.context}: {s.state} — {s.description}" for s in statuses]
    payload = {
        "sha": sha,
        "statuses": [
            {"context": s.context, "state": s.state, "description": s.description} for s in statuses
        ],
    }
    if dry_run:
        _emit(payload, as_json=json_output, lines=lines)
        return
    try:
        repository = repo or os.environ.get("GITHUB_REPOSITORY", "")
        if "/" not in repository:
            raise BellwetherError(
                "no repository: pass --repo owner/repo or run where GITHUB_REPOSITORY is set"
            )
        token = os.environ.get(token_env, "")
        if not token:
            raise BellwetherError(f"no GitHub token in ${token_env}; cannot post statuses")
        posted = post_statuses(
            github_transport(),
            repository,
            sha,
            statuses,
            token=token,
            target_url=run_url(os.environ),
            api_root=api_root,
        )
    except BellwetherError as error:
        refuse(str(error))
    payload["posted"] = posted  # type: ignore[assignment]
    _emit(payload, as_json=json_output, lines=[*lines, f"posted {posted} status(es) on {sha}"])


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
    update_only: Annotated[
        bool,
        typer.Option(
            "--update-only",
            help="Edit this report's existing comment but never create one — for a clean result "
            "that must replace a stale red comment without adding noise to a PR never red.",
        ),
    ] = False,
    json_output: JsonFlag = False,
) -> None:
    """Post (or update in place) a Bellwether report comment on a pull request (§18.2).

    Reads the comment `bellwether run` already rendered and upserts it: a re-run edits the
    same comment rather than stacking a new one. Each evaluation — a skill on its targets —
    owns its own comment, keyed from the ``summary.json`` beside the report, so two harnesses
    or two skills on one PR never overwrite each other. Repo and PR default to the GitHub
    Actions environment; the token is read from ``--token-env`` and used only in the auth header.

    A static-scan summary (``bellwether scan --markdown``, first line ``<!-- bellwether-static
    -->``) is accepted too: it owns one comment per pull request, keyed apart from every
    evaluation's.
    """
    from bellwether.cli.pr import (
        STATIC_SCAN_KEY,
        PrContext,
        github_transport,
        marked_body,
        resolve_pr_context,
        upsert_pr_comment,
    )
    from bellwether.report import SCAN_MARKER

    source = report / "report" / "pr_comment.md" if report.is_dir() else report
    try:
        body = source.read_text(encoding="utf-8")
        # The scan summary is recognised by its own first line, which `render_scan_markdown`
        # always writes and no evaluation's comment starts with.
        is_scan = body.split("\n", 1)[0].strip() == SCAN_MARKER
        key = STATIC_SCAN_KEY if is_scan else _report_key_beside(source)
    except OSError as error:
        typer.echo(f"bellwether pr-comment: cannot read {source}: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    except BellwetherError as error:
        typer.echo(f"bellwether pr-comment: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

    if dry_run:
        typer.echo(marked_body(body, key))
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
            github_transport(),
            context,
            body,
            key=key,
            token=token,
            api_root=api_root,
            update_only=update_only,
        )
    except (BellwetherError, ValueError) as error:
        typer.echo(f"bellwether pr-comment: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

    _emit(
        {"action": action, "repo": context.slug, "pr": context.number},
        as_json=json_output,
        lines=[
            f"no earlier comment on {context.slug}#{context.number} to update; nothing posted"
            if action == "skipped"
            else f"{action} comment on {context.slug}#{context.number}"
        ],
    )


def _interception_probe_check(loaded_config: Any) -> dict[str, str]:
    """Run the §9.2 probe and render its doctor row, or say why it could not run.

    An unwired proxy is a ``warn``, not a failure: a first-light configuration deliberately has
    no egress plane, and there is no trust chain to establish. A *rejected* CA is ``critical``
    and makes
    doctor exit non-zero, because that is the state in which every later run looks clean while
    observing nothing. An inconclusive probe is a ``warn`` that says so rather than passing.
    """
    from bellwether.cli.interception_probe import run_interception_probe
    from bellwether.cli.run import build_proxy_provider

    provider = build_proxy_provider(loaded_config, environ=os.environ)
    if provider is None:
        return {
            "check": "TLS interception (§9.2)",
            "status": "warn",
            "detail": (
                "not probed: egress.image is empty, so no recording proxy is wired and the "
                "sandbox runs with no network at all (the first-light configuration). There is "
                "no trust chain to establish until a live config sets the sidecar image."
            ),
        }
    try:
        # The image that has to trust the CA is the **sandbox** image: that is what a run puts
        # on the internal bridge, and a sandbox that rejects the certificate is the whole state
        # this probe exists to rule out. Probing the sidecar instead would render an `ok` row
        # about a container no evaluation uses, and could not fail for the case that matters.
        probe = run_interception_probe(provider, client_image=loaded_config.sandbox.image)
    except (BellwetherError, OSError, subprocess.SubprocessError) as error:
        # A missing docker binary, a pull that outruns the client timeout, a daemon that goes
        # away mid-probe: none of these say anything about the CA, and none may abort doctor
        # with a traceback in place of the rest of its rows.
        return {
            "check": "TLS interception (§9.2)",
            "status": "warn",
            "detail": f"not probed: {type(error).__name__}: {error}",
        }
    status = "ok" if probe.confirmed else ("critical" if probe.ca_rejected else "warn")
    return {
        "check": "TLS interception (§9.2)",
        "status": status,
        "detail": f"{probe.reason} (probe host {probe.probe_host}, client exit {probe.exit_code})",
    }


def _estimate_gate(yes: bool) -> Callable[[RunEstimate], bool]:
    """Print the §19.1 estimate (always) and ask to proceed (only on an interactive terminal).

    The estimate goes to stderr so a ``--json`` result on stdout stays machine-readable. On a
    terminal without ``--yes`` the operator is asked; in CI there is nobody to ask, so the run
    proceeds after the estimate is printed — the flag skips the prompt, never the figures.
    """

    def gate(estimate: RunEstimate) -> bool:
        for line in render_estimate(estimate):
            typer.echo(line, err=True)
        if yes or not sys.stdin.isatty():
            return True
        return bool(typer.confirm("Proceed with the run?", default=False, err=True))

    return gate


def exit_code_for(result_exit_code: int, verdict: str, *, strict: bool) -> ExitCode:
    """The §20 exit code for one skill's result.

    ``ready`` and ``conditional`` are 0 and ``not_ready`` is 2 (revision 1 mapped ``conditional``
    to 1, which every CI system reads as failure — the opposite of the documented default).
    ``--strict`` promotes ``conditional`` to the failing code for repositories that want the
    stricter posture; it never touches ``ready``.
    """
    if result_exit_code == 2 or (strict and verdict == "conditional"):
        return ExitCode.NOT_READY
    return ExitCode.OK


def _split_csv(text: str | None) -> tuple[str, ...]:
    return tuple(part.strip() for part in (text or "").split(",") if part.strip())


def _parse_looks(text: str | None) -> tuple[int, ...] | None:
    """``--looks 6,12,20`` → ``(6, 12, 20)``; a non-integer refuses rather than being dropped."""
    if text is None:
        return None
    looks: list[int] = []
    for part in _split_csv(text):
        try:
            looks.append(int(part))
        except ValueError:
            raise BellwetherError(
                f"--looks expects comma-separated integers (e.g. 6,12,20), got {part!r}"
            ) from None
    if not looks:
        raise BellwetherError("--looks was given but names no look points")
    return tuple(looks)


def _expand_skill_args(
    args: list[str],
) -> list[tuple[Path, tuple[str, ...], PluginBundle | None]]:
    """Resolve each ``run`` argument to the skill directories it names.

    A plain skill directory passes through unchanged. A directory holding a
    ``plugin.json`` and no ``SKILL.md`` of its own is an Agent Plugin root
    (agent-plugins.org): it expands to the skills under its ``skills/``, each evaluated
    exactly as if named directly. The bundle-level observations — a manifest defect, an
    ``mcp.json`` whose servers this version never stands up — are returned alongside every
    expanded skill, so what was not evaluated travels with the skills that were. A plugin
    carrying no skills is a refusal, not an empty clean run.

    The bundle travels with each expanded skill (``None`` for a bare directory) so the
    executor can install the plugin *whole* — the layout a real client uses — rather than
    lifting each skill out of it (§5/§6/§18). The whole bundle rather than its root path,
    because the *name* it installs under has to be the bundle's own, not the host checkout
    directory's: the same plugin must land at the same container path on every machine.
    """
    from bellwether.skill import SKILL_FILE, is_plugin_root, load_plugin

    expanded: list[tuple[Path, tuple[str, ...], PluginBundle | None]] = []
    for arg in args:
        directory = Path(arg)
        if not is_plugin_root(directory) or (directory / SKILL_FILE).is_file():
            expanded.append((directory, (), None))
            continue
        bundle = load_plugin(directory)
        if not bundle.skill_dirs:
            raise BellwetherError(
                f"{arg} is an Agent Plugin carrying no skills under 'skills/'; there is "
                "nothing for a skill evaluation to run"
            )
        notes = list(bundle.problems)
        if bundle.has_mcp_servers:
            notes.append(
                f"plugin '{bundle.name}' declares MCP servers in mcp.json; this version "
                "does not stand plugin MCP servers up in the sandbox, so their behaviour "
                "is unobserved and outside this verdict — the evaluation covers the "
                "skill files alone"
            )
        expanded.extend((skill_dir, tuple(notes), bundle) for skill_dir in bundle.skill_dirs)
    return expanded


def _run_fixture(skill_dir: Path) -> Path:
    """The default workspace fixture for this skill's runs: its ``evals/fixtures/`` when it
    exists, else an empty workspace.

    The same lookup :func:`resolve_fixture` performs with no name, called rather than restated:
    this used to be a second copy of that rule, and when the resolver learned to refuse a
    fixtures directory that is a symlink out of the skill, the copy did not — a skill shipping
    ``evals/fixtures -> /root`` still had the host copy ``/root`` into its workspace.
    """
    from bellwether.cli.fixtures import resolve_fixture

    return resolve_fixture(skill_dir, None).path


@app.command()
def scan(
    # Optional at the parser so a bare `bellwether scan` is refused with exit 3 below: click's
    # own usage error is exit 2, which is this command's "a finding failed the threshold".
    skills: Annotated[
        list[str] | None,
        typer.Argument(help="Skill directories (or Agent Plugin roots) to scan."),
    ] = None,
    skills_from: Annotated[
        Path | None,
        typer.Option(
            "--skills-from",
            help="Read skill directories from this file, one per line — the output of "
            "`bellwether changed-skills`. An empty file is a quiet pass, not an error.",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="config.yaml; the policy beside it is read (§16.1)."),
    ] = None,
    policy_path: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            help="policy.yaml: each skill is held to its criticality's static gate — threshold, "
            "required scanners, severity floors (default: beside --config, if given).",
        ),
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Judge every skill under this profile.")
    ] = None,
    max_severity: Annotated[
        str | None,
        typer.Option(
            "--max-severity",
            help="Highest severity that does not fail the scan (low|medium|high|critical); "
            "overrides the policy. Default: the policy's, else medium.",
        ),
    ] = None,
    sarif: Annotated[
        Path | None, typer.Option("--sarif", help="Also write SARIF 2.1.0 to this file.")
    ] = None,
    markdown: Annotated[
        Path | None,
        typer.Option(
            "--markdown",
            help="Also write a Markdown summary (for $GITHUB_STEP_SUMMARY or a PR comment).",
        ),
    ] = None,
    scanner_sarif: Annotated[
        list[Path] | None,
        typer.Option(
            "--scanner-sarif",
            help="SARIF 2.1.0 written by an external scanner (Semgrep, Gitleaks, …) to merge "
            "into the static scan (§15); repeatable. Bellwether reads it, never runs the tool.",
        ),
    ] = None,
    json_output: JsonFlag = False,
) -> None:
    """Static pre-flight scan only (§15): nothing is executed.

    With a policy (``--policy``, or the one beside ``--config``), each skill is held to the
    static gate of the profile its criticality selects — the same profile ``bellwether run``
    would judge it under: its threshold, its required external scanners and its severity
    floors. Without one, the threshold is ``--max-severity`` (default ``medium``).

    Exits 2 when any finding is more severe than its skill's threshold, 3 when a skill, the
    policy or a scanner file cannot be read (or a required scanner was not supplied), 0
    otherwise — including for an empty ``--skills-from``, which is a pull request that touched
    no skill. Excerpts are reduced (invisible characters spelled out, matched secrets cut to
    their prefix) so posting the output does not carry the hidden text or the secret onward.
    """
    from dataclasses import replace

    from bellwether.cli.run import repository_relative_root, scan_with_delegates
    from bellwether.cli.run_plan import select_profile
    from bellwether.report import ScanSummaryEntry, render_scan_markdown, render_scan_sarif
    from bellwether.scan import SEVERITIES, ScanReport
    from bellwether.skill import load_skill, load_skill_manifest

    def refuse(message: str) -> NoReturn:
        typer.echo(f"error: {message}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    if not skills and skills_from is None:
        refuse("name at least one skill directory to scan, or pass --skills-from")
    if max_severity is not None and max_severity not in SEVERITIES[1:]:
        refuse(f"--max-severity must be one of {', '.join(SEVERITIES[1:])}, not {max_severity!r}")
    names = list(skills or ())
    if skills_from is not None:
        try:
            listed = skills_from.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            refuse(f"cannot read --skills-from {skills_from}: {type(error).__name__}")
        # Each line is a directory name exactly as `changed-skills` printed it: a name may begin
        # or end with a space, and stripping it would scan a different (or no) directory.
        names.extend(line for line in listed if line.strip())

    loaded_policy = None
    chosen_policy = policy_path or (_policy_beside(config, None) if config is not None else None)
    if chosen_policy is not None:
        try:
            loaded_policy = load_policy(chosen_policy)
        except (BellwetherError, OSError) as error:
            refuse(f"cannot load policy {chosen_policy}: {error}")
    elif profile is not None:
        refuse("--profile needs a policy to select from (--policy or --config)")

    try:
        expanded = _expand_skill_args(names)
    except BellwetherError as error:
        refuse(str(error))
    seen: set[Path] = set()
    entries: list[ScanSummaryEntry] = []
    reports: list[tuple[str, str | None, ScanReport]] = []
    for skill_dir, _notes, bundle in expanded:
        resolved = skill_dir.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            package = load_skill(skill_dir, load_evals=False)
        except BellwetherError as error:
            refuse(f"cannot load {skill_dir}: {error}")
        threshold = max_severity or "medium"
        profile_name: str | None = None
        required: list[str] = []
        floors: dict[str, str] = {}
        if loaded_policy is not None:
            try:
                manifest = load_skill_manifest(package.root)
                profile_name, spec = select_profile(
                    loaded_policy, manifest, profile_override=profile
                )
            except BellwetherError as error:
                refuse(f"cannot select a policy profile for {skill_dir}: {error}")
            static = spec.gates.static
            threshold = max_severity or static.max_severity_allowed
            required = list(static.required_scanners)
            floors = dict(static.scanner_min_severity)
        try:
            report = scan_with_delegates(
                package,
                tuple(scanner_sarif or ()),
                required=required,
                severity_floor=floors,
            )
        except BellwetherError as error:
            refuse(str(error))
        if bundle is not None:
            # A bundle's own files (plugin.json, mcp.json, client extensions) belong to no
            # skill; this scan reads skills. Said here so their absence is not read as clean.
            report = replace(
                report,
                notes=tuple(
                    sorted(
                        {
                            *report.notes,
                            f"plugin '{bundle.name}': bundle-level files outside its skills "
                            "are not part of a skill's static scan",
                        }
                    )
                ),
            )
        root = repository_relative_root(package.root)
        reports.append((package.name, root, report))
        entries.append(
            ScanSummaryEntry(
                name=package.name,
                root=root,
                report=report,
                threshold=threshold,
                profile=profile_name,
            )
        )

    failing = sum(len(entry.report.above(entry.threshold)) for entry in entries)
    lines: list[str] = []
    if not entries:
        lines.append("no skills to scan")
    for entry in entries:
        report = entry.report
        held = f", profile {entry.profile}" if entry.profile else ""
        lines.append(
            f"{entry.name} ({entry.root or '.'}): {len(report.files_scanned)} file(s), worst "
            f"{report.worst or 'none'}, threshold {entry.threshold}{held} [{report.ruleset}]"
        )
        for finding in report.findings:
            lines.append(
                f"  {finding.severity:<8} {finding.rule_id} {finding.path}:{finding.line} "
                f"{finding.message}"
            )
            if finding.excerpt:
                lines.append(f"           {finding.excerpt}")
        for unscanned in report.unscanned_outside_machinery():
            lines.append(f"  not scanned: {unscanned.path} ({unscanned.reason})")
        if report.machinery_unscanned:
            lines.append(
                f"  not scanned: {report.machinery_unscanned} file(s) under evals/ "
                "(evaluation machinery, never installed with the skill)"
            )
        for note in report.notes:
            lines.append(f"  note: {note}")
    lines.append(f"{failing} finding(s) above threshold" if failing else "nothing above threshold")
    if sarif is not None:
        sarif.write_text(render_scan_sarif(reports, version=__version__), encoding="utf-8")
    if markdown is not None:
        markdown.write_text(render_scan_markdown(entries), encoding="utf-8")
    _emit(
        {
            "failing": failing,
            "skills": [
                {
                    "name": entry.name,
                    "root": entry.root,
                    "profile": entry.profile,
                    "threshold": entry.threshold,
                    "above_threshold": len(entry.report.above(entry.threshold)),
                    **entry.report.as_record(),
                }
                for entry in entries
            ],
        },
        as_json=json_output,
        lines=lines,
    )
    if failing:
        raise typer.Exit(ExitCode.NOT_READY)


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
    skill: Annotated[str, typer.Argument(help="Skill directory (the one holding SKILL.md).")],
    source: Annotated[
        str,
        typer.Option(
            "--from",
            help="The observed evaluation: an eval id under --out, an eval directory, or a "
            "summary.json.",
        ),
    ],
    out: Annotated[
        Path, typer.Option("--out", help="The artifact directory eval ids are resolved under.")
    ] = RUN_OUTPUT_DIR,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing evals/manifest.yaml.")
    ] = False,
    json_output: JsonFlag = False,
) -> None:
    """Infer evals/manifest.yaml from an observed run, marked inferred-not-reviewed (§6.2).

    The declared scope is what the evaluation's capability profile recorded the skill
    doing — tools, paths read and written, egress hosts, processes — spelled out for a
    reviewer to tighten. Finding classes (a canary read, a blocked egress, a DNS lookup)
    are listed in the header as observed-but-not-declared, never laundered into an allowlist.
    """
    from bellwether.cli.diff import load_summary, resolve_summary
    from bellwether.cli.infer_manifest import describe, write_inferred_manifest
    from bellwether.skill import load_skill

    try:
        package = load_skill(Path(skill))
        summary = load_summary(resolve_summary(source, out_dir=out))
        path, scope = write_inferred_manifest(package, summary, force=force)
    except BellwetherError as error:
        typer.echo(f"bellwether init-manifest: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    _emit(
        {
            "path": str(path),
            "skill": package.name,
            "eval_id": summary.eval_id,
            "declared_scope": scope.as_declared_scope(),
            "undeclared": [{"class": tier1, "why": why} for tier1, why in scope.undeclared],
        },
        as_json=json_output,
        lines=[f"wrote {path} (INFERRED, NOT REVIEWED — from {summary.eval_id})", *describe(scope)],
    )


@app.command(name="trace")
def show_trace(
    run: Annotated[
        str, typer.Argument(help="A run id (from the report's evidence links) or a trace path.")
    ],
    out: Annotated[
        Path, typer.Option("--out", help="The artifact directory `bellwether run` wrote to.")
    ] = RUN_OUTPUT_DIR,
    eval_id: Annotated[
        str | None, typer.Option("--eval", help="Search only this evaluation's traces.")
    ] = None,
    plane: Annotated[
        list[str] | None,
        typer.Option("--plane", help="Show only actions from this plane (repeatable)."),
    ] = None,
    kind: Annotated[
        list[str] | None,
        typer.Option("--kind", help="Show only actions of this kind (repeatable)."),
    ] = None,
    json_output: JsonFlag = False,
) -> None:
    """Pretty-print or filter one ARF trace from an artifact tree (§20, §17.1).

    Finds the trace by the ``run_id`` its header carries — the id the report's evidence
    links name — under ``--out`` (optionally within one ``--eval``), or reads the path given.
    One line per action: seq, time, plane, kind, and what it did.
    """
    from bellwether.cli.trace_view import (
        TraceFilter,
        load_trace,
        locate_trace,
        render_trace_lines,
        trace_record,
    )

    try:
        path = locate_trace(run, out_dir=out, eval_id=eval_id)
        trace = load_trace(path)
    except BellwetherError as error:
        typer.echo(f"bellwether trace: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    filt = TraceFilter(planes=frozenset(plane or ()), kinds=frozenset(kind or ()))
    _emit(
        {"path": str(path), **trace_record(trace, filt)},
        as_json=json_output,
        lines=[f"trace    {path}", *render_trace_lines(trace, filt)],
    )


@app.command(name="report")
def render_report(
    evaluation: Annotated[
        str, typer.Argument(help="An eval id under --out, or an evaluation directory.")
    ],
    out: Annotated[
        Path, typer.Option("--out", help="The artifact directory eval ids are resolved under.")
    ] = RUN_OUTPUT_DIR,
    fmt: Annotated[str, typer.Option("--format", help="md, html, sarif, or all.")] = "all",
    to: Annotated[
        Path | None,
        typer.Option(
            "--to", help="Write here instead of the tree's own report/ directory (and root)."
        ),
    ] = None,
    json_output: JsonFlag = False,
) -> None:
    """Re-render a stored evaluation's report from its artifacts (§17.1, §20).

    Reads ``summary.json`` and ``metrics/figures.json`` and renders the PR comment, the
    HTML report and ``findings.sarif`` again — the same renderers ``bellwether run`` used, on the same inputs, so
    the bytes match what the run wrote. A tree written before the figures were persisted
    is refused with the reason, never rendered from a guess.
    """
    from bellwether.cli.rerender import rerender_tree

    try:
        written = rerender_tree(evaluation, out_dir=out, fmt=fmt, to=to)
    except BellwetherError as error:
        typer.echo(f"bellwether report: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    _emit(
        {"written": [str(path) for path in written]},
        as_json=json_output,
        lines=[f"wrote {path}" for path in written],
    )


@app.command()
def diff(
    eval_a: Annotated[
        str,
        typer.Argument(
            help="Baseline: an eval id under --out, an eval directory, or a summary.json."
        ),
    ],
    eval_b: Annotated[str, typer.Argument(help="Candidate, same forms.")],
    out: Annotated[
        Path, typer.Option("--out", help="The artifact directory eval ids are resolved under.")
    ] = RUN_OUTPUT_DIR,
    json_output: JsonFlag = False,
) -> None:
    """Diff two evaluations by their summary.json (§17.5, §20).

    Compares the verdict, every gate, the functional and consistency readings, the tier-1
    capability profile (expansion is the regression signal), security findings and spend.
    Components whose inputs are not comparable are named at the top rather than silently
    skipped; different schema versions are refused. Reports; does not apply the regression gate.
    """
    from bellwether.cli.diff import (
        diff_record,
        diff_summaries,
        load_summary,
        render_diff_markdown,
        resolve_summary,
    )

    try:
        summary_a = load_summary(resolve_summary(eval_a, out_dir=out))
        summary_b = load_summary(resolve_summary(eval_b, out_dir=out))
        result = diff_summaries(summary_a, summary_b)
    except BellwetherError as error:
        typer.echo(f"bellwether diff: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    _emit(
        diff_record(result),
        as_json=json_output,
        lines=[render_diff_markdown(result).rstrip("\n")],
    )


baseline_app = typer.Typer(
    name="baseline",
    help="Store, show, or clear a skill's regression baseline (§17.5).",
    no_args_is_help=True,
)
app.add_typer(baseline_app, name="baseline")

_BaselinesDir = Annotated[
    Path,
    typer.Option("--baselines", help="The baselines directory (default: .bellwether/baselines)."),
]


@baseline_app.command("set")
def baseline_set(
    skill: Annotated[str, typer.Argument(help="Skill name the baseline is for.")],
    source: Annotated[
        str,
        typer.Option(
            "--from",
            help="The evaluation to baseline: an eval id under --out, an eval directory, or "
            "a summary.json.",
        ),
    ],
    out: Annotated[
        Path, typer.Option("--out", help="The artifact directory eval ids are resolved under.")
    ] = RUN_OUTPUT_DIR,
    baselines: _BaselinesDir = Path(".bellwether/baselines"),
    json_output: JsonFlag = False,
) -> None:
    """Write <baselines>/<skill>.baseline.json from an evaluation's summary (§17.5).

    The record is the summary under its baseline key (skill, payload digest, canon version,
    target set, platform baseline version); the evaluation must be of the named skill.
    Commit the file: the regression gate reads it on every later run of the skill.
    """
    from bellwether.cli.baselines import baseline_from_summary, write_baseline
    from bellwether.cli.diff import load_summary, resolve_summary

    try:
        summary = load_summary(resolve_summary(source, out_dir=out))
        if summary.skill.name != skill:
            raise BellwetherError(
                f"{source!r} is an evaluation of skill {summary.skill.name!r}, not {skill!r}; "
                "a baseline is filed under the skill it was collected for"
            )
        record = baseline_from_summary(summary)
        path = write_baseline(record, baselines)
    except BellwetherError as error:
        typer.echo(f"bellwether baseline set: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    _emit(
        {
            "path": str(path),
            "skill": skill,
            "eval_id": record.eval_id,
            "digest": record.digest,
            "key": record.key.model_dump(),
        },
        as_json=json_output,
        lines=[
            f"wrote {path}",
            f"  baseline of {record.eval_id} (payload {record.key.payload_digest[:19]}…, "
            f"targets {record.key.target_set_digest[:19]}…); commit it so the regression gate "
            "reads it",
        ],
    )


@baseline_app.command("show")
def baseline_show(
    skill: Annotated[str, typer.Argument(help="Skill name.")],
    baselines: _BaselinesDir = Path(".bellwether/baselines"),
    json_output: JsonFlag = False,
) -> None:
    """Show the stored baseline's key, metadata, and headline readings."""
    from bellwether.cli.baselines import read_baseline_for

    try:
        record = read_baseline_for(baselines, skill)
    except BellwetherError as error:
        typer.echo(f"bellwether baseline show: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    if record is None:
        typer.echo(
            f"bellwether baseline show: no baseline for {skill!r} under {baselines}", err=True
        )
        raise typer.Exit(ExitCode.INFRASTRUCTURE)
    summary = record.summary
    _emit(
        {
            "skill": skill,
            "eval_id": record.eval_id,
            "digest": record.digest,
            "key": record.key.model_dump(),
            "metadata": record.metadata.model_dump(),
            "verdict": summary.verdict.status,
            "lower_bound": summary.functional.lower_bound,
            "bci": summary.consistency.bci,
            "tier1": summary.capability_profile.tier1,
        },
        as_json=json_output,
        lines=[
            f"baseline for {skill}: evaluation {record.eval_id} ({record.metadata.captured_at})",
            f"  digest            {record.digest}",
            f"  payload_digest    {record.key.payload_digest}",
            f"  canon_version     {record.key.canon_version}",
            f"  target_set_digest {record.key.target_set_digest}",
            f"  platform_baseline {record.key.platform_baseline_version or '(none)'}",
            f"  policy            {record.metadata.policy_profile} {record.metadata.policy_digest}",
            f"  verdict {summary.verdict.status}, lower bound {summary.functional.lower_bound}, "
            f"BCI {summary.consistency.bci}",
            f"  tier-1 core {summary.capability_profile.tier1.get('core', [])}",
        ],
    )


@baseline_app.command("clear")
def baseline_clear(
    skill: Annotated[str, typer.Argument(help="Skill name.")],
    baselines: _BaselinesDir = Path(".bellwether/baselines"),
    json_output: JsonFlag = False,
) -> None:
    """Remove the stored baseline; later runs compose no regression gate until one is set."""
    from bellwether.cli.baselines import baseline_path

    try:
        path = baseline_path(baselines, skill)
    except BellwetherError as error:
        typer.echo(f"bellwether baseline clear: {error}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE) from None
    if not path.is_file():
        typer.echo(f"bellwether baseline clear: no baseline for {skill!r} at {path}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)
    path.unlink()
    _emit({"removed": str(path)}, as_json=json_output, lines=[f"removed {path}"])


_RepoOption = Annotated[
    str | None, typer.Option("--repo", help="owner/repo (default: $GITHUB_REPOSITORY).")
]
_TokenEnvOption = Annotated[
    str, typer.Option("--token-env", help="Env var holding the GitHub token.")
]
_ApiRootOption = Annotated[
    str, typer.Option("--api-root", help="GitHub API root (for Enterprise).")
]


def _github_repository(repo: str | None, refuse: Callable[[str], NoReturn]) -> str:
    repository = repo or os.environ.get("GITHUB_REPOSITORY", "")
    if not repository:
        refuse("no repository: pass --repo or set GITHUB_REPOSITORY")
    return repository


def _github_token(token_env: str, refuse: Callable[[str], NoReturn]) -> str:
    token = os.environ.get(token_env, "")
    if not token:
        refuse(f"${token_env} is not set; the GitHub API needs a token")
    return token


@baseline_app.command("fetch")
def baseline_fetch(
    dest: Annotated[
        Path, typer.Option("--dest", help="Directory to write the evaluations' summaries into.")
    ],
    merge_sha: Annotated[
        str,
        typer.Option(
            "--merge-sha",
            help="The pushed commit (GITHUB_SHA on a push to main): the pull request it merged "
            "is found, and the evaluation run on that pull request's final head.",
        ),
    ] = "",
    run_id: Annotated[
        int | None,
        typer.Option(
            "--run-id",
            help="Take the evidence of this workflow run instead of looking one up — a manual "
            "(workflow_dispatch) evaluation, say.",
        ),
    ] = None,
    workflow: Annotated[
        str, typer.Option("--workflow", help="The evaluation workflow's file name.")
    ] = "bellwether.yml",
    artifact: Annotated[
        str, typer.Option("--artifact", help="The evidence artifact's name.")
    ] = "bellwether-evidence",
    out_prefix: Annotated[
        str,
        typer.Option(
            "--out-prefix", help="The output directory the workflow's evaluations.txt names."
        ),
    ] = ".bellwether-out/",
    repo: _RepoOption = None,
    token_env: _TokenEnvOption = "GITHUB_TOKEN",
    api_root: _ApiRootOption = "https://api.github.com",
    json_output: JsonFlag = False,
) -> None:
    """Fetch the evaluations a merged pull request was judged on (§17.5 ``baseline-pr``).

    Finds the pull request ``--merge-sha`` merged, the newest run of ``--workflow`` on its final
    head that uploaded ``--artifact``, and writes the summary of every evaluation that run lists
    to ``<dest>/<n>/summary.json``, with ``<dest>/source.json`` naming where they came from.
    Nothing is evaluated again. A push that merged no pull request, or a pull request no
    evaluation ran on, is not an error: ``found`` is false and the reason says why.
    """
    from bellwether.cli.baseline_pr import (
        artifact_of_run,
        download_artifact,
        find_evaluation_artifact,
        find_merged_pr,
        read_evaluations,
    )
    from bellwether.cli.pr import github_transport

    def refuse(message: str) -> NoReturn:
        typer.echo(f"bellwether baseline fetch: {message}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    if not merge_sha and run_id is None:
        refuse("pass --merge-sha (the merged commit) or --run-id (a run to take evidence from)")
    repository = _github_repository(repo, refuse)
    token = _github_token(token_env, refuse)
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    transport = github_transport(follow_redirects=False)
    payload: dict[str, Any] = {"found": False, "dest": str(dest), "merge_sha": merge_sha}

    def done(reason: str) -> None:
        payload["reason"] = reason
        _emit(payload, as_json=json_output, lines=[f"nothing to baseline: {reason}"])

    try:
        merged = None
        if merge_sha:
            merged = find_merged_pr(
                transport, repository, merge_sha, token=token, api_root=api_root
            )
            if merged is None and run_id is None:
                done(f"{merge_sha[:12]} merged no pull request (a direct push)")
                return
        if merged is not None:
            payload["pr"] = {
                "number": merged.number,
                "head_sha": merged.head_sha,
                "title": merged.title,
                "url": merged.url,
            }
        if run_id is not None:
            found = artifact_of_run(
                transport,
                repository,
                run_id,
                artifact=artifact,
                token=token,
                api_root=api_root,
                server_url=server,
            )
            if found is None:
                refuse(f"run {run_id} has no unexpired artifact named {artifact!r}")
            evidence = found
        else:
            assert merged is not None
            located = find_evaluation_artifact(
                transport,
                repository,
                workflow=workflow,
                head_sha=merged.head_sha,
                artifact=artifact,
                token=token,
                api_root=api_root,
                server_url=server,
            )
            if located is None:
                done(
                    f"no run of {workflow} on pull request #{merged.number}'s head "
                    f"{merged.head_sha[:12]} uploaded {artifact!r} (not labelled for evaluation, "
                    "or its evidence has expired)"
                )
                return
            evidence = located
        summaries = read_evaluations(
            download_artifact(
                transport, repository, evidence.artifact_id, token=token, api_root=api_root
            ),
            out_prefix=out_prefix,
        )
    except BellwetherError as error:
        refuse(str(error))
    if not summaries:
        payload.update(run_id=evidence.run_id, run_url=evidence.run_url)
        done(f"run {evidence.run_id} lists no completed evaluation")
        return
    dest.mkdir(parents=True, exist_ok=True)
    for index, summary in enumerate(summaries, start=1):
        target = dest / str(index)
        target.mkdir(exist_ok=True)
        (target / "summary.json").write_text(
            canonical_json(summary.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8"
        )
    payload.update(
        found=True,
        run_id=evidence.run_id,
        run_url=evidence.run_url,
        evaluations=[
            {
                "dir": str(dest / str(i)),
                "skill": s.skill.name,
                "eval_id": s.eval_id,
                "verdict": s.verdict.status,
            }
            for i, s in enumerate(summaries, start=1)
        ],
    )
    (dest / "source.json").write_text(canonical_json(payload, indent=2) + "\n", encoding="utf-8")
    _emit(
        payload,
        as_json=json_output,
        lines=[
            f"fetched {len(summaries)} evaluation(s) from {evidence.run_url}",
            *(f"  {s.skill.name}: {s.eval_id} ({s.verdict.status})" for s in summaries),
        ],
    )


@baseline_app.command("update")
def baseline_update(
    evaluations: Annotated[
        list[Path] | None,
        typer.Argument(help="Evaluation directories (each holding summary.json)."),
    ] = None,
    skills_from: Annotated[
        Path | None,
        typer.Option(
            "--skills-from",
            help="The merged tree's skill directories, one per line (`changed-skills` output).",
        ),
    ] = None,
    skill_dirs: Annotated[
        list[Path] | None,
        typer.Option("--skill", help="A skill directory in the merged tree (repeatable)."),
    ] = None,
    baselines: _BaselinesDir = Path(".bellwether/baselines"),
    body: Annotated[
        Path | None,
        typer.Option("--body", help="Write the baseline pull request's body (Markdown) here."),
    ] = None,
    source: Annotated[
        Path | None,
        typer.Option("--source", help="The source.json `baseline fetch` wrote, for the body."),
    ] = None,
    merge_sha: Annotated[
        str, typer.Option("--merge-sha", help="The merged commit, for the body.")
    ] = "",
    allow_not_ready: Annotated[
        bool,
        typer.Option(
            "--allow-not-ready",
            help="Baseline a not_ready evaluation too (by default it is skipped: its "
            "regressions would become the reference).",
        ),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Decide and report, but write no baseline.")
    ] = False,
    json_output: JsonFlag = False,
) -> None:
    """Write the baselines a merged pull request's evaluations observed (§17.5).

    Each evaluation is baselined only where its skill's payload digest equals that of the skill
    with its name in the merged tree — recomputed here from ``--skill``/``--skills-from`` — so an
    evaluation of an earlier push is never recorded as the merged skill's. A ``not_ready``
    evaluation is skipped unless ``--allow-not-ready``. ``changed`` in the output is how many
    files were written; zero means there is nothing to propose.
    """
    from bellwether.cli.baseline_pr import MergedPr, plan_baselines, render_baseline_pr_body
    from bellwether.cli.diff import load_summary
    from bellwether.skill import load_skill

    def refuse(message: str) -> NoReturn:
        typer.echo(f"bellwether baseline update: {message}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    directories = list(skill_dirs or ())
    if skills_from is not None:
        try:
            listed = skills_from.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            refuse(f"cannot read --skills-from {skills_from}: {type(error).__name__}")
        directories.extend(Path(line) for line in listed if line.strip())
    if not directories:
        refuse("name the merged tree's skills (--skill or --skills-from)")
    if not evaluations:
        refuse("name the evaluation directories to baseline")
    merged_payloads: dict[str, list[str]] = {}
    try:
        for directory in directories:
            package = load_skill(directory, load_evals=False)
            merged_payloads.setdefault(package.name, []).append(package.payload_digest)
        summaries = [load_summary(directory / "summary.json") for directory in evaluations]
        merged = None
        run_link = None
        if source is not None:
            recorded = json.loads(source.read_text(encoding="utf-8"))
            pr = recorded.get("pr") if isinstance(recorded, dict) else None
            if isinstance(pr, dict):
                merged = MergedPr(
                    int(pr["number"]),
                    str(pr["head_sha"]),
                    str(pr.get("title", "")),
                    str(pr.get("url", "")),
                )
            run_link = recorded.get("run_url") if isinstance(recorded, dict) else None
            merge_sha = merge_sha or str(recorded.get("merge_sha", ""))
        decisions = plan_baselines(
            summaries,
            merged_payloads,
            baselines,
            allow_not_ready=allow_not_ready,
            write=not dry_run,
        )
    except (BellwetherError, OSError, ValueError, KeyError) as error:
        refuse(f"{type(error).__name__}: {error}")
    written = [d for d in decisions if d.action == "write"]
    if body is not None:
        body.write_text(
            render_baseline_pr_body(
                decisions,
                merged=merged,
                merge_sha=merge_sha,
                run_url=run_link if isinstance(run_link, str) else None,
            ),
            encoding="utf-8",
        )
    _emit(
        {
            "changed": 0 if dry_run else len(written),
            "decisions": [
                {
                    "skill": d.skill,
                    "action": d.action,
                    "reason": d.reason,
                    "eval_id": d.eval_id,
                    "path": str(d.path) if d.path is not None else None,
                    "changed_key": list(d.changed_key),
                }
                for d in decisions
            ],
        },
        as_json=json_output,
        lines=[f"{d.skill}: {d.action} — {d.reason}" for d in decisions],
    )


@baseline_app.command("open-pr")
def baseline_open_pr(
    branch: Annotated[str, typer.Option("--branch", help="The pushed branch holding the update.")],
    body_file: Annotated[Path, typer.Option("--body-file", help="The pull request's body.")],
    title: Annotated[str, typer.Option("--title", help="The pull request's title.")] = (
        "chore: update baseline"
    ),
    base: Annotated[str, typer.Option("--base", help="The branch to merge into.")] = "main",
    repo: _RepoOption = None,
    token_env: _TokenEnvOption = "GITHUB_TOKEN",
    api_root: _ApiRootOption = "https://api.github.com",
    json_output: JsonFlag = False,
) -> None:
    """Open the baseline pull request from ``--branch``, or update the one already open."""
    from bellwether.cli.baseline_pr import upsert_pull_request
    from bellwether.cli.pr import github_transport

    def refuse(message: str) -> NoReturn:
        typer.echo(f"bellwether baseline open-pr: {message}", err=True)
        raise typer.Exit(ExitCode.INFRASTRUCTURE)

    repository = _github_repository(repo, refuse)
    token = _github_token(token_env, refuse)
    try:
        text_body = body_file.read_text(encoding="utf-8")
        result = upsert_pull_request(
            github_transport(),
            repository,
            branch=branch,
            base=base,
            title=title,
            body=text_body,
            token=token,
            api_root=api_root,
        )
    except (BellwetherError, OSError, UnicodeDecodeError) as error:
        refuse(str(error))
    _emit(
        {"number": result.number, "url": result.url, "action": result.action},
        as_json=json_output,
        lines=[f"{result.action} pull request #{result.number} {result.url}"],
    )


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
