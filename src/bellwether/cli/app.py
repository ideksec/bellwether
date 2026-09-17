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
from bellwether.cli.orchestrator import ENFORCED_SECURITY_RUNTIME_DISPOSITIONS, TargetInfo
from bellwether.cli.preflight import available_planes, preflight_failures
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

    # §15 static scan is not built yet (v0.2). A policy that requires it would otherwise be a
    # silent no-op — a required check that reads as passed. Surface it here rather than hide it.
    _static_profiles = [loaded_policy.defaults, *loaded_policy.profiles.values()]
    if any(profile.gates.static.require_scan for profile in _static_profiles):
        checks.append(
            {
                "check": "static scan (§15)",
                "status": "warn",
                "detail": (
                    "policy sets gates.static.require_scan, but the static scanner is not built "
                    "in this version (v0.2 work package); it will not run — set require_scan: "
                    "false until it lands, or treat scan findings as unavailable"
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
        "the CA-in-the-loop probe is CI-only (WP-14's live half)",
    ),
    (
        "internal bridge blocks direct UDP/53 to a public resolver",
        "the §3.3 invariant-3 live probe is CI-only (WP-15's live half)",
    ),
    (
        "fanotify markable; eBPF loadable by the host agent",
        "read and process capture are v0.2/v0.3; neither plane is built yet",
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
    budget_usd: Annotated[
        float | None,
        typer.Option(
            "--budget-usd",
            help="Override the profile's max_cost_usd for this evaluation (§19.1); the cost gate "
            "is composed only where every target alias has providers.<name>.pricing.",
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
        build_proxy_provider,
        build_resolver_provider,
        claude_code_providers,
        run_evaluation,
        sandbox_executor_factory,
    )
    from bellwether.determinism import stable_hash
    from bellwether.harness import RunLimits
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
    for skill_dir, bundle_notes in work:
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
            eval_id = f"{package.name}-{dt.datetime.now(dt.UTC):%Y%m%dT%H%M%SZ}"
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
                environ=os.environ,
                make_executor=sandbox_executor_factory(
                    loaded_config.sandbox.image,
                    out / eval_id / "runs",
                    eval_id,
                    limits=RunLimits(max_total_tokens=max_tokens),
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
                ),
                # The artifact writer appends <eval_id> itself, so the parent is `out`;
                # passing `out / eval_id` here doubled it and hid the report from pr-comment.
                out_dir=out,
                eval_id=eval_id,
                created_at=dt.datetime.now(dt.UTC).isoformat(),
                bellwether_version=__version__,
                profile_override=profile,
            )
        except (BellwetherError, ConfigurationError) as error:
            typer.echo(f"bellwether run [{skill_dir}]: {error}", err=True)
            raise typer.Exit(ExitCode.INFRASTRUCTURE) from None

        if exit_code_for(result.exit_code, result.verdict.verdict, strict=strict) != ExitCode.OK:
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
    a changed file is attributed to its nearest such ancestor). A plugin-level change inside
    an Agent Plugin bundle (a directory with a ``plugin.json``) is attributed to every skill
    the plugin carries. Empty output means the change touched no skill, so nothing needs
    evaluating. Always exits 0: "no skills changed" is a normal result, not an error.
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


def _expand_skill_args(args: list[str]) -> list[tuple[Path, tuple[str, ...]]]:
    """Resolve each ``run`` argument to the skill directories it names.

    A plain skill directory passes through unchanged. A directory holding a
    ``plugin.json`` and no ``SKILL.md`` of its own is an Agent Plugin root
    (agent-plugins.org): it expands to the skills under its ``skills/``, each evaluated
    exactly as if named directly. The bundle-level observations — a manifest defect, an
    ``mcp.json`` whose servers this version never stands up — are returned alongside every
    expanded skill, so what was not evaluated travels with the skills that were. A plugin
    carrying no skills is a refusal, not an empty clean run.
    """
    from bellwether.skill import SKILL_FILE, is_plugin_root, load_plugin

    expanded: list[tuple[Path, tuple[str, ...]]] = []
    for arg in args:
        directory = Path(arg)
        if not is_plugin_root(directory) or (directory / SKILL_FILE).is_file():
            expanded.append((directory, ()))
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
        expanded.extend((skill_dir, tuple(notes)) for skill_dir in bundle.skill_dirs)
    return expanded


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
    # v0.2, matching what `doctor` says about require_scan — these two must agree, or a user
    # reading both is told the scanner lands in two different places.
    _not_yet("scan", "v0.2 (the §15 static scanner)", "static analysis has not landed")


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
    run: Annotated[
        str, typer.Argument(help="A run id (from the report's evidence links) or a trace path.")
    ],
    out: Annotated[
        Path, typer.Option("--out", help="The artifact directory `bellwether run` wrote to.")
    ] = Path("bellwether-runs"),
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
    ] = Path("bellwether-runs"),
    fmt: Annotated[str, typer.Option("--format", help="md, html, or all.")] = "all",
    to: Annotated[
        Path | None,
        typer.Option("--to", help="Write here instead of the tree's own report/ directory."),
    ] = None,
    json_output: JsonFlag = False,
) -> None:
    """Re-render a stored evaluation's report from its artifacts (§17.1, §20).

    Reads ``summary.json`` and ``metrics/figures.json`` and renders the PR comment and the
    HTML report again — the same renderers ``bellwether run`` used, on the same inputs, so
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
    ] = Path("bellwether-runs"),
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
    ] = Path("bellwether-runs"),
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
