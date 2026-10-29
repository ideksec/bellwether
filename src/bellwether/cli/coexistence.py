"""The library-wide trigger-collision matrix (§7.4), and its baseline.

The most under-tested failure mode of a skill library is a description broad enough to capture
activations meant for another skill. §7.4 measures it directly: every skill's probe scenarios are
run with **the whole library** offered beside it, and what is recorded is not whether the skill
under test activated but *which* skill did. The result is a matrix — one row per (skill, probe),
one count per winner — and the headline is its delta against the stored library baseline:
"`deploy-helper` began winning 4 of 12 activations previously won by `k8s-debug`."

Three constraints §7.4 sets, kept here:

- **Off the pull-request path.** This is the ``bellwether coexistence`` command, meant for the
  scheduled trigger; it is not composed into any verdict.
- **Two probe scenarios per skill.** The skill's ``probe: activation`` and ``probe:
  representative`` scenarios; where neither is marked, its first ``should_trigger`` scenario
  stands in as the representative and the §7.6 generated activation probe — the description
  echoed back — as the activation probe. A skill with no scenarios at all contributes the
  generated probe alone.
- **One target, a fixed ceiling.** The matrix measures a boolean, so it runs on one target at a
  fixed N of 12 (``descriptive_only``, §13.1); a second target is refused rather than averaged.

And one §9.4 restriction: on ``api-loop`` Bellwether writes the system prompt and decides how
descriptions are presented, so collisions measured there are measurements of Bellwether's own
prompt assembly. The command refuses ``api-loop`` without ``--force``, and a forced matrix is
labelled ``harness-specific: not portable`` in the file and on the page.

The baseline is keyed on the sorted set of member package digests: adding, removing or changing
any skill invalidates it, and the delta says so rather than comparing across different libraries.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from bellwether.assertions.engine import skill_name_matches
from bellwether.cli.estimate import RunEstimate
from bellwether.cli.fixtures import fixture_resolver
from bellwether.cli.orchestrator import EvalResult, TargetInfo
from bellwether.cli.run import ExecutorFactory, apply_matrix_options, run_evaluation
from bellwether.cli.run_plan import resolve_run
from bellwether.config.models.config import Config
from bellwether.config.models.policy import Policy
from bellwether.config.models.scenarios import Scenario, ScenarioSuite
from bellwether.determinism import canonical_json, stable_hash
from bellwether.errors import BellwetherError, SkillError
from bellwether.report.mdsafe import code, text
from bellwether.skill import SKILL_FILE, SkillPackage, generic_probe_suite, load_skill
from bellwether.skill.probes import ACTIVATION_PROBE_ID

__all__ = [
    "COEXISTENCE_N",
    "LIBRARY_BASELINE_FILE",
    "MATRIX_VERSION",
    "CoexistenceMatrix",
    "LibraryDelta",
    "LibraryMember",
    "ProbeCell",
    "collision_matrix",
    "compare_with_baseline",
    "library_key",
    "library_members",
    "load_library_baseline",
    "probe_scenarios_for",
    "render_coexistence_json",
    "render_coexistence_markdown",
    "resolve_coexistence_target",
    "run_coexistence",
    "write_library_baseline",
]

#: §7.4: "Run it on one target with ``n_max: 12``." Fixed-N, since a count needs a denominator.
COEXISTENCE_N = 12
#: ``.bellwether/baselines/_library.coexistence.json`` (§5, §7.4).
LIBRARY_BASELINE_FILE = "_library.coexistence.json"
#: The matrix record's own schema version, bumped on any change to its shape.
MATRIX_VERSION = "1"
#: The §9.4 label every ``api-loop`` matrix carries.
NOT_PORTABLE = "harness-specific: not portable"
#: The winner column for a run on which no skill activated at all.
NO_ACTIVATION = "(none)"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProbeCell(_Frozen):
    """One row of the matrix: one skill's probe, and who won its activations."""

    skill: str
    probe_id: str
    #: ``activation`` / ``representative``, and where the probe came from.
    probe_kind: str
    source: str
    runs: int
    #: Winner → number of runs on which that skill activated. A run on which two skills
    #: activated counts for both; a run with none counts under ``NO_ACTIVATION``. Sorted by name.
    winners: dict[str, int]

    def collisions(self) -> dict[str, int]:
        """Activations won by a skill other than the one probed."""
        return {
            name: count
            for name, count in self.winners.items()
            if name != self.skill and name != NO_ACTIVATION
        }


class CoexistenceMatrix(_Frozen):
    matrix_version: str = MATRIX_VERSION
    #: The sorted member package digests, hashed — what the baseline is keyed on.
    library_key: str
    members: tuple[str, ...]
    member_digests: dict[str, str]
    target: str
    harness: str
    #: ``False`` on ``api-loop`` (§9.4): the collisions measure Bellwether's prompt assembly.
    portable: bool
    n: int
    created_at: str
    bellwether_version: str
    cells: tuple[ProbeCell, ...]

    @property
    def digest(self) -> str:
        return stable_hash(render_coexistence_json(self))


class LibraryDelta(_Frozen):
    """The headline: what changed against the stored library baseline (§7.4)."""

    comparable: bool
    reason: str
    #: Human sentences, one per change, sorted. Empty where nothing moved or not comparable.
    changes: tuple[str, ...]
    baseline_digest: str | None = None


# ---------------------------------------------------------------------------
# The library and its probes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LibraryMember:
    """One skill of the library: the directory it loaded from, and the package."""

    path: Path
    package: SkillPackage

    @property
    def name(self) -> str:
        return self.package.name


def library_members(root: Path) -> list[LibraryMember]:
    """Every skill directly under ``root`` (§5: ``skills/<name>/SKILL.md``), sorted by directory.

    Fewer than two members is refused: a collision needs a competitor, and a one-skill matrix
    would read as a library with no collisions. The directory travels with the package — a
    declared name never chooses a directory.
    """
    if not root.is_dir():
        raise BellwetherError(f"{root} is not a directory; the library root holds skills/<name>/")
    members: list[LibraryMember] = []
    for child in sorted(root.iterdir(), key=lambda path: path.name):
        if not child.is_dir() or not (child / SKILL_FILE).is_file():
            continue
        try:
            members.append(LibraryMember(path=child, package=load_skill(child)))
        except SkillError as error:
            raise BellwetherError(f"library member {child} did not load: {error}") from error
    if len(members) < 2:
        raise BellwetherError(
            f"{root} holds {len(members)} skill(s); a coexistence matrix needs at least two, "
            "since a collision needs a competitor (§7.4)"
        )
    names = [member.name for member in members]
    if len(set(names)) != len(names):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        raise BellwetherError(
            f"two library members share a name ({', '.join(duplicates)}); which activated "
            "would be undecidable"
        )
    return members


def probe_scenarios_for(package: SkillPackage) -> list[tuple[Scenario, str, str]]:
    """The §7.4 probe scenarios of one skill: ``(scenario, kind, source)``.

    ``kind`` is ``activation`` or ``representative``; ``source`` says where it came from —
    ``marked`` (the skill's own ``probe:`` scenario), ``first_should_trigger`` (the fallback
    representative) or ``generated`` (the §7.6 activation probe). The activation probe is always
    present; the representative only where the skill has a ``should_trigger`` scenario to stand
    in. Fixed order, so the matrix rows are stable.
    """
    suite = package.scenarios
    scenarios = list(suite.scenarios) if suite is not None else []
    marked = {s.probe: s for s in scenarios if s.probe is not None}
    out: list[tuple[Scenario, str, str]] = []
    if "activation" in marked:
        out.append((marked["activation"], "activation", "marked"))
    else:
        generated = generic_probe_suite(package.name, package.description).scenarios
        probe = next(s for s in generated if s.id == ACTIVATION_PROBE_ID)
        out.append((probe, "activation", "generated"))
    if "representative" in marked:
        out.append((marked["representative"], "representative", "marked"))
    else:
        first = next(
            (s for s in scenarios if s.expectation == "should_trigger" and s.probe is None), None
        )
        if first is not None:
            out.append((first, "representative", "first_should_trigger"))
    return out


def library_key(packages: Sequence[SkillPackage]) -> str:
    """The sorted member package digests, hashed (§7.4, §4)."""
    return stable_hash("\n".join(sorted(package.package_digest for package in packages)))


# ---------------------------------------------------------------------------
# Running it
# ---------------------------------------------------------------------------


def _probe_suite(package: SkillPackage, probes: Sequence[Scenario]) -> ScenarioSuite:
    """The suite one member runs: its probes, under its own suite defaults (the fixture)."""
    defaults = package.scenarios.defaults if package.scenarios is not None else None
    return ScenarioSuite.model_validate(
        {
            "apiVersion": "bellwether/v1",
            "kind": "ScenarioSuite",
            **({"defaults": defaults.model_dump(exclude_none=True)} if defaults else {}),
            # The probes as the skill wrote them, minus any companions of their own: the
            # library is the competitor set here, and a scenario's also_load_skills would be
            # offered twice.
            "scenarios": [
                probe.model_dump(by_alias=True, exclude_none=True) | {"also_load_skills": []}
                for probe in probes
            ],
        }
    )


def resolve_coexistence_target(
    config: Config,
    policy: Policy,
    *,
    environ: Mapping[str, str],
    profile_override: str | None,
    target_aliases: Sequence[str],
    force: bool,
) -> TargetInfo:
    """The one target the matrix runs on, or a refusal (§7.4, §9.4).

    Resolved the way ``run`` resolves the matrix, before any member is loaded for execution, so
    a two-target profile or a bare ``api-loop`` costs an error message and not a library's worth
    of runs. A manifest is not consulted: the target set is the profile's, and the matrix is a
    property of the library, not of any one skill's declared criticality.
    """
    resolved = apply_matrix_options(
        resolve_run(config, policy, None, environ=environ, profile_override=profile_override),
        target_aliases=target_aliases,
        n_max_override=None,
        looks_override=None,
        repetitions=COEXISTENCE_N,
        require_every_alias=False,
    )
    targets = [rt.target for rt in resolved.targets]
    if len(targets) != 1:
        raise BellwetherError(
            f"coexistence runs on one target (§7.4) and profile '{resolved.profile_name}' "
            f"resolves to {len(targets)} ({', '.join(t.slug for t in targets)}); pass "
            "--targets <alias> to pick one"
        )
    target = targets[0]
    if target.harness == "api-loop" and not force:
        raise BellwetherError(
            f"target {target.slug} is api-loop, where Bellwether writes the system prompt and "
            "decides how descriptions are presented: collisions measured there are measurements "
            "of Bellwether's own prompt assembly, not of the skills' behaviour in a real harness "
            "(§9.4). Pick a claude-code target, or pass --force to run anyway with the result "
            f"labelled '{NOT_PORTABLE}'"
        )
    return target


def run_coexistence(
    *,
    config: Config,
    policy: Policy,
    members: Sequence[LibraryMember],
    target: TargetInfo,
    environ: Mapping[str, str],
    executor_factory_for: Callable[[str], ExecutorFactory],
    out_dir: Path,
    created_at: str,
    bellwether_version: str,
    profile_override: str | None = None,
    shared_fixture_root: Path | None = None,
    max_tokens_per_run: int = 1_000_000,
    on_estimate: Callable[[RunEstimate], bool] | None = None,
    on_member: Callable[[SkillPackage, EvalResult], None] | None = None,
) -> CoexistenceMatrix:
    """Run every member's probes against the whole library and build the matrix (§7.4).

    Each member is one ordinary evaluation (``run_evaluation``: the same sandbox, planes,
    estimate gate and artifact tree as ``run``) of its probe suite, with every other member
    offered as a companion and a fixed N of ``COEXISTENCE_N``. ``executor_factory_for`` takes
    the member's eval id and returns the factory ``run_evaluation`` builds the executor with.
    The per-member artifact trees land under ``out_dir`` as usual; the matrix is what the caller
    writes beside them.
    """
    packages = [member.package for member in members]
    results: dict[str, EvalResult] = {}
    probes_by_member: dict[str, list[tuple[Scenario, str, str]]] = {}
    for entry in members:
        package = entry.package
        probes = probe_scenarios_for(package)
        probes_by_member[package.name] = probes
        suite = _probe_suite(package, [probe for probe, _kind, _source in probes])
        probed = replace(package, scenarios=suite)
        others = tuple(other for other in packages if other.name != package.name)
        eval_id = f"coexistence-{package.slug}-{_stamp(created_at)}"
        result = run_evaluation(
            config=config,
            policy=policy,
            package=probed,
            fixture=_default_fixture(entry.path),
            fixture_for=fixture_resolver(entry.path, suite, shared_root=shared_fixture_root),
            companions_for=_constant(others),
            environ=environ,
            make_executor=executor_factory_for(eval_id),
            out_dir=out_dir,
            eval_id=eval_id,
            created_at=created_at,
            bellwether_version=bellwether_version,
            profile_override=profile_override,
            target_aliases=[target.model_alias],
            repetitions=COEXISTENCE_N,
            max_tokens_per_run=max_tokens_per_run,
            on_estimate=on_estimate,
        )
        results[package.name] = result
        if on_member is not None:
            on_member(package, result)
    return collision_matrix(
        results,
        packages,
        probes_by_member,
        target=target,
        created_at=created_at,
        bellwether_version=bellwether_version,
    )


def _constant(
    others: tuple[SkillPackage, ...],
) -> Callable[[Scenario], tuple[SkillPackage, ...]]:
    """Every probe of a member competes against the same library (§7.4: the full library)."""

    def companions(_scenario: Scenario) -> tuple[SkillPackage, ...]:
        return others

    return companions


def _stamp(created_at: str) -> str:
    parsed = dt.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    return f"{parsed:%Y%m%dT%H%M%SZ}"


def _default_fixture(skill_dir: Path) -> Path:
    from bellwether.cli.fixtures import resolve_fixture

    return resolve_fixture(skill_dir, None).path


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------


def collision_matrix(
    results: Mapping[str, EvalResult],
    packages: Sequence[SkillPackage],
    probes_by_member: Mapping[str, Sequence[tuple[Scenario, str, str]]],
    *,
    target: TargetInfo,
    created_at: str,
    bellwether_version: str,
) -> CoexistenceMatrix:
    """Count, per probe, which skill each run's activation went to.

    A winner is named as the library knows it: an activation Plane A recorded under a name that
    refers to a member — the same rule ``skill_activated`` uses, which understands the real
    CLI's ``bundle:skill`` qualification — is credited to that member; anything else is kept
    under the name recorded, so a harness that activated something outside the library is
    visible rather than dropped.
    """
    names = [package.name for package in packages]
    cells: list[ProbeCell] = []
    for package in packages:
        result = results[package.name]
        for probe, kind, source in probes_by_member[package.name]:
            runs = [
                run
                for reading in result.readings
                if reading.scenario_id == probe.id
                for run in reading.runs
            ]
            winners: dict[str, int] = {}
            for run in runs:
                credited = sorted({_credit(name, names) for name in run.activated_skills})
                for name in credited or [NO_ACTIVATION]:
                    winners[name] = winners.get(name, 0) + 1
            cells.append(
                ProbeCell(
                    skill=package.name,
                    probe_id=probe.id,
                    probe_kind=kind,
                    source=source,
                    runs=len(runs),
                    winners=dict(sorted(winners.items())),
                )
            )
    return CoexistenceMatrix(
        library_key=library_key(packages),
        members=tuple(names),
        member_digests={package.name: package.package_digest for package in packages},
        target=target.slug,
        harness=target.harness,
        portable=target.harness != "api-loop",
        n=COEXISTENCE_N,
        created_at=created_at,
        bellwether_version=bellwether_version,
        cells=tuple(cells),
    )


def _credit(activated: str, members: Sequence[str]) -> str:
    for member in members:
        if skill_name_matches(activated, member):
            return member
    return activated


# ---------------------------------------------------------------------------
# The baseline and the delta
# ---------------------------------------------------------------------------


def render_coexistence_json(matrix: CoexistenceMatrix) -> str:
    return canonical_json(matrix.model_dump(mode="json"), indent=2) + "\n"


def write_library_baseline(matrix: CoexistenceMatrix, baselines_dir: Path) -> Path:
    baselines_dir.mkdir(parents=True, exist_ok=True)
    path = baselines_dir / LIBRARY_BASELINE_FILE
    path.write_text(render_coexistence_json(matrix), encoding="utf-8")
    return path


def load_library_baseline(path: Path) -> CoexistenceMatrix:
    try:
        matrix = CoexistenceMatrix.model_validate_json(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise BellwetherError(f"cannot read library baseline {path}: {error}") from None
    except ValidationError as error:
        raise BellwetherError(f"{path} is not a valid library baseline: {error}") from None
    if matrix.matrix_version != MATRIX_VERSION:
        raise BellwetherError(
            f"{path} is a library baseline of version {matrix.matrix_version!r}; this build "
            f"reads {MATRIX_VERSION!r} — re-set it with `bellwether coexistence --set-baseline`"
        )
    return matrix


def compare_with_baseline(
    current: CoexistenceMatrix, baseline: CoexistenceMatrix | None
) -> LibraryDelta:
    """The §7.4 headline against the stored library baseline, or why there is none.

    Comparable only under the same library key (the sorted member digests — adding, removing or
    changing any skill invalidates it), the same target and the same N; a mismatch says which,
    and a full re-run with ``--set-baseline`` is the remedy, never a delta over different sets.
    """
    if baseline is None:
        return LibraryDelta(
            comparable=False,
            reason="no library baseline stored; run with --set-baseline to record this matrix",
            changes=(),
        )
    if baseline.library_key != current.library_key:
        added = sorted(set(current.members) - set(baseline.members))
        removed = sorted(set(baseline.members) - set(current.members))
        changed = sorted(
            name
            for name in set(current.members) & set(baseline.members)
            if current.member_digests[name] != baseline.member_digests[name]
        )
        parts = [
            f"{label}: {', '.join(names)}"
            for label, names in (("added", added), ("removed", removed), ("changed", changed))
            if names
        ]
        return LibraryDelta(
            comparable=False,
            reason=(
                "the library baseline was recorded for a different library ("
                + "; ".join(parts)
                + "); the key is the sorted set of member package digests, so any change "
                "invalidates it — re-run with --set-baseline before diffing resumes"
            ),
            changes=(),
            baseline_digest=baseline.digest,
        )
    if baseline.target != current.target or baseline.n != current.n:
        return LibraryDelta(
            comparable=False,
            reason=(
                f"the library baseline was recorded on {baseline.target} at N={baseline.n}; "
                f"this matrix is {current.target} at N={current.n}"
            ),
            changes=(),
            baseline_digest=baseline.digest,
        )
    before = {(cell.skill, cell.probe_id): cell for cell in baseline.cells}
    changes: list[str] = []
    for cell in current.cells:
        prior = before.get((cell.skill, cell.probe_id))
        if prior is None:
            changes.append(f"`{cell.skill}` gained a probe `{cell.probe_id}` the baseline lacks")
            continue
        for name in sorted(set(cell.winners) | set(prior.winners)):
            now, then = cell.winners.get(name, 0), prior.winners.get(name, 0)
            if now == then:
                continue
            who = "no skill" if name == NO_ACTIVATION else f"`{name}`"
            on = f"on `{cell.skill}`'s `{cell.probe_id}` probe"
            if name == cell.skill:
                verb = "regained" if now > then else "lost"
                changes.append(
                    f"`{cell.skill}` {verb} {abs(now - then)} of {cell.runs} activations {on} "
                    f"({then} → {now})"
                )
            elif now > then:
                changes.append(
                    f"{who} began winning {now - then} of {cell.runs} activations {on}, "
                    f"previously won by `{cell.skill}` or no skill ({then} → {now})"
                )
            else:
                changes.append(
                    f"{who} stopped winning {then - now} of {cell.runs} activations {on} "
                    f"({then} → {now})"
                )
    for key in set(before) - {(cell.skill, cell.probe_id) for cell in current.cells}:
        changes.append(f"`{key[0]}` no longer has the probe `{key[1]}` the baseline recorded")
    return LibraryDelta(
        comparable=True,
        reason="same library, target and N as the stored baseline",
        changes=tuple(sorted(changes)),
        baseline_digest=baseline.digest,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_coexistence_markdown(matrix: CoexistenceMatrix, delta: LibraryDelta) -> str:
    """The matrix and its headline as Markdown, every skill-controlled string escaped."""
    lines = ["## Bellwether coexistence matrix (§7.4)", ""]
    lines.append(
        f"Library of {len(matrix.members)} skill(s) on {code(matrix.target)}, "
        f"N={matrix.n} per probe · key `{matrix.library_key[:19]}…`"
    )
    if not matrix.portable:
        lines.append("")
        lines.append(
            f"**{NOT_PORTABLE}** — measured on `api-loop`, where Bellwether writes the system "
            "prompt and decides how descriptions are presented (§9.4)."
        )
    lines += ["", "### Headline", ""]
    if not delta.comparable:
        lines.append(f"Not compared: {text(delta.reason)}.")
    elif not delta.changes:
        lines.append("No change against the stored library baseline.")
    else:
        lines.extend(f"- {change}" for change in delta.changes)
    lines += ["", "### Collisions", ""]
    collisions = [(cell, cell.collisions()) for cell in matrix.cells]
    collisions = [(cell, won) for cell, won in collisions if won]
    if not collisions:
        lines.append("No probe's activation was won by another skill.")
    else:
        lines.append("| Skill | Probe | Won by another skill |")
        lines.append("|---|---|---|")
        for cell, won in collisions:
            who = ", ".join(f"{code(name)} {count}/{cell.runs}" for name, count in won.items())
            lines.append(
                f"| {code(cell.skill)} | {code(cell.probe_id)} ({cell.probe_kind}, "
                f"{cell.source}) | {who} |"
            )
    lines += ["", "### Matrix", ""]
    lines.append(
        "| Skill | Probe | " + " | ".join(f"{code(m)}" for m in matrix.members) + " | none |"
    )
    lines.append("|---|---|" + "---|" * (len(matrix.members) + 1))
    for cell in matrix.cells:
        counts = [str(cell.winners.get(member, 0)) for member in matrix.members]
        lines.append(
            f"| {code(cell.skill)} | {code(cell.probe_id)} | "
            + " | ".join(counts)
            + f" | {cell.winners.get(NO_ACTIVATION, 0)} |"
        )
    return "\n".join(lines) + "\n"
