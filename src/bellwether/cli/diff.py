"""``bellwether diff`` — compare two evaluations by their ``summary.json`` (§17.5, §20).

The ad-hoc comparison §17.5 asks for: what changed between two evaluations of a skill — the
verdict, each gate, the functional and consistency readings, the tier-1 capability profile
(whose *expansion* is the key regression signal; tier 3 churns too much to diff usefully),
the security findings, and the spend. It reads only the machine-readable rollup, so it works
on any two artifact trees, committed baselines included, with no re-analysis.

§17.5 is firm that a silently partial diff is worse than a refused one: components whose
inputs are not comparable are **skipped and named at the top** (the weighted figures under a
different ``weights_digest``), and two summaries at different schema versions are refused
outright. This module compares and renders; the policy that would turn a delta into a gate
(``gates.regression``) is not applied here — the diff reports, it does not decide.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from bellwether.determinism import format_float
from bellwether.errors import BellwetherError
from bellwether.report import Summary

__all__ = [
    "Delta",
    "EvalDiff",
    "diff_record",
    "diff_summaries",
    "load_summary",
    "render_diff_markdown",
    "resolve_summary",
]


def resolve_summary(ref: str, *, out_dir: Path) -> Path:
    """``ref`` is a ``summary.json``, an evaluation directory, or an eval id under ``out_dir``."""
    candidate = Path(ref)
    if candidate.is_file():
        return candidate
    if candidate.is_dir() and (candidate / "summary.json").is_file():
        return candidate / "summary.json"
    under_out = out_dir / ref / "summary.json"
    if under_out.is_file():
        return under_out
    raise BellwetherError(
        f"{ref!r} is not a summary.json, an evaluation directory holding one, or an evaluation "
        f"id under {out_dir} (looked for {under_out})"
    )


def load_summary(path: Path) -> Summary:
    """Parse a ``summary.json`` against the schema, or refuse naming the file and the error."""
    try:
        return Summary.model_validate_json(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise BellwetherError(f"cannot read {path}: {error}") from None
    except ValidationError as error:
        raise BellwetherError(f"{path} is not a valid summary.json: {error}") from None


@dataclass(frozen=True)
class Delta:
    """One field that differs: where it lives, and its value on each side, as rendered text."""

    component: str
    name: str
    before: str
    after: str


@dataclass(frozen=True)
class EvalDiff:
    """The comparison of two summaries, ready to render."""

    eval_a: str
    eval_b: str
    #: Components not compared, with why (§17.5) — rendered first, before any delta.
    skipped: tuple[tuple[str, str], ...]
    #: Context a reader needs before trusting the deltas: different policy, skill, or matrix.
    caveats: tuple[str, ...]
    changes: tuple[Delta, ...]
    #: Tier-1 classes present in B and not in A (core ∪ peripheral) — the regression signal.
    capabilities_added: tuple[str, ...] = ()
    capabilities_removed: tuple[str, ...] = ()
    sensitive_hits_added: tuple[str, ...] = ()
    sensitive_hits_removed: tuple[str, ...] = ()
    gates_only_in_a: tuple[str, ...] = ()
    gates_only_in_b: tuple[str, ...] = ()
    unchanged: tuple[str, ...] = field(default_factory=tuple)

    @property
    def capability_expanded(self) -> bool:
        return bool(self.capabilities_added)

    @property
    def identical(self) -> bool:
        return not (
            self.changes
            or self.capabilities_added
            or self.capabilities_removed
            or self.sensitive_hits_added
            or self.sensitive_hits_removed
            or self.gates_only_in_a
            or self.gates_only_in_b
        )


def _text(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return format_float(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_text(item) for item in value) + "]"
    return str(value)


def _tier1_classes(summary: Summary) -> set[str]:
    """Core ∪ peripheral tier-1 classes. ``core`` lists names; ``peripheral`` lists the
    §13.5.2 records (``{"tier1": ..., "frequency": ..., "tier3": [...]}``) — the class is
    the ``tier1`` key."""
    tier1 = summary.capability_profile.tier1
    classes: set[str] = set()
    for key in ("core", "peripheral"):
        value = tier1.get(key)
        if not isinstance(value, (list, tuple)):
            continue
        for item in value:
            if isinstance(item, str):
                classes.add(item)
            elif isinstance(item, Mapping) and isinstance(item.get("tier1"), str):
                classes.add(item["tier1"])
    return classes


def _sensitive_hits(summary: Summary) -> set[str]:
    value = summary.capability_profile.tier2.get("sensitive_hits")
    return {str(item) for item in value} if isinstance(value, (list, tuple)) else set()


def _tokens_total(summary: Summary) -> int | None:
    if summary.cost is None:
        return None
    return sum(int(v) for v in summary.cost.tokens.values())


def diff_summaries(a: Summary, b: Summary) -> EvalDiff:
    """Compare ``a`` (baseline) with ``b`` (candidate) under the §17.5 comparability rules."""
    if a.schema_version != b.schema_version:
        raise BellwetherError(
            f"summaries are at different schema versions ({a.eval_id}: {a.schema_version}, "
            f"{b.eval_id}: {b.schema_version}); refusing rather than comparing fields whose "
            "meaning may have changed (§17.5)"
        )

    skipped: list[tuple[str, str]] = []
    caveats: list[str] = []
    changes: list[Delta] = []
    unchanged: list[str] = []

    def compare(component: str, name: str, before: object, after: object) -> None:
        if before == after:
            unchanged.append(f"{component}.{name}")
        else:
            changes.append(Delta(component, name, _text(before), _text(after)))

    # Context first: a reader must know whether the two evaluations are of the same thing.
    if a.skill.name != b.skill.name:
        caveats.append(f"different skills: {a.skill.name!r} vs {b.skill.name!r}")
    compare("skill", "payload_digest", a.skill.payload_digest, b.skill.payload_digest)
    compare("skill", "package_digest", a.skill.package_digest, b.skill.package_digest)
    compare("skill", "criticality", a.skill.criticality, b.skill.criticality)
    if a.policy.digest != b.policy.digest:
        caveats.append(
            f"policies differ ({a.policy.profile} {a.policy.digest[:19]}… vs "
            f"{b.policy.profile} {b.policy.digest[:19]}…): gate thresholds may not be the same, "
            "so a changed gate status may reflect the policy, not the skill"
        )
    compare("policy", "profile", a.policy.profile, b.policy.profile)
    compare("bellwether", "version", a.bellwether_version, b.bellwether_version)
    compare("matrix", "targets", a.matrix.targets, b.matrix.targets)
    compare("matrix", "scenarios", a.matrix.scenarios, b.matrix.scenarios)
    compare("matrix", "design", a.matrix.design, b.matrix.design)
    compare("matrix", "looks", list(a.matrix.looks), list(b.matrix.looks))
    compare("matrix", "runs_completed", a.matrix.runs_completed, b.matrix.runs_completed)
    compare("matrix", "runs_evaluable", a.matrix.runs_evaluable, b.matrix.runs_evaluable)
    compare("matrix", "runs_timed_out", a.matrix.runs_timed_out, b.matrix.runs_timed_out)
    compare("matrix", "descriptive_only", a.matrix.descriptive_only, b.matrix.descriptive_only)

    # The verdict and every gate by name.
    compare("verdict", "status", a.verdict.status, b.verdict.status)
    gates_a = {gate.name: gate for gate in a.verdict.gates}
    gates_b = {gate.name: gate for gate in b.verdict.gates}
    for name in sorted(gates_a.keys() & gates_b.keys()):
        compare("gate", name, gates_a[name].status, gates_b[name].status)
    only_a = tuple(sorted(gates_a.keys() - gates_b.keys()))
    only_b = tuple(sorted(gates_b.keys() - gates_a.keys()))

    # Functional: the lower bound is the gated figure; the point estimate travels beside it.
    compare("functional", "pass_rate", a.functional.pass_rate, b.functional.pass_rate)
    compare("functional", "lower_bound", a.functional.lower_bound, b.functional.lower_bound)
    compare("functional", "n_evaluable", a.functional.n_evaluable, b.functional.n_evaluable)
    compare("functional", "decision", a.functional.decision, b.functional.decision)
    compare(
        "functional", "stopped_at_look", a.functional.stopped_at_look, b.functional.stopped_at_look
    )

    # Consistency: the weighted figures are comparable only under one weights_digest (§17.5).
    if a.consistency.weights_digest != b.consistency.weights_digest:
        skipped.append(
            (
                "consistency.bci, consistency.capability_jaccard_weighted",
                "weights_digest differs "
                f"({a.consistency.weights_digest[:19]}… vs {b.consistency.weights_digest[:19]}…), "
                "so the risk-weighted figures are not comparable (§17.5)",
            )
        )
    else:
        compare("consistency", "bci", a.consistency.bci, b.consistency.bci)
        compare(
            "consistency",
            "capability_jaccard_weighted",
            a.consistency.capability_jaccard_weighted,
            b.consistency.capability_jaccard_weighted,
        )
    compare(
        "consistency",
        "capability_jaccard_plain",
        a.consistency.capability_jaccard_plain,
        b.consistency.capability_jaccard_plain,
    )
    compare("consistency", "annotation", a.consistency.annotation, b.consistency.annotation)
    compare(
        "consistency",
        "trajectory_clusters",
        a.consistency.trajectory_clusters,
        b.consistency.trajectory_clusters,
    )
    compare(
        "consistency",
        "trajectory_at_noise_floor",
        a.consistency.trajectory_at_noise_floor,
        b.consistency.trajectory_at_noise_floor,
    )

    # Capability profile: tier 1 by set difference (the regression signal), tier 2 sensitive
    # hits by set difference, tier 3 deliberately not diffed (§4.1: it churns).
    t1_a, t1_b = _tier1_classes(a), _tier1_classes(b)
    hits_a, hits_b = _sensitive_hits(a), _sensitive_hits(b)
    compare(
        "capability_profile",
        "rare_high_risk",
        len(a.capability_profile.rare_high_risk),
        len(b.capability_profile.rare_high_risk),
    )
    skipped.append(("capability_profile.tier3", "tier 3 churns too much to diff usefully (§4.1)"))

    # Security findings and spend.
    compare("security", "canary_leaks", len(a.security.canary_leaks), len(b.security.canary_leaks))
    compare(
        "security",
        "runtime_findings",
        sorted(a.security.runtime.keys()),
        sorted(b.security.runtime.keys()),
    )
    if a.cost is not None and b.cost is not None:
        compare("cost", "usd", a.cost.usd, b.cost.usd)
        compare("cost", "wall_clock_s", a.cost.wall_clock_s, b.cost.wall_clock_s)
        compare("cost", "tokens_total", _tokens_total(a), _tokens_total(b))
    else:
        skipped.append(("cost", "one or both summaries carry no cost block"))

    return EvalDiff(
        eval_a=a.eval_id,
        eval_b=b.eval_id,
        skipped=tuple(skipped),
        caveats=tuple(caveats),
        changes=tuple(changes),
        capabilities_added=tuple(sorted(t1_b - t1_a)),
        capabilities_removed=tuple(sorted(t1_a - t1_b)),
        sensitive_hits_added=tuple(sorted(hits_b - hits_a)),
        sensitive_hits_removed=tuple(sorted(hits_a - hits_b)),
        gates_only_in_a=only_a,
        gates_only_in_b=only_b,
        unchanged=tuple(unchanged),
    )


def _bullets(items: Sequence[str]) -> list[str]:
    return [f"- {item}" for item in items]


def render_diff_markdown(diff: EvalDiff) -> str:
    """The human rendering: skipped components first (§17.5), then the deltas by component."""
    lines = [f"# bellwether diff — `{diff.eval_a}` → `{diff.eval_b}`", ""]
    if diff.skipped:
        lines.append(
            "**Not compared** (§17.5 — a silently partial diff is worse than a refused one):"
        )
        lines += [f"- `{component}`: {why}" for component, why in diff.skipped]
        lines.append("")
    if diff.caveats:
        lines.append("**Read with care:**")
        lines += _bullets(diff.caveats)
        lines.append("")
    if diff.identical:
        lines.append("No differences in the compared components.")
        return "\n".join(lines) + "\n"

    if diff.capability_expanded:
        lines.append(
            "**Tier-1 capability expansion** — the key regression signal (§17.5): "
            + ", ".join(f"`{name}`" for name in diff.capabilities_added)
        )
        lines.append("")
    if diff.capabilities_removed:
        lines.append(
            "Tier-1 capabilities no longer exercised: "
            + ", ".join(f"`{name}`" for name in diff.capabilities_removed)
        )
        lines.append("")
    if diff.sensitive_hits_added or diff.sensitive_hits_removed:
        lines.append("Sensitive-directory hits (§13.5.4):")
        lines += [f"- added `{hit}`" for hit in diff.sensitive_hits_added]
        lines += [f"- removed `{hit}`" for hit in diff.sensitive_hits_removed]
        lines.append("")
    if diff.gates_only_in_a or diff.gates_only_in_b:
        lines.append("Gates present on one side only:")
        lines += [f"- `{name}` only in `{diff.eval_a}`" for name in diff.gates_only_in_a]
        lines += [f"- `{name}` only in `{diff.eval_b}`" for name in diff.gates_only_in_b]
        lines.append("")
    if diff.changes:
        lines += ["| component | field | before | after |", "|---|---|---|---|"]
        lines += [
            f"| {delta.component} | {delta.name} | {delta.before} | {delta.after} |"
            for delta in diff.changes
        ]
        lines.append("")
    lines.append(f"{len(diff.unchanged)} compared field(s) unchanged.")
    return "\n".join(lines) + "\n"


def diff_record(diff: EvalDiff) -> dict[str, Any]:
    """The machine-readable rendering for ``--json``."""
    return {
        "eval_a": diff.eval_a,
        "eval_b": diff.eval_b,
        "identical": diff.identical,
        "capability_expanded": diff.capability_expanded,
        "skipped": [{"component": component, "why": why} for component, why in diff.skipped],
        "caveats": list(diff.caveats),
        "changes": [
            {
                "component": delta.component,
                "field": delta.name,
                "before": delta.before,
                "after": delta.after,
            }
            for delta in diff.changes
        ],
        "capabilities_added": list(diff.capabilities_added),
        "capabilities_removed": list(diff.capabilities_removed),
        "sensitive_hits_added": list(diff.sensitive_hits_added),
        "sensitive_hits_removed": list(diff.sensitive_hits_removed),
        "gates_only_in_a": list(diff.gates_only_in_a),
        "gates_only_in_b": list(diff.gates_only_in_b),
        "unchanged": list(diff.unchanged),
    }
