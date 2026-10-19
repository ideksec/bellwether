"""Model drift: the nightly re-evaluation, read against each skill's baseline (§18.1, §18.4).

§18.1: the nightly full-library run "is how you catch **model drift**: the same skills, the
same tests, a new model version". §18.4 step 6: "a drift failure opens an issue
automatically". The run itself is an ordinary ``bellwether run`` of every skill with the cache
off; its regression gate already compares the evaluation with the stored baseline under the
§17.5 key rules. This module reads what that comparison found and decides, per skill:

* ``drift`` — the regression gate **blocks**, or the verdict is worse than the baseline's
  (``ready`` → ``conditional`` → ``not_ready``). An issue is opened.
* ``warn`` — the regression gate warns (a new sensitive-directory hit under the default
  policy). Reported, no issue: §18.4 opens one on a drift *failure*.
* ``stable`` — compared, and nothing regressed. An open drift issue for the skill is closed.
* ``not_comparable`` — a baseline exists but the §17.5 key rules it incomparable (a new canon
  version, a different target set); the evaluation's note says which. Nothing can be said
  about drift until the baseline is re-set, and the report says so rather than reading clean.
* ``no_baseline`` — nothing to compare against.

Which model answered is reported beside the verdict, per target, from ``matrix.models``
(the reported id where the provider gave one): the same alias served by a different model is
the usual cause, and the reader should not have to dig it out of a trace. A model change on
its own is not drift — a new snapshot that behaves the same is the outcome hoped for.

Issues are keyed per skill by a marker in the body, so each skill has at most one open drift
issue; it is edited in place, commented on only when its findings change, and closed when a
later run is stable. A night that finds the same drift as the last one adds nothing.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Literal

from bellwether.cli.baselines import BaselineRecord
from bellwether.cli.pr import GITHUB_API_ROOT, GitHubTransport, auth_headers
from bellwether.errors import BellwetherError
from bellwether.report import Summary
from bellwether.report.mdsafe import code, text

__all__ = [
    "DriftReading",
    "DriftStatus",
    "IssueAction",
    "drift_key",
    "read_drift",
    "render_drift_issue",
    "render_drift_markdown",
    "upsert_drift_issues",
]

DriftStatus = Literal["drift", "warn", "stable", "not_comparable", "no_baseline"]

_VERDICT_RANK = {"ready": 0, "conditional": 1, "not_ready": 2}
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
#: How many pages of open issues are searched for an existing drift issue (100 per page).
_MAX_ISSUE_PAGES = 10


def drift_key(skill: str) -> str:
    """The skill's drift-issue key: a fixed domain plus the name, hashed — so no skill name
    can collide with another skill's key or with any other Bellwether marker."""
    return hashlib.sha256(b"bellwether-drift/v1\0" + skill.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class DriftReading:
    """One skill's nightly evaluation, read against its baseline."""

    skill: str
    status: DriftStatus
    eval_id: str
    verdict: str
    baseline_verdict: str | None = None
    baseline_eval_id: str | None = None
    #: What regressed, one line each — the content of the issue, and what its digest covers.
    findings: tuple[str, ...] = ()
    #: Why no comparison was made, where none was.
    reason: str = ""
    #: target slug → (baseline's models, tonight's models), for targets where they differ or
    #: where the baseline recorded none.
    model_changes: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]] = field(
        default_factory=dict
    )
    models: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def findings_digest(self) -> str:
        """What changes when the drift changes — the verdict, and every finding line."""
        material = json.dumps([self.status, self.verdict, list(self.findings)], sort_keys=True)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _gate(summary: Summary, name: str) -> tuple[str, str] | None:
    for gate in summary.verdict.gates:
        if gate.name == name:
            return gate.status, gate.reason
    return None


def _regression_findings(summary: Summary) -> list[str]:
    regression = summary.regression
    if regression is None:
        return []
    deltas = regression.deltas
    found: list[str] = []
    added = deltas.get("capabilities_added")
    if isinstance(added, list) and added:
        found.append("new tier-1 capabilities: " + ", ".join(str(item) for item in added))
    removed = deltas.get("capabilities_removed")
    if isinstance(removed, list) and removed:
        found.append("tier-1 capabilities no longer seen: " + ", ".join(str(i) for i in removed))
    hits = deltas.get("sensitive_hits_added")
    if isinstance(hits, list) and hits:
        found.append("new sensitive-directory hits: " + ", ".join(str(item) for item in hits))
    for name, label in (("lower_bound", "pass-rate lower bound"), ("bci", "BCI")):
        movement = deltas.get(name)
        if isinstance(movement, Mapping):
            drop = movement.get("drop")
            if isinstance(drop, (int, float)) and drop > 0:
                found.append(
                    f"{label} {movement.get('before')} → {movement.get('after')} (drop {drop})"
                )
    return found


def read_drift(summary: Summary, baseline: BaselineRecord | None) -> DriftReading:
    """Classify one evaluation against its stored baseline (``None`` where none is stored)."""
    models = {slug: tuple(ids) for slug, ids in sorted(summary.matrix.models.items())}
    base = DriftReading(
        skill=summary.skill.name,
        status="no_baseline",
        eval_id=summary.eval_id,
        verdict=summary.verdict.status,
        models=models,
    )
    if baseline is None:
        return replace(base, reason="no baseline is stored for this skill")
    before = baseline.summary
    then = {slug: tuple(ids) for slug, ids in before.matrix.models.items()}
    base = replace(
        base,
        baseline_verdict=before.verdict.status,
        baseline_eval_id=baseline.eval_id,
        model_changes={
            slug: (then.get(slug, ()), now)
            for slug, now in models.items()
            if then.get(slug, ()) != now
        },
    )
    gate = _gate(summary, "regression")
    if gate is None:
        notes = [note for note in summary.verdict.notes if "regression not composed" in note]
        return replace(
            base,
            status="not_comparable",
            reason=notes[0] if notes else "the regression gate was not composed",
        )
    status, gate_reason = gate
    findings: list[str] = []
    worse = _VERDICT_RANK.get(summary.verdict.status, 2) > _VERDICT_RANK.get(
        before.verdict.status, 2
    )
    if worse:
        findings.append(f"verdict {before.verdict.status} → {summary.verdict.status}")
        findings += [
            f"gate {gate_summary.name} blocks: {gate_summary.reason}"
            for gate_summary in summary.verdict.gates
            if gate_summary.status == "block" and gate_summary.name != "regression"
        ]
    findings += _regression_findings(summary)
    if status == "block" or worse:
        if status == "block":
            findings.insert(0, f"regression gate blocks: {gate_reason}")
        return replace(base, status="drift", findings=tuple(findings))
    if status == "warn":
        return replace(
            base, status="warn", findings=(f"regression gate warns: {gate_reason}", *findings)
        )
    return replace(base, status="stable", findings=tuple(findings))


def _models_line(models: Sequence[str]) -> str:
    return ", ".join(code(model) for model in models) if models else "not recorded"


def render_drift_markdown(readings: Sequence[DriftReading], *, run_url: str | None) -> str:
    """The run's summary: one row per skill, then the detail of each that drifted."""
    lines = ["## Bellwether nightly drift run", ""]
    if run_url:
        lines += [f"Run: {run_url}", ""]
    if not readings:
        return "\n".join([*lines, "No skill was evaluated.", ""])
    lines += ["| Skill | Result | Verdict | Baseline |", "|---|---|---|---|"]
    for reading in sorted(readings, key=lambda r: r.skill):
        baseline = (
            f"{code(reading.baseline_verdict)} ({code(reading.baseline_eval_id)})"
            if reading.baseline_verdict
            else "none"
        )
        lines.append(
            f"| {code(reading.skill)} | **{reading.status}** | {code(reading.verdict)} | "
            f"{baseline} |"
        )
    lines.append("")
    for reading in sorted(readings, key=lambda r: r.skill):
        detail = list(reading.findings)
        if reading.reason:
            detail.append(reading.reason)
        for slug, (then, now) in sorted(reading.model_changes.items()):
            detail.append(
                f"{slug}: served by {', '.join(now) or 'not recorded'} "
                f"(baseline: {', '.join(then) or 'not recorded'})"
            )
        if detail:
            lines += [f"### {code(reading.skill)} — {reading.status}", ""]
            lines += [f"- {text(item)}" for item in detail]
            lines.append("")
    return "\n".join(lines)


def _marker(skill: str) -> str:
    return f"<!-- bellwether-drift:{drift_key(skill)} -->"


def _digest_marker(reading: DriftReading) -> str:
    return f"<!-- bellwether-drift-findings:{reading.findings_digest} -->"


def render_drift_issue(reading: DriftReading, *, run_url: str | None) -> tuple[str, str]:
    """The drift issue's title and body for one skill."""
    title = f"Bellwether drift: {reading.skill}"
    lines = [
        f"The nightly evaluation of {code(reading.skill)} regressed against its stored baseline "
        "(§18.1). The same skill and scenarios were run with the cache off; what changed is the "
        "model, the provider, or the environment underneath them.",
        "",
        f"- Verdict: {code(reading.verdict)} (baseline {code(reading.baseline_verdict)}, "
        f"evaluation {code(reading.baseline_eval_id)})",
        f"- Tonight's evaluation: {code(reading.eval_id)}",
    ]
    if run_url:
        lines.append(f"- Run and evidence: {run_url}")
    lines += ["", "**What regressed**", ""]
    lines += [f"- {text(item)}" for item in reading.findings]
    lines += ["", "**Which model answered**", ""]
    for slug, now in sorted(reading.models.items()):
        then = reading.model_changes.get(slug)
        change = f" — baseline: {_models_line(then[0])}" if then is not None else " (unchanged)"
        lines.append(f"- {code(slug)}: {_models_line(now)}{change}")
    if not reading.models:
        lines.append("- not recorded by this evaluation")
    lines += [
        "",
        "If the new behaviour is intended, re-set the baseline from tonight's evaluation "
        "(`bellwether baseline set`); this issue closes itself on the next stable night.",
        "",
        _digest_marker(reading),
        _marker(reading.skill),
    ]
    return title, "\n".join(lines) + "\n"


IssueAction = Literal["opened", "updated", "unchanged", "closed", "none"]


def _open_drift_issues(
    transport: GitHubTransport, root: str, token: str
) -> dict[str, Mapping[str, object]]:
    """Open issues carrying a drift marker, by marker — the bot's own only."""
    found: dict[str, Mapping[str, object]] = {}
    for page in range(1, _MAX_ISSUE_PAGES + 1):
        query = urllib.parse.urlencode({"state": "open", "per_page": 100, "page": page})
        response = transport("GET", f"{root}/issues?{query}", auth_headers(token), None)
        if response.status != 200:
            raise BellwetherError(f"listing issues failed with HTTP {response.status}")
        try:
            issues = json.loads(response.body)
        except ValueError:
            raise BellwetherError("listing issues: the response is not JSON") from None
        if not isinstance(issues, list):
            raise BellwetherError("listing issues: expected a list")
        for issue in issues:
            if not isinstance(issue, Mapping) or "pull_request" in issue:
                continue
            user = issue.get("user")
            body = issue.get("body")
            if not (isinstance(user, Mapping) and user.get("type") == "Bot"):
                continue
            if isinstance(body, str):
                match = re.search(r"<!-- bellwether-drift:([0-9a-f]{16}) -->\s*$", body)
                if match and match.group(1) not in found:
                    found[match.group(1)] = issue
        if len(issues) < 100:
            break
    return found


def _call(
    transport: GitHubTransport,
    method: str,
    url: str,
    token: str,
    payload: Mapping[str, object],
    expect: int,
    what: str,
) -> None:
    response = transport(method, url, auth_headers(token), json.dumps(payload).encode("utf-8"))
    if response.status != expect:
        raise BellwetherError(
            f"{what} failed with HTTP {response.status}: "
            f"{response.body[:300].decode('utf-8', 'replace')}"
        )


def upsert_drift_issues(
    transport: GitHubTransport,
    repository: str,
    readings: Sequence[DriftReading],
    *,
    token: str,
    run_url: str | None = None,
    api_root: str = GITHUB_API_ROOT,
) -> dict[str, IssueAction]:
    """Open, update or close each skill's drift issue; what was done, by skill.

    ``drift`` opens an issue, or — where one is open — edits it and comments only if the
    findings changed. ``stable`` closes an open one with a comment. Every other status leaves
    the issue as it is: a skill that could not be compared tonight has not stopped drifting.
    """
    if not _REPOSITORY.fullmatch(repository):
        raise BellwetherError(f"not an owner/repo: {repository!r}")
    root = f"{api_root.rstrip('/')}/repos/{repository}"
    existing = _open_drift_issues(transport, root, token)
    actions: dict[str, IssueAction] = {}
    for reading in sorted(readings, key=lambda r: r.skill):
        issue = existing.get(drift_key(reading.skill))
        number = issue.get("number") if issue is not None else None
        if issue is not None and not isinstance(number, int):
            raise BellwetherError(f"the open drift issue for {reading.skill!r} has no number")
        if reading.status == "drift":
            title, body = render_drift_issue(reading, run_url=run_url)
            if issue is None:
                _call(
                    transport,
                    "POST",
                    f"{root}/issues",
                    token,
                    {"title": title, "body": body},
                    201,
                    "opening a drift issue",
                )
                actions[reading.skill] = "opened"
                continue
            previous = issue.get("body")
            if isinstance(previous, str) and _digest_marker(reading) in previous:
                actions[reading.skill] = "unchanged"
                continue
            _call(
                transport,
                "PATCH",
                f"{root}/issues/{number}",
                token,
                {"title": title, "body": body},
                200,
                f"updating drift issue #{number}",
            )
            note = "The drift changed" + (f" on {run_url}" if run_url else "") + "; the "
            note += "description above is updated."
            _call(
                transport,
                "POST",
                f"{root}/issues/{number}/comments",
                token,
                {"body": note},
                201,
                f"commenting on drift issue #{number}",
            )
            actions[reading.skill] = "updated"
        elif reading.status == "stable" and issue is not None:
            note = (
                f"No longer drifting: evaluation {code(reading.eval_id)} compared with the "
                "baseline and nothing regressed"
                + (f" ({run_url})" if run_url else "")
                + ". Closing."
            )
            _call(
                transport,
                "POST",
                f"{root}/issues/{number}/comments",
                token,
                {"body": note},
                201,
                f"commenting on drift issue #{number}",
            )
            _call(
                transport,
                "PATCH",
                f"{root}/issues/{number}",
                token,
                {"state": "closed", "state_reason": "completed"},
                200,
                f"closing drift issue #{number}",
            )
            actions[reading.skill] = "closed"
        else:
            actions[reading.skill] = "none"
    return actions
