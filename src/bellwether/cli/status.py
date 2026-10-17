"""Commit statuses per gate group (§18.2) — how branch protection reads a verdict.

§18.2: "Set a commit status per gate group … so branch protection can require them
individually. This is the mechanism by which a repository decides whether ``conditional``
blocks — not the exit code." The exit code is one bit for the whole verdict; a repository may
want security findings to block a merge while letting a consistency warning through, and the
only knob GitHub gives it is *which status contexts are required*. So each group of gates gets
a context of its own, and two more carry the verdict itself:

* ``<prefix>/<group>`` — one per gate group. ``failure`` when any gate in the group blocks —
  including a *required* gate that could not be evaluated, which blocks the verdict (§16.2) —
  ``success`` otherwise, with ``warn`` in the description where a gate warned.
* ``<prefix>/verdict`` — ``failure`` on ``not_ready``. Requiring it is the exit-code rule.
* ``<prefix>/ready`` — ``failure`` unless every evaluation is ``ready``. Requiring it makes
  ``conditional`` block.

Groups are the spec's five — ``static``, ``functional``, ``consistency``, ``security``,
``evidence`` — and three for gates the build has since grown: ``budget``, ``regression``,
``review``. Declared scope (``scope``, ``scope.manifest``) is in ``security``: exceeding it is a
capability the skill did not declare (§12.5). **Every gate maps to exactly one group, and an
unmapped gate refuses**: a gate that reported into no context would be a check branch protection
could never require — the silent-no-op shape the control registry exists to prevent. A test
extracts every gate name the composition can produce and checks it maps.

Statuses go on the pull request's **head** commit. On a ``pull_request`` event ``GITHUB_SHA`` is
the synthetic merge commit, and a status posted there never appears on the PR; so the SHA is
always passed explicitly and checked for shape.

Like the PR comment, the HTTP call is the injected :data:`~bellwether.cli.pr.GitHubTransport`
and the token travels only in the auth header.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from bellwether.cli.pr import GITHUB_API_ROOT, GitHubTransport, auth_headers
from bellwether.errors import BellwetherError
from bellwether.report.mdsafe import one_line
from bellwether.report.summary import GateSummary, Summary

__all__ = [
    "GROUPS",
    "GroupStatus",
    "StatusState",
    "check_prefix",
    "check_sha",
    "evaluation_statuses",
    "gate_group",
    "post_statuses",
    "run_url",
    "uniform_statuses",
]

StatusState = Literal["success", "failure", "pending", "error"]

#: The gate groups, in the order their statuses are posted. ``verdict`` and ``ready`` follow.
GROUPS: tuple[str, ...] = (
    "static",
    "functional",
    "consistency",
    "security",
    "evidence",
    "budget",
    "regression",
    "review",
)

#: Exact gate names → group. Prefixes are not used: a new ``security_runtime.*`` gate must be
#: placed here deliberately, and the completeness test fails the build until it is.
_GROUP_OF: Mapping[str, str] = {
    "static": "static",
    "functional": "functional",
    "functional.false_trigger": "functional",
    "consistency": "consistency",
    "scope": "security",
    "scope.manifest": "security",
    "security_runtime.canaries": "security",
    "security_runtime.canary_reads": "security",
    "security_runtime.credential_reads": "security",
    "security_runtime.dns": "security",
    "security_runtime.egress": "security",
    "security_runtime.processes": "security",
    "security_runtime.provider_endpoint": "security",
    "security_runtime.sensitive_directories": "security",
    "security_runtime.volume_anomaly": "security",
    "evidence": "evidence",
    "budget.cost": "budget",
    "budget.wall_clock": "budget",
    "regression": "regression",
    "human_review": "review",
}

#: GitHub caps a status description at 140 characters.
_DESCRIPTION_CHARS = 140
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def gate_group(name: str) -> str:
    """The group a gate reports into; :class:`BellwetherError` for a gate in no group."""
    try:
        return _GROUP_OF[name]
    except KeyError:
        raise BellwetherError(
            f"gate {name!r} belongs to no commit-status group (cli/status.py); a gate that "
            "reports into no context is one branch protection can never require — add it to "
            "the group table"
        ) from None


@dataclass(frozen=True)
class GroupStatus:
    """One commit status: its context, state and the line GitHub shows beside it."""

    context: str
    state: StatusState
    description: str


def _describe(text: str) -> str:
    """One line, no controls, at most GitHub's 140 characters."""
    line = " ".join(one_line(text).split())
    return line if len(line) <= _DESCRIPTION_CHARS else line[: _DESCRIPTION_CHARS - 1] + "…"


def _list(items: Sequence[str]) -> str:
    shown = ", ".join(items[:3])
    return shown + (f" and {len(items) - 3} more" if len(items) > 3 else "")


def _blocks(gate: GateSummary) -> bool:
    return gate.status == "block" or (gate.status == "not_evaluable" and gate.required)


def _warns(gate: GateSummary) -> bool:
    return gate.status == "warn" or (gate.status == "not_evaluable" and not gate.required)


def evaluation_statuses(summaries: Sequence[Summary], *, prefix: str) -> list[GroupStatus]:
    """The statuses for one or more evaluations of the same commit (several skills, say).

    Every group is reported, worst across the evaluations: one skill blocking its security
    gate fails ``security`` for the commit. A group none of the evaluations composed is
    ``success`` and says so — no gate there was asked for — rather than being left unposted,
    which a required context would read as "pending" forever.
    """
    if not summaries:
        raise BellwetherError("no evaluation to report a commit status for")
    grouped: dict[str, list[tuple[str, GateSummary]]] = {group: [] for group in GROUPS}
    for summary in summaries:
        for gate in summary.verdict.gates:
            grouped[gate_group(gate.name)].append((summary.skill.name, gate))
    many = len(summaries) > 1

    def label(skill: str, gate: GateSummary) -> str:
        return f"{gate.name} ({skill})" if many else gate.name

    statuses: list[GroupStatus] = []
    for group in GROUPS:
        gates = grouped[group]
        blocking = [label(skill, gate) for skill, gate in gates if _blocks(gate)]
        warning = [label(skill, gate) for skill, gate in gates if _warns(gate)]
        if not gates:
            state: StatusState = "success"
            text = "no gate in this group was composed for this evaluation"
        elif blocking:
            state, text = "failure", f"blocked: {_list(blocking)}"
        elif warning:
            state, text = "success", f"warn: {_list(warning)}"
        else:
            state, text = "success", f"pass: {len(gates)} gate(s)"
        statuses.append(GroupStatus(f"{prefix}/{group}", state, _describe(text)))

    verdicts = [(summary.skill.name, summary.verdict.status) for summary in summaries]
    not_ready = [skill for skill, status in verdicts if status == "not_ready"]
    conditional = [skill for skill, status in verdicts if status == "conditional"]
    if not_ready:
        verdict = GroupStatus(
            f"{prefix}/verdict", "failure", _describe(f"not_ready: {_list(not_ready)}")
        )
    elif conditional:
        verdict = GroupStatus(
            f"{prefix}/verdict", "success", _describe(f"conditional: {_list(conditional)}")
        )
    else:
        verdict = GroupStatus(f"{prefix}/verdict", "success", "ready")
    short = not_ready + conditional
    ready = (
        GroupStatus(f"{prefix}/ready", "failure", _describe(f"not ready: {_list(short)}"))
        if short
        else GroupStatus(f"{prefix}/ready", "success", "ready")
    )
    return [*statuses, verdict, ready]


def uniform_statuses(state: StatusState, reason: str, *, prefix: str) -> list[GroupStatus]:
    """The same state on every context — for a commit with nothing to evaluate (``success``)
    or one waiting on a maintainer's label (``pending``)."""
    contexts = [*(f"{prefix}/{group}" for group in GROUPS), f"{prefix}/verdict", f"{prefix}/ready"]
    return [GroupStatus(context, state, _describe(reason)) for context in contexts]


def check_sha(sha: str) -> str:
    """``sha`` if it is a full commit SHA; :class:`BellwetherError` naming the usual mistake."""
    if not _SHA.fullmatch(sha):
        raise BellwetherError(
            f"not a commit SHA: {sha!r}; pass the pull request's head SHA "
            "(github.event.pull_request.head.sha), not GITHUB_SHA, which is the merge commit"
        )
    return sha


def check_prefix(prefix: str) -> str:
    """``prefix`` if it is a valid context prefix; :class:`BellwetherError` otherwise."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", prefix):
        raise BellwetherError(f"not a status context prefix: {prefix!r}")
    return prefix


def post_statuses(
    transport: GitHubTransport,
    repository: str,
    sha: str,
    statuses: Sequence[GroupStatus],
    *,
    token: str,
    target_url: str | None = None,
    api_root: str = GITHUB_API_ROOT,
) -> int:
    """POST each status to ``repos/{owner}/{repo}/statuses/{sha}``; the number posted.

    Raises :class:`BellwetherError` on the first non-201, naming the context, so a CI step
    fails loudly rather than leaving branch protection reading a partial set. The token goes
    in the auth header only (the same header builder as the PR comment).
    """
    check_sha(sha)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise BellwetherError(f"not an owner/repo: {repository!r}")
    if target_url is not None and not target_url.startswith("https://"):
        raise BellwetherError(f"a status target_url must be https: {target_url!r}")
    headers = auth_headers(token)
    url = f"{api_root.rstrip('/')}/repos/{repository}/statuses/{sha}"
    for status in statuses:
        payload: dict[str, str] = {
            "state": status.state,
            "context": status.context,
            "description": status.description,
        }
        if target_url is not None:
            payload["target_url"] = target_url
        response = transport("POST", url, headers, json.dumps(payload).encode("utf-8"))
        if response.status != 201:
            raise BellwetherError(
                f"posting status {status.context!r} failed with HTTP {response.status}: "
                f"{response.body[:300].decode('utf-8', 'replace')}"
            )
    return len(statuses)


def run_url(environ: Mapping[str, str]) -> str | None:
    """The workflow run's URL from the Actions environment, or ``None`` outside it."""
    server = environ.get("GITHUB_SERVER_URL", "")
    repository = environ.get("GITHUB_REPOSITORY", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    if server.startswith("https://") and "/" in repository and run_id.isdigit():
        return f"{server.rstrip('/')}/{repository}/actions/runs/{run_id}"
    return None
