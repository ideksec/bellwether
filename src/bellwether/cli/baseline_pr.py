"""The post-merge baseline-update pull request (§17.5, §18.1 ``baseline-pr``, §18.4 step 5).

When a pull request that changed a skill merges, the skill's regression baseline should become
what that pull request's evaluation observed — but a workflow token must never get push rights
to ``main`` (§17.5). So the post-merge job *proposes*: it writes the new baseline records onto a
bot branch and opens a ``chore: update baseline`` pull request that a maintainer approves.

Three steps, each its own command so each is testable on its own:

1. **fetch** (:func:`find_merged_pr`, :func:`find_evaluation_artifact`,
   :func:`download_artifact`, :func:`read_evaluations`) — find the pull request the pushed
   commit merged, the evaluation run on that pull request's *final head*, and the evidence
   artifact it uploaded, and take from it the ``summary.json`` of every evaluation the run
   listed in ``evaluations.txt``. Nothing is re-run: re-evaluating on ``main`` would spend the
   same tokens again for the observations the review already read.
2. **update** (:func:`plan_baselines`) — for each evaluation, decide: write a new baseline,
   leave an identical one, or skip it and say why.
3. **open** (:func:`upsert_pull_request`) — open the pull request, or update the one already
   open for that branch.

**What is checked, and what is not.** The evidence artifact was produced by the pull request's
own workflow run, so its contents are only as trustworthy as that run. One property is checked
here against something the artifact cannot influence: the evaluated skill's
``payload_digest`` must equal the digest of the same skill *in the merged tree*, recomputed
here. An evaluation of an earlier push, or of a skill the merge itself changed, describes code
that is not on ``main`` and is skipped, naming both digests. What the run *observed* cannot be
recomputed without running it again; that is what the maintainer's review of the baseline pull
request is for, and its body says so.

A ``not_ready`` evaluation is skipped unless asked for: a baseline is the reference later runs
are compared against, and baselining a blocked evaluation makes its regressions the reference.

**The token** travels only in the auth header, and never to the artifact's storage host: GitHub
answers an artifact download with a redirect to a pre-signed URL on another host, and a client
that follows redirects with its headers intact sends the repository token there. The download is
asked not to follow; the redirect target is fetched with no credentials.
"""

from __future__ import annotations

import io
import json
import re
import urllib.parse
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal, NamedTuple

from pydantic import ValidationError

from bellwether.cli.baselines import (
    BaselineRecord,
    baseline_from_summary,
    baseline_path,
    read_baseline_for,
    write_baseline,
)
from bellwether.cli.pr import GITHUB_API_ROOT, GitHubResponse, GitHubTransport, auth_headers
from bellwether.errors import BellwetherError
from bellwether.report import Summary
from bellwether.report.mdsafe import code, text

__all__ = [
    "EVALUATIONS_LIST",
    "MAX_ARTIFACT_BYTES",
    "BaselineDecision",
    "EvaluationArtifact",
    "MergedPr",
    "PullRequestResult",
    "artifact_of_run",
    "download_artifact",
    "find_evaluation_artifact",
    "find_merged_pr",
    "plan_baselines",
    "read_evaluations",
    "render_baseline_pr_body",
    "upsert_pull_request",
]

#: The list the live workflows append each completed evaluation directory to (one per line).
#: It is what says which ``summary.json`` in the artifact is an evaluation's: a skill's own
#: output files are uploaded too (``outputs/``), and a skill can name a file ``summary.json``.
EVALUATIONS_LIST = "evaluations.txt"

#: A cap on the artifact zip held in memory. The evidence artifact is traces and reports for
#: one pull request's evaluations — megabytes; a larger one is refused rather than read.
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
#: Caps on the members read out of it (uncompressed), checked before decompression.
_MAX_LIST_BYTES = 64 * 1024
_MAX_SUMMARY_BYTES = 16 * 1024 * 1024

_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_WORKFLOW = re.compile(r"[A-Za-z0-9_.-]+\.ya?ml")
_ARTIFACT = re.compile(r"[A-Za-z0-9_.-]+")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")


# ---------------------------------------------------------------------------
# GitHub lookups
# ---------------------------------------------------------------------------


class MergedPr(NamedTuple):
    """The pull request a pushed commit merged."""

    number: int
    head_sha: str
    title: str
    url: str


class EvaluationArtifact(NamedTuple):
    """The evaluation run on a pull request's head, and the evidence artifact it uploaded."""

    run_id: int
    run_url: str
    artifact_id: int


def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise BellwetherError(f"not {what}: {value!r}")
    return value


def _get_json(
    transport: GitHubTransport, url: str, *, token: str, what: str
) -> Mapping[str, object] | list[object]:
    response = transport("GET", url, auth_headers(token), None)
    if response.status != 200:
        raise BellwetherError(
            f"reading {what} failed with HTTP {response.status}: "
            f"{response.body[:300].decode('utf-8', 'replace')}"
        )
    try:
        decoded = json.loads(response.body)
    except ValueError:
        raise BellwetherError(f"reading {what}: the response is not JSON") from None
    if not isinstance(decoded, (dict, list)):
        raise BellwetherError(f"reading {what}: unexpected response shape")
    return decoded


def find_merged_pr(
    transport: GitHubTransport,
    repository: str,
    sha: str,
    *,
    token: str,
    api_root: str = GITHUB_API_ROOT,
) -> MergedPr | None:
    """The pull request whose merge produced ``sha``; ``None`` for a direct push.

    A commit can be *associated* with several pull requests (every open PR that contains it);
    only one *merged* to it — the one whose ``merge_commit_sha`` is ``sha``. That holds for a
    merge commit, a squash and a rebase merge alike.
    """
    _check(_REPOSITORY, repository, "an owner/repo")
    _check(_SHA, sha, "a commit SHA")
    url = f"{api_root.rstrip('/')}/repos/{repository}/commits/{sha}/pulls?per_page=100"
    pulls = _get_json(transport, url, token=token, what=f"the pull requests of {sha[:12]}")
    if not isinstance(pulls, list):
        raise BellwetherError("reading the pull requests of a commit: expected a list")
    for pull in pulls:
        if not isinstance(pull, Mapping):
            continue
        if pull.get("merge_commit_sha") != sha or not pull.get("merged_at"):
            continue
        head = pull.get("head")
        head_sha = head.get("sha") if isinstance(head, Mapping) else None
        number = pull.get("number")
        if not isinstance(number, int) or not isinstance(head_sha, str):
            raise BellwetherError(f"pull request for {sha[:12]} has no number or head SHA")
        _check(_SHA, head_sha, "a head SHA")
        return MergedPr(
            number=number,
            head_sha=head_sha,
            title=str(pull.get("title", "")),
            url=str(pull.get("html_url", "")),
        )
    return None


def find_evaluation_artifact(
    transport: GitHubTransport,
    repository: str,
    *,
    workflow: str,
    head_sha: str,
    artifact: str,
    token: str,
    api_root: str = GITHUB_API_ROOT,
    server_url: str = "https://github.com",
) -> EvaluationArtifact | None:
    """The newest ``workflow`` run on ``head_sha`` that uploaded ``artifact``; ``None`` if none.

    A pull request's head usually has several runs of the evaluation workflow — one per event
    (opened, synchronize, labeled) — and only a labelled one uploads evidence. Runs are tried
    newest first (highest id), and an expired artifact is passed over.
    """
    _check(_REPOSITORY, repository, "an owner/repo")
    _check(_WORKFLOW, workflow, "a workflow file name")
    _check(_SHA, head_sha, "a commit SHA")
    _check(_ARTIFACT, artifact, "an artifact name")
    root = f"{api_root.rstrip('/')}/repos/{repository}"
    runs_url = f"{root}/actions/workflows/{workflow}/runs?" + urllib.parse.urlencode(
        {"head_sha": head_sha, "event": "pull_request", "per_page": 100}
    )
    listing = _get_json(transport, runs_url, token=token, what=f"the runs of {workflow}")
    runs = listing.get("workflow_runs") if isinstance(listing, Mapping) else None
    if not isinstance(runs, list):
        raise BellwetherError(f"reading the runs of {workflow}: no workflow_runs list")
    ids = sorted(
        (
            run["id"]
            for run in runs
            if isinstance(run, Mapping)
            and isinstance(run.get("id"), int)
            and run.get("head_sha") == head_sha
        ),
        reverse=True,
    )
    for run_id in ids:
        found = artifact_of_run(
            transport,
            repository,
            run_id,
            artifact=artifact,
            token=token,
            api_root=api_root,
            server_url=server_url,
        )
        if found is not None:
            return found
    return None


def artifact_of_run(
    transport: GitHubTransport,
    repository: str,
    run_id: int,
    *,
    artifact: str,
    token: str,
    api_root: str = GITHUB_API_ROOT,
    server_url: str = "https://github.com",
) -> EvaluationArtifact | None:
    """Run ``run_id``'s unexpired artifact named ``artifact``; ``None`` if it has none."""
    _check(_REPOSITORY, repository, "an owner/repo")
    _check(_ARTIFACT, artifact, "an artifact name")
    url = (
        f"{api_root.rstrip('/')}/repos/{repository}/actions/runs/{int(run_id)}/artifacts?"
        + urllib.parse.urlencode({"name": artifact, "per_page": 100})
    )
    found = _get_json(transport, url, token=token, what=f"run {run_id}'s artifacts")
    entries = found.get("artifacts") if isinstance(found, Mapping) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, Mapping):
            continue
        artifact_id = entry.get("id")
        if (
            entry.get("name") == artifact
            and entry.get("expired") is False
            and isinstance(artifact_id, int)
        ):
            return EvaluationArtifact(
                run_id=int(run_id),
                run_url=f"{server_url.rstrip('/')}/{repository}/actions/runs/{int(run_id)}",
                artifact_id=artifact_id,
            )
    return None


def download_artifact(
    transport: GitHubTransport,
    repository: str,
    artifact_id: int,
    *,
    token: str,
    api_root: str = GITHUB_API_ROOT,
) -> bytes:
    """The artifact's zip bytes, fetched without sending the token to the storage host.

    ``transport`` must **not** follow redirects (``github_transport(follow_redirects=False)``):
    GitHub answers with a 302 to a pre-signed URL elsewhere, and that URL is fetched here with no
    credentials at all. A 200 straight from the API is accepted too.
    """
    _check(_REPOSITORY, repository, "an owner/repo")
    url = f"{api_root.rstrip('/')}/repos/{repository}/actions/artifacts/{int(artifact_id)}/zip"
    response = transport("GET", url, auth_headers(token), None)
    if response.status in (301, 302, 303, 307, 308):
        location = response.location
        if not location.startswith("https://") and not location.startswith(
            api_root.rstrip("/") + "/"
        ):
            raise BellwetherError(
                f"the artifact download redirected to a non-https location: {location[:120]!r}"
            )
        response = transport("GET", location, {"user-agent": "bellwether"}, None)
    if response.status != 200:
        raise BellwetherError(
            f"downloading artifact {artifact_id} failed with HTTP {response.status}"
        )
    if len(response.body) > MAX_ARTIFACT_BYTES:
        raise BellwetherError(
            f"artifact {artifact_id} is {len(response.body)} bytes, over the "
            f"{MAX_ARTIFACT_BYTES}-byte cap"
        )
    return response.body


# ---------------------------------------------------------------------------
# Reading the artifact
# ---------------------------------------------------------------------------


def _member(archive: zipfile.ZipFile, name: str, cap: int) -> bytes | None:
    try:
        info = archive.getinfo(name)
    except KeyError:
        return None
    if info.is_dir():
        return None
    if info.file_size > cap:
        raise BellwetherError(f"{name} in the artifact is {info.file_size} bytes, over {cap}")
    data = archive.read(info)
    if len(data) > cap:  # the header's size is the archive's claim; check what was read
        raise BellwetherError(f"{name} in the artifact is over {cap} bytes")
    return data


def _evaluation_member(line: str, out_prefix: str) -> str:
    """The artifact path of one listed evaluation's ``summary.json``.

    The list holds paths as the workflow wrote them (``.bellwether-out/<skill>/<eval_id>``);
    the artifact holds them relative to the uploaded directory. The line must be exactly two
    plain components under the prefix — anything else (an absolute path, a ``..``, a deeper
    path that would reach into a skill's own ``outputs/``) is refused, not normalised.
    """
    if not line.startswith(out_prefix):
        raise BellwetherError(
            f"{EVALUATIONS_LIST} lists {line!r}, which is not under {out_prefix!r}"
        )
    relative = PurePosixPath(line[len(out_prefix) :])
    parts = relative.parts
    if len(parts) != 2 or any(part in ("", ".", "..") or "\\" in part for part in parts):
        raise BellwetherError(
            f"{EVALUATIONS_LIST} lists {line!r}; an evaluation is <out>/<skill>/<eval_id>"
        )
    return f"{relative}/summary.json"


def read_evaluations(zip_bytes: bytes, *, out_prefix: str = ".bellwether-out/") -> list[Summary]:
    """The summaries of the evaluations ``evaluations.txt`` lists, in its order.

    Only listed evaluations are read: the artifact also carries files a skill wrote, and a
    ``summary.json`` among them is the skill's, not an evaluation's. A listed evaluation whose
    summary is absent or does not validate refuses the whole artifact — a baseline proposal that
    silently drops one of the skills the pull request changed is the partial result §17.5 calls
    worse than a refusal.
    """
    if not out_prefix.endswith("/"):
        out_prefix += "/"
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise BellwetherError("the evidence artifact is not a zip archive") from None
    with archive:
        # upload-artifact roots an artifact at its search path (here the output directory), so
        # members are relative to it; an archive that kept the directory is read the same way.
        # Which of the two GitHub produces for the live workflow's upload has not been observed
        # from this environment (artifact storage is off-host), so both are accepted, and no
        # other: a member is read only at a path the list names.
        root = ""
        listing = _member(archive, EVALUATIONS_LIST, _MAX_LIST_BYTES)
        if listing is None:
            listing = _member(archive, out_prefix + EVALUATIONS_LIST, _MAX_LIST_BYTES)
            root = out_prefix
        if listing is None:
            raise BellwetherError(
                f"the evidence artifact has no {EVALUATIONS_LIST}: it predates the list, or the "
                "evaluation step stopped before recording an evaluation"
            )
        try:
            lines = listing.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            raise BellwetherError(f"{EVALUATIONS_LIST} is not UTF-8") from None
        summaries: list[Summary] = []
        for line in lines:
            if not line:
                continue
            member = root + _evaluation_member(line, out_prefix)
            data = _member(archive, member, _MAX_SUMMARY_BYTES)
            if data is None:
                raise BellwetherError(f"the artifact lists {line!r} but holds no {member}")
            try:
                summaries.append(Summary.model_validate_json(data))
            except ValidationError as error:
                raise BellwetherError(f"{member} is not a valid summary.json: {error}") from None
    return summaries


# ---------------------------------------------------------------------------
# Deciding
# ---------------------------------------------------------------------------

Action = Literal["write", "unchanged", "skip"]


@dataclass(frozen=True)
class BaselineDecision:
    """What happens to one evaluation, and why."""

    skill: str
    action: Action
    reason: str
    eval_id: str
    path: Path | None = None
    previous: BaselineRecord | None = None
    record: BaselineRecord | None = None
    changed_key: tuple[str, ...] = field(default=())


def plan_baselines(
    summaries: Sequence[Summary],
    merged_payloads: Mapping[str, Sequence[str]],
    baselines_dir: Path,
    *,
    allow_not_ready: bool = False,
    write: bool = True,
) -> list[BaselineDecision]:
    """Decide, and (``write``) write, the baseline for each evaluation.

    ``merged_payloads`` maps each skill name in the merged tree to the ``payload_digest`` of
    every skill directory carrying that name (normally one). An evaluation is baselined only
    where exactly one merged skill carries its name and that skill's payload is the one it
    evaluated. Decisions are sorted by skill name (§24).
    """
    counts: dict[str, int] = {}
    for summary in summaries:
        counts[summary.skill.name] = counts.get(summary.skill.name, 0) + 1
    decisions: list[BaselineDecision] = []
    for summary in sorted(summaries, key=lambda s: (s.skill.name, s.eval_id)):
        skill = summary.skill.name
        eval_id = summary.eval_id

        def skip(reason: str, *, skill: str = skill, eval_id: str = eval_id) -> BaselineDecision:
            return BaselineDecision(skill=skill, action="skip", reason=reason, eval_id=eval_id)

        try:
            path = baseline_path(baselines_dir, skill)
        except BellwetherError as error:
            decisions.append(skip(str(error)))
            continue
        if counts[skill] > 1:
            decisions.append(
                skip(f"{counts[skill]} evaluations of this skill in one run; which is the baseline")
            )
            continue
        digests = list(merged_payloads.get(skill, ()))
        if not digests:
            decisions.append(skip("no skill of this name is in the merged tree"))
            continue
        if len(digests) > 1:
            decisions.append(
                skip(f"{len(digests)} skills in the merged tree carry this name; it is ambiguous")
            )
            continue
        if digests[0] != summary.skill.payload_digest:
            decisions.append(
                skip(
                    f"the evaluation is of payload {summary.skill.payload_digest}, the merged "
                    f"skill is {digests[0]}: it describes code that is not on the merged commit "
                    "(a push after the evaluation, or a merge that changed the skill); evaluate "
                    "the merged commit and set the baseline from that"
                )
            )
            continue
        if summary.verdict.status == "not_ready" and not allow_not_ready:
            decisions.append(
                skip(
                    "the evaluation is not_ready: baselining it would make its regressions the "
                    "reference later runs are compared against"
                )
            )
            continue
        record = baseline_from_summary(summary)
        try:
            previous = read_baseline_for(baselines_dir, skill)
        except BellwetherError as error:
            previous = None
            prior_note = f" (the existing file did not load and is replaced: {error})"
        else:
            prior_note = ""
        if previous is not None and previous.digest == record.digest:
            decisions.append(
                BaselineDecision(
                    skill=skill,
                    action="unchanged",
                    reason="the stored baseline is this evaluation already",
                    eval_id=eval_id,
                    path=path,
                    previous=previous,
                    record=record,
                )
            )
            continue
        changed: tuple[str, ...] = ()
        if previous is not None:
            old, new = previous.key.model_dump(), record.key.model_dump()
            changed = tuple(name for name in sorted(new) if old.get(name) != new[name])
        if write:
            write_baseline(record, baselines_dir)
        decisions.append(
            BaselineDecision(
                skill=skill,
                action="write",
                reason=("first baseline for this skill" if previous is None else "replaced")
                + prior_note,
                eval_id=eval_id,
                path=path,
                previous=previous,
                record=record,
                changed_key=changed,
            )
        )
    return decisions


# ---------------------------------------------------------------------------
# The pull request
# ---------------------------------------------------------------------------


def _headline(record: BaselineRecord) -> str:
    summary = record.summary
    listed = summary.capability_profile.tier1.get("core")
    core = ", ".join(str(item) for item in listed) if isinstance(listed, (list, tuple)) else ""
    core = core or "none"
    return (
        f"{code(summary.verdict.status)} · lower bound {summary.functional.lower_bound:.3f} · "
        f"BCI {summary.consistency.bci:.3f} · tier-1 core {code(core)}"
    )


def render_baseline_pr_body(
    decisions: Sequence[BaselineDecision],
    *,
    merged: MergedPr | None,
    merge_sha: str,
    run_url: str | None,
) -> str:
    """The baseline pull request's body: what changes, from which evaluation, what was skipped."""
    lines = ["## Bellwether baseline update", ""]
    source = f"pull request #{merged.number}" if merged is not None else "a manual run"
    lines.append(
        f"Proposes the regression baselines (§17.5) observed by the evaluation of {source}, "
        f"merged as `{merge_sha[:12]}`."
    )
    if merged is not None and merged.title:
        lines.append(f"Merged pull request: {text(merged.title)}")
    if run_url:
        lines.append(f"Evaluation run: {run_url}")
    lines.append("")
    written = [d for d in decisions if d.action == "write"]
    if written:
        lines += ["| Skill | Evaluation | New baseline | Replaces |", "|---|---|---|---|"]
        for decision in written:
            assert decision.record is not None
            replaces = (
                _headline(decision.previous)
                + (
                    f" — key changed: {', '.join(decision.changed_key)}"
                    if decision.changed_key
                    else ""
                )
                if decision.previous is not None
                else "no baseline"
            )
            lines.append(
                f"| {code(decision.skill)} | {code(decision.eval_id)} | "
                f"{_headline(decision.record)} | {replaces} |"
            )
        lines.append("")
    others = [d for d in decisions if d.action != "write"]
    if others:
        lines += ["**Not baselined:**", ""]
        for decision in others:
            lines.append(
                f"- {code(decision.skill)} ({code(decision.eval_id)}): {text(decision.reason)}"
            )
        lines.append("")
    lines += [
        "### Before approving",
        "",
        "The skill's payload digest in each record was recomputed from the merged tree and "
        "matches the evaluated one. What the evaluation *observed* was not re-run: it is read "
        "from that run's evidence artifact, so read the run's report before approving — every "
        "later evaluation of the skill is compared against this record, and a capability "
        "recorded here stops reading as an expansion.",
        "",
        "Two pull requests re-baselining the same skill conflict; regenerate the baseline on "
        "`main` rather than merging the two by hand.",
    ]
    return "\n".join(lines) + "\n"


class PullRequestResult(NamedTuple):
    number: int
    url: str
    action: Literal["created", "updated"]


def _pull_from(response: GitHubResponse, what: str) -> Mapping[str, object]:
    try:
        pull = json.loads(response.body)
    except ValueError:
        raise BellwetherError(f"{what}: the response is not JSON") from None
    if not isinstance(pull, Mapping) or not isinstance(pull.get("number"), int):
        raise BellwetherError(f"{what}: the response carries no pull request number")
    return pull


def upsert_pull_request(
    transport: GitHubTransport,
    repository: str,
    *,
    branch: str,
    base: str,
    title: str,
    body: str,
    token: str,
    api_root: str = GITHUB_API_ROOT,
) -> PullRequestResult:
    """Open a pull request from ``branch`` into ``base``, or update the open one's title/body."""
    _check(_REPOSITORY, repository, "an owner/repo")
    _check(_BRANCH, branch, "a branch name")
    _check(_BRANCH, base, "a branch name")
    owner = repository.split("/", 1)[0]
    root = f"{api_root.rstrip('/')}/repos/{repository}/pulls"
    query = urllib.parse.urlencode({"head": f"{owner}:{branch}", "base": base, "state": "open"})
    existing = _get_json(transport, f"{root}?{query}", token=token, what="the open pull requests")
    payload = {"title": title, "body": body}
    if isinstance(existing, list) and existing:
        pull = existing[0]
        number = pull.get("number") if isinstance(pull, Mapping) else None
        if not isinstance(number, int):
            raise BellwetherError("the open pull request carries no number")
        response = transport(
            "PATCH", f"{root}/{number}", auth_headers(token), json.dumps(payload).encode()
        )
        if response.status != 200:
            raise BellwetherError(
                f"updating pull request #{number} failed with HTTP {response.status}: "
                f"{response.body[:300].decode('utf-8', 'replace')}"
            )
        updated = _pull_from(response, f"updating pull request #{number}")
        return PullRequestResult(number, str(updated.get("html_url", "")), "updated")
    create = {**payload, "head": branch, "base": base}
    response = transport("POST", root, auth_headers(token), json.dumps(create).encode())
    if response.status != 201:
        detail = response.body[:300].decode("utf-8", "replace")
        hint = (
            " — the repository does not let GitHub Actions open pull requests; enable "
            "Settings → Actions → General → 'Allow GitHub Actions to create and approve pull "
            f"requests', or open one from the pushed branch {branch!r} by hand"
            if response.status == 403
            else ""
        )
        raise BellwetherError(
            f"opening the pull request failed with HTTP {response.status}: {detail}{hint}"
        )
    created = _pull_from(response, "opening the pull request")
    number = created["number"]
    assert isinstance(number, int)
    return PullRequestResult(number, str(created.get("html_url", "")), "created")
