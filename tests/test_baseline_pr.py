"""The post-merge baseline-update pull request (§17.5, §18.1 ``baseline-pr``, §18.4 step 5).

Three layers, each tested where it is wired:

* the pieces — reading an evidence artifact by its ``evaluations.txt`` and nothing else, the
  merged-tree payload check that decides what is baselined, the GitHub lookups, the pull request
  upsert, the body's escaping;
* the transport — the real ``github_transport`` against a local fake whose artifact download
  redirects to a storage path that counts every request arriving with a token, as GitHub's
  off-host storage would receive it;
* the workflow — ``bellwether-baseline.yml``'s own steps, executed (``tests/workflow_harness.py``)
  in a scratch repository with a bare ``origin``, so the branch push and the pull request are the
  real ones the job would make.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from bellwether.cli.baseline_pr import (
    artifact_of_run,
    download_artifact,
    find_evaluation_artifact,
    find_merged_pr,
    plan_baselines,
    read_evaluations,
    render_baseline_pr_body,
    upsert_pull_request,
)
from bellwether.cli.baselines import baseline_from_summary, read_baseline_for, write_baseline
from bellwether.cli.pr import GitHubResponse, github_transport
from bellwether.errors import BellwetherError
from bellwether.report import Summary
from bellwether.skill import load_skill
from tests.workflow_harness import (
    FAKE_TOKEN,
    Event,
    FakeGitHub,
    WorkflowRunner,
    bellwether_wrapper,
)

_ROOT = Path(__file__).resolve().parents[1]
_DEMO = _ROOT / "examples" / "reports" / "demo-benign-note-taker" / "summary.json"
_WORKFLOW = _ROOT / ".github" / "workflows" / "bellwether-baseline.yml"
_REPO = "owner/repo"
_HEAD = "c" * 40
_MERGE = "d" * 40


@pytest.fixture
def api() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    yield fake
    fake.close()


def _skill(root: Path, name: str, body: str = "x") -> Path:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Counts lines in Markdown files.\n---\n{body}\n",
        encoding="utf-8",
    )
    return directory


def _summary(
    name: str,
    payload_digest: str,
    *,
    verdict: str = "ready",
    eval_id: str | None = None,
) -> Summary:
    """The committed demo summary, relabelled as an evaluation of ``name`` at ``payload``."""
    data = json.loads(_DEMO.read_text(encoding="utf-8"))
    data["skill"]["name"] = name
    data["skill"]["payload_digest"] = payload_digest
    data["verdict"]["status"] = verdict
    data["eval_id"] = eval_id or f"eval-{name}"
    return Summary.model_validate(data)


def _payload(directory: Path) -> str:
    return load_skill(directory, load_evals=False).payload_digest


def _artifact(
    summaries: Sequence[Summary],
    *,
    extra: Mapping[str, bytes] | None = None,
    listing: str | None = None,
    root: str = "",
) -> bytes:
    """An evidence artifact as the live workflow uploads it: each evaluation at
    ``<skill-slug>/<eval_id>/``, and ``evaluations.txt`` naming them as the loop wrote them."""
    buffer = io.BytesIO()
    lines = []
    with zipfile.ZipFile(buffer, "w") as archive:
        for summary in summaries:
            relative = f"examples-skills-{summary.skill.name}/{summary.eval_id}"
            archive.writestr(f"{root}{relative}/summary.json", summary.model_dump_json())
            lines.append(f".bellwether-out/{relative}")
        for name, data in (extra or {}).items():
            archive.writestr(f"{root}{name}", data)
        archive.writestr(
            f"{root}evaluations.txt", listing if listing is not None else "\n".join(lines) + "\n"
        )
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Reading the artifact
# ---------------------------------------------------------------------------


def test_the_listed_evaluations_are_read_in_order() -> None:
    first, second = _summary("b-skill", "sha256:1"), _summary("a-skill", "sha256:2")
    read = read_evaluations(_artifact([first, second]))
    assert [s.skill.name for s in read] == ["b-skill", "a-skill"]
    assert read[0] == first


def test_an_artifact_that_kept_its_output_directory_reads_the_same() -> None:
    summary = _summary("a-skill", "sha256:1")
    assert read_evaluations(_artifact([summary], root=".bellwether-out/")) == [summary]


def test_a_summary_a_skill_wrote_is_never_read_as_an_evaluation() -> None:
    """A skill's own output files are uploaded with the evidence (``outputs/``); a skill can
    write one called ``summary.json`` claiming any verdict. Only listed paths are read."""
    real = _summary("a-skill", "sha256:1", verdict="not_ready")
    forged = _summary("a-skill", "sha256:1", verdict="ready", eval_id="forged")
    read = read_evaluations(
        _artifact(
            [real],
            extra={
                "examples-skills-a-skill/eval-a-skill/outputs/summary.json": (
                    forged.model_dump_json().encode()
                ),
                "summary.json": forged.model_dump_json().encode(),
            },
        )
    )
    assert [(s.eval_id, s.verdict.status) for s in read] == [("eval-a-skill", "not_ready")]


@pytest.mark.parametrize(
    "line",
    [
        "/etc/passwd",
        ".bellwether-out/../x/summary",
        ".bellwether-out/a/../b",
        ".bellwether-out/a/b/outputs",  # deeper: into a skill's own outputs
        ".bellwether-out/a",  # shallower
        "elsewhere/a/b",
        ".bellwether-out/a\\b/c",
    ],
)
def test_a_list_line_that_is_not_out_skill_eval_is_refused(line: str) -> None:
    """Refused by its shape, not by happening to name no member: a valid summary is placed at
    exactly the member the line would otherwise resolve to."""
    member = line.removeprefix(".bellwether-out/") + "/summary.json"
    planted = {member: _summary("a-skill", "sha256:1").model_dump_json().encode()}
    with pytest.raises(BellwetherError, match=r"not under|an evaluation is"):
        read_evaluations(_artifact([], listing=f"{line}\n", extra=planted))


def test_an_artifact_without_the_list_is_refused_not_read_as_empty() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a/b/summary.json", _summary("a", "sha256:1").model_dump_json())
    with pytest.raises(BellwetherError, match=r"no evaluations\.txt"):
        read_evaluations(buffer.getvalue())


def test_a_listed_evaluation_whose_summary_is_missing_refuses_the_whole_artifact() -> None:
    summary = _summary("a-skill", "sha256:1")
    listing = ".bellwether-out/examples-skills-a-skill/eval-a-skill\n.bellwether-out/x/gone\n"
    with pytest.raises(BellwetherError, match="holds no"):
        read_evaluations(_artifact([summary], listing=listing))


def test_an_invalid_summary_is_refused() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("s/e/summary.json", b'{"not": "a summary"}')
        archive.writestr("evaluations.txt", ".bellwether-out/s/e\n")
    with pytest.raises(BellwetherError, match="not a valid summary"):
        read_evaluations(buffer.getvalue())


def test_an_oversized_member_is_refused_before_it_is_decompressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The size is checked from the member's header, so a small zip that inflates to gigabytes
    is refused without inflating it."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("evaluations.txt", b"\n" * (64 * 1024 + 1))
    assert len(buffer.getvalue()) < 4096

    def never(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("the oversized member was decompressed")

    monkeypatch.setattr(zipfile.ZipFile, "read", never)
    with pytest.raises(BellwetherError, match="over"):
        read_evaluations(buffer.getvalue())


def test_not_a_zip_is_refused() -> None:
    with pytest.raises(BellwetherError, match="not a zip"):
        read_evaluations(b"<html>sign in</html>")


# ---------------------------------------------------------------------------
# Deciding what is baselined
# ---------------------------------------------------------------------------


def test_an_evaluation_of_the_merged_payload_is_baselined(tmp_path: Path) -> None:
    skill = _skill(tmp_path / "skills", "a-skill")
    baselines = tmp_path / "baselines"
    summary = _summary("a-skill", _payload(skill))
    [decision] = plan_baselines([summary], {"a-skill": [_payload(skill)]}, baselines)
    assert decision.action == "write"
    assert decision.reason == "first baseline for this skill"
    stored = read_baseline_for(baselines, "a-skill")
    assert stored is not None and stored == baseline_from_summary(summary)
    assert (baselines / ".gitattributes").is_file()


def test_an_evaluation_of_an_earlier_push_is_not_baselined(tmp_path: Path) -> None:
    """The pull request's last evaluation ran before a later push changed the skill (or the
    merge itself changed it): the evaluation describes code that is not on main."""
    evaluated = _skill(tmp_path / "then", "a-skill", body="v1")
    merged = _skill(tmp_path / "now", "a-skill", body="v2")
    assert _payload(evaluated) != _payload(merged)
    baselines = tmp_path / "baselines"
    [decision] = plan_baselines(
        [_summary("a-skill", _payload(evaluated))], {"a-skill": [_payload(merged)]}, baselines
    )
    assert decision.action == "skip"
    assert _payload(evaluated) in decision.reason and _payload(merged) in decision.reason
    assert not baselines.exists()


def test_a_not_ready_evaluation_is_skipped_unless_asked_for(tmp_path: Path) -> None:
    payloads = {"a-skill": ["sha256:1"]}
    summary = _summary("a-skill", "sha256:1", verdict="not_ready")
    [skipped] = plan_baselines([summary], payloads, tmp_path / "b1")
    assert skipped.action == "skip" and "not_ready" in skipped.reason
    [written] = plan_baselines([summary], payloads, tmp_path / "b2", allow_not_ready=True)
    assert written.action == "write"


def test_a_conditional_evaluation_is_baselined(tmp_path: Path) -> None:
    summary = _summary("a-skill", "sha256:1", verdict="conditional")
    [decision] = plan_baselines([summary], {"a-skill": ["sha256:1"]}, tmp_path)
    assert decision.action == "write"


def test_the_same_record_again_is_unchanged_and_not_rewritten(tmp_path: Path) -> None:
    summary = _summary("a-skill", "sha256:1")
    path = write_baseline(baseline_from_summary(summary), tmp_path)
    before = path.stat().st_mtime_ns
    [decision] = plan_baselines([summary], {"a-skill": ["sha256:1"]}, tmp_path)
    assert decision.action == "unchanged"
    assert path.stat().st_mtime_ns == before


def test_a_replacement_names_the_key_components_that_changed(tmp_path: Path) -> None:
    write_baseline(baseline_from_summary(_summary("a-skill", "sha256:old")), tmp_path)
    [decision] = plan_baselines(
        [_summary("a-skill", "sha256:new", eval_id="later")], {"a-skill": ["sha256:new"]}, tmp_path
    )
    assert decision.action == "write" and decision.reason == "replaced"
    assert decision.changed_key == ("payload_digest",)
    assert decision.previous is not None and decision.previous.eval_id == "eval-a-skill"


def test_a_skill_absent_from_the_merged_tree_is_not_baselined(tmp_path: Path) -> None:
    [decision] = plan_baselines([_summary("gone", "sha256:1")], {}, tmp_path)
    assert decision.action == "skip" and "is in the merged tree" in decision.reason


def test_two_merged_skills_with_one_name_are_ambiguous(tmp_path: Path) -> None:
    [decision] = plan_baselines(
        [_summary("a-skill", "sha256:1")], {"a-skill": ["sha256:1", "sha256:2"]}, tmp_path
    )
    assert decision.action == "skip" and "ambiguous" in decision.reason


def test_two_evaluations_of_one_skill_in_one_run_are_both_skipped(tmp_path: Path) -> None:
    summaries = [_summary("a-skill", "sha256:1", eval_id=e) for e in ("e1", "e2")]
    decisions = plan_baselines(summaries, {"a-skill": ["sha256:1"]}, tmp_path)
    assert [d.action for d in decisions] == ["skip", "skip"]
    assert not list(tmp_path.iterdir())


def test_a_skill_name_that_cannot_name_a_file_is_skipped(tmp_path: Path) -> None:
    [decision] = plan_baselines([_summary("..", "sha256:1")], {"..": ["sha256:1"]}, tmp_path)
    assert decision.action == "skip"
    assert list(tmp_path.iterdir()) == []


def test_a_dry_run_decides_but_writes_nothing(tmp_path: Path) -> None:
    [decision] = plan_baselines(
        [_summary("a-skill", "sha256:1")], {"a-skill": ["sha256:1"]}, tmp_path, write=False
    )
    assert decision.action == "write"
    assert list(tmp_path.iterdir()) == []


def test_decisions_are_sorted_by_skill(tmp_path: Path) -> None:
    summaries = [_summary(name, "sha256:1") for name in ("c", "a", "b")]
    payloads = {name: ["sha256:1"] for name in ("a", "b", "c")}
    assert [d.skill for d in plan_baselines(summaries, payloads, tmp_path)] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# The body
# ---------------------------------------------------------------------------


def test_the_body_says_what_was_checked_and_what_was_not(tmp_path: Path) -> None:
    decisions = plan_baselines(
        [_summary("a-skill", "sha256:1"), _summary("b-skill", "sha256:9", verdict="not_ready")],
        {"a-skill": ["sha256:1"], "b-skill": ["sha256:9"]},
        tmp_path,
    )
    from bellwether.cli.baseline_pr import MergedPr

    body = render_baseline_pr_body(
        decisions,
        merged=MergedPr(12, _HEAD, "Add a-skill", "https://github.com/owner/repo/pull/12"),
        merge_sha=_MERGE,
        run_url="https://github.com/owner/repo/actions/runs/5",
    )
    assert "pull request #12" in body and _MERGE[:12] in body
    assert "| `a-skill` | `eval-a-skill` | `ready`" in body
    assert "**Not baselined:**" in body and "`b-skill`" in body and "not\\_ready" in body
    assert "was not re-run" in body
    assert "actions/runs/5" in body


def test_values_the_pull_request_chose_are_inert_in_the_body(tmp_path: Path) -> None:
    """The merged pull request's title and the evaluated skill's name are the author's text,
    and the body is posted by the workflow's bot."""
    from bellwether.cli.baseline_pr import MergedPr

    hostile = "x\n## ✅ approved @maintainers <img src=x>"
    decisions = plan_baselines([_summary("a-skill", "sha256:1")], {}, tmp_path)
    body = render_baseline_pr_body(
        decisions, merged=MergedPr(1, _HEAD, hostile, ""), merge_sha=_MERGE, run_url=None
    )
    assert "\n## ✅" not in body
    assert "@maintainers" not in body
    assert re.search(r"(?<!\\)<img", body) is None  # escaped, so never a tag


# ---------------------------------------------------------------------------
# GitHub, through the real transport
# ---------------------------------------------------------------------------


def _pull(number: int, *, merge_sha: str, merged: bool = True, head: str = _HEAD) -> dict[str, Any]:
    return {
        "number": number,
        "title": f"PR {number}",
        "html_url": f"https://github.com/owner/repo/pull/{number}",
        "merge_commit_sha": merge_sha,
        "merged_at": "2026-10-17T00:00:00Z" if merged else None,
        "head": {"sha": head},
    }


def test_the_merged_pull_request_is_the_one_whose_merge_commit_it_is(api: FakeGitHub) -> None:
    """``/commits/{sha}/pulls`` lists every PR *containing* the commit; only one merged to it."""
    api.commit_pulls[_MERGE] = [
        _pull(3, merge_sha="e" * 40, head="f" * 40),  # an open PR that contains the commit
        _pull(4, merge_sha=_MERGE, merged=False),
        _pull(5, merge_sha=_MERGE),
    ]
    found = find_merged_pr(github_transport(), _REPO, _MERGE, token=FAKE_TOKEN, api_root=api.url)
    assert found is not None and (found.number, found.head_sha) == (5, _HEAD)


def test_a_direct_push_merged_no_pull_request(api: FakeGitHub) -> None:
    assert (
        find_merged_pr(github_transport(), _REPO, _MERGE, token=FAKE_TOKEN, api_root=api.url)
        is None
    )


def test_the_newest_run_with_unexpired_evidence_is_chosen(api: FakeGitHub) -> None:
    api.runs = [
        {"id": 10, "workflow": "bellwether.yml", "head_sha": _HEAD},
        {"id": 30, "workflow": "bellwether.yml", "head_sha": _HEAD},  # unlabelled: no artifact
        {"id": 20, "workflow": "bellwether.yml", "head_sha": _HEAD},
        {"id": 40, "workflow": "other.yml", "head_sha": _HEAD},
    ]
    api.artifacts = {
        10: [{"id": 100, "name": "bellwether-evidence", "expired": False}],
        20: [
            {"id": 200, "name": "something-else", "expired": False},
            {"id": 201, "name": "bellwether-evidence", "expired": False},
        ],
        40: [{"id": 400, "name": "bellwether-evidence", "expired": False}],
    }
    found = find_evaluation_artifact(
        github_transport(),
        _REPO,
        workflow="bellwether.yml",
        head_sha=_HEAD,
        artifact="bellwether-evidence",
        token=FAKE_TOKEN,
        api_root=api.url,
    )
    assert found is not None and (found.run_id, found.artifact_id) == (20, 201)
    assert found.run_url == "https://github.com/owner/repo/actions/runs/20"

    api.artifacts[20][1]["expired"] = True
    found = find_evaluation_artifact(
        github_transport(),
        _REPO,
        workflow="bellwether.yml",
        head_sha=_HEAD,
        artifact="bellwether-evidence",
        token=FAKE_TOKEN,
        api_root=api.url,
    )
    assert found is not None and found.run_id == 10


def test_no_run_with_evidence_is_none(api: FakeGitHub) -> None:
    api.runs = [{"id": 10, "workflow": "bellwether.yml", "head_sha": _HEAD}]
    assert (
        find_evaluation_artifact(
            github_transport(),
            _REPO,
            workflow="bellwether.yml",
            head_sha=_HEAD,
            artifact="bellwether-evidence",
            token=FAKE_TOKEN,
            api_root=api.url,
        )
        is None
    )
    assert (
        artifact_of_run(
            github_transport(),
            _REPO,
            10,
            artifact="bellwether-evidence",
            token=FAKE_TOKEN,
            api_root=api.url,
        )
        is None
    )


def test_the_download_never_sends_the_token_to_the_storage_host(api: FakeGitHub) -> None:
    """GitHub answers an artifact download with a redirect to a pre-signed URL on another host
    (observed: ``productionresultssa6.blob.core.windows.net``). urllib follows a redirect with
    the request's headers, Authorization included, so the download is made not to follow."""
    data = _artifact([_summary("a-skill", "sha256:1")])
    api.blobs[7] = data
    got = download_artifact(
        github_transport(follow_redirects=False), _REPO, 7, token=FAKE_TOKEN, api_root=api.url
    )
    assert got == data
    assert api.blob_auth == 0


def test_a_following_transport_would_have_sent_it(api: FakeGitHub) -> None:
    """The reason for the above, measured: the default transport carries the token across."""
    api.blobs[7] = b"zip"
    download_artifact(github_transport(), _REPO, 7, token=FAKE_TOKEN, api_root=api.url)
    assert api.blob_auth == 1


def test_a_redirect_to_plain_http_elsewhere_is_refused() -> None:
    def transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> Any:
        return GitHubResponse(302, b"", "http://storage.example/blob")

    with pytest.raises(BellwetherError, match="non-https"):
        download_artifact(transport, _REPO, 7, token=FAKE_TOKEN)


def test_an_oversized_artifact_is_refused() -> None:
    from bellwether.cli import baseline_pr

    def transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> Any:
        return GitHubResponse(200, b"x" * 11)

    original = baseline_pr.MAX_ARTIFACT_BYTES
    baseline_pr.MAX_ARTIFACT_BYTES = 10
    try:
        with pytest.raises(BellwetherError, match="cap"):
            download_artifact(transport, _REPO, 7, token=FAKE_TOKEN)
    finally:
        baseline_pr.MAX_ARTIFACT_BYTES = original


def test_the_pull_request_is_opened_then_updated_in_place(api: FakeGitHub) -> None:
    def upsert(body: str) -> Any:
        return upsert_pull_request(
            github_transport(),
            _REPO,
            branch="bellwether/baseline-pr-5",
            base="main",
            title="chore: update baseline (#5)",
            body=body,
            token=FAKE_TOKEN,
            api_root=api.url,
        )

    first = upsert("one")
    assert first.action == "created" and first.number == 500
    second = upsert("two")
    assert second.action == "updated" and second.number == 500
    assert len(api.pulls) == 1 and api.pulls[0]["body"] == "two"
    assert api.pulls[0]["head"] == "bellwether/baseline-pr-5"
    assert api.pulls[0]["base"] == "main"


def test_a_repository_that_forbids_actions_pull_requests_is_named(api: FakeGitHub) -> None:
    api.create_pull_status = 403
    with pytest.raises(BellwetherError, match="Allow GitHub Actions to create"):
        upsert_pull_request(
            github_transport(),
            _REPO,
            branch="b",
            base="main",
            title="t",
            body="b",
            token=FAKE_TOKEN,
            api_root=api.url,
        )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"branch": "-x"}, "branch"),
        ({"base": "main\n"}, "branch"),
    ],
)
def test_upsert_refuses_bad_names(kwargs: Mapping[str, str], match: str) -> None:
    arguments: dict[str, str] = {"branch": "b", "base": "main", **kwargs}
    with pytest.raises(BellwetherError, match=match):
        upsert_pull_request(
            github_transport(),
            _REPO,
            title="t",
            body="b",
            token=FAKE_TOKEN,
            **arguments,
        )


# ---------------------------------------------------------------------------
# The workflow, executed
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _merged_repository(tmp_path: Path, skills: Mapping[str, str]) -> tuple[Path, Path, str]:
    """A repository on ``main`` holding ``skills`` (name → body) and a bare ``origin``; the
    working copy, the origin and the merge commit's SHA."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    repo = tmp_path / "repo"
    for name, body in skills.items():
        _skill(repo / "examples" / "skills", name, body)
    # A skill-shaped fixture outside the root: never a baseline candidate.
    _skill(repo / "tests" / "corpus", "a-skill", "hostile twin")
    _git(repo.parent, "init", "-q", "-b", "main", str(repo))
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "merge")
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")
    return repo, origin, _git(repo, "rev-parse", "HEAD")


def _evidence(api: FakeGitHub, merge_sha: str, summaries: Sequence[Summary]) -> None:
    api.commit_pulls[merge_sha] = [_pull(12, merge_sha=merge_sha)]
    api.runs = [{"id": 77, "workflow": "bellwether.yml", "head_sha": _HEAD}]
    api.artifacts = {77: [{"id": 700, "name": "bellwether-evidence", "expired": False}]}
    api.blobs[700] = _artifact(summaries)


def _run(
    repo: Path, tmp: Path, api: FakeGitHub, merge_sha: str, *, inputs: Mapping[str, str] = {}
) -> WorkflowRunner:
    bellwether = Path(sys.executable).parent / "bellwether"
    wrapper = bellwether_wrapper(tmp, str(bellwether), api)
    runner = WorkflowRunner(
        _WORKFLOW,
        "baseline-pr",
        repo,
        tmp,
        event=Event(
            name="workflow_dispatch" if inputs else "push", merge_sha=merge_sha, inputs=inputs
        ),
        api=api,
        substitutions=[("uv run bellwether", str(wrapper))],
        skip=(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
            "Install uv",
            "Install Bellwether",
        ),
    )
    runner.run()
    return runner


def _explain(runner: WorkflowRunner) -> list[tuple[str, int, str]]:
    return [(r.name, r.returncode, r.output[-1500:]) for r in runner.results if r.ran]


def test_a_merge_opens_a_baseline_pull_request_from_a_bot_branch(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, origin, merge = _merged_repository(tmp_path, {"a-skill": "v1", "b-skill": "v1"})
    skills = repo / "examples" / "skills"
    a = _summary("a-skill", _payload(skills / "a-skill"))
    b = _summary("b-skill", _payload(skills / "b-skill"), verdict="conditional")
    _evidence(api, merge, [a, b])

    runner = _run(repo, tmp_path, api, merge)
    assert not runner.failed, _explain(runner)
    assert "Open the baseline pull request" in runner.ran()

    # The branch on origin holds exactly the two records, and main is untouched.
    branch = "bellwether/baseline-pr-12"
    assert _git(origin, "rev-parse", "refs/heads/main") == merge
    files = _git(origin, "diff", "--name-only", f"{merge}..refs/heads/{branch}").splitlines()
    assert files == [
        "examples/live/baselines/.gitattributes",
        "examples/live/baselines/a-skill.baseline.json",
        "examples/live/baselines/b-skill.baseline.json",
    ]
    stored = json.loads(
        _git(origin, "show", f"refs/heads/{branch}:examples/live/baselines/a-skill.baseline.json")
    )
    assert stored["eval_id"] == "eval-a-skill"
    assert stored["key"]["payload_digest"] == _payload(skills / "a-skill")
    assert _git(origin, "log", "-1", "--format=%an %s", f"refs/heads/{branch}") == (
        "github-actions[bot] chore: update baseline (#12)"
    )

    [pull] = api.pulls
    assert pull["head"] == branch and pull["base"] == "main"
    assert pull["title"] == "chore: update baseline (#12)"
    assert "`a-skill`" in pull["body"] and "`b-skill`" in pull["body"]
    assert "actions/runs/77" in pull["body"]
    assert api.blob_auth == 0
    assert api.unauthorised == 0
    assert "Bellwether baseline update" in runner.summary.read_text(encoding="utf-8")


def test_a_direct_push_proposes_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    repo, origin, merge = _merged_repository(tmp_path, {"a-skill": "v1"})
    runner = _run(repo, tmp_path, api, merge)
    assert not runner.failed, _explain(runner)
    assert runner.ran()[-1] == "Fetch the evaluation"
    assert "merged no pull request" in runner.summary.read_text(encoding="utf-8")
    assert api.pulls == []
    assert _git(origin, "branch", "--list").split() == ["main"]


def test_a_pull_request_never_evaluated_proposes_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    repo, _origin, merge = _merged_repository(tmp_path, {"a-skill": "v1"})
    api.commit_pulls[merge] = [_pull(12, merge_sha=merge)]
    api.runs = [{"id": 77, "workflow": "bellwether.yml", "head_sha": _HEAD}]  # unlabelled
    runner = _run(repo, tmp_path, api, merge)
    assert not runner.failed, _explain(runner)
    assert "uploaded 'bellwether-evidence'" in runner.summary.read_text(encoding="utf-8")
    assert api.pulls == []


def test_an_evaluation_of_an_earlier_push_proposes_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    repo, origin, merge = _merged_repository(tmp_path, {"a-skill": "v2"})
    then = _skill(tmp_path / "then", "a-skill", "v1")
    _evidence(api, merge, [_summary("a-skill", _payload(then))])
    runner = _run(repo, tmp_path, api, merge)
    assert not runner.failed, _explain(runner)
    assert "Push the baseline branch" not in runner.ran()
    assert api.pulls == []
    summary = runner.summary.read_text(encoding="utf-8")
    assert "**Not baselined:**" in summary and "not on the merged commit" in summary
    assert _git(origin, "branch", "--list").split() == ["main"]


def test_a_not_ready_merge_proposes_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    repo, _origin, merge = _merged_repository(tmp_path, {"a-skill": "v1"})
    skill = repo / "examples" / "skills" / "a-skill"
    _evidence(api, merge, [_summary("a-skill", _payload(skill), verdict="not_ready")])
    runner = _run(repo, tmp_path, api, merge)
    assert not runner.failed, _explain(runner)
    assert api.pulls == []


def test_a_baseline_already_stored_proposes_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    repo, _origin, merge = _merged_repository(tmp_path, {"a-skill": "v1"})
    summary = _summary("a-skill", _payload(repo / "examples" / "skills" / "a-skill"))
    write_baseline(baseline_from_summary(summary), repo / "examples" / "live" / "baselines")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "baselined")
    merge = _git(repo, "rev-parse", "HEAD")
    _evidence(api, merge, [summary])
    runner = _run(repo, tmp_path, api, merge)
    assert not runner.failed, _explain(runner)
    assert runner.outputs["update"]["changed"] == "false"
    assert api.pulls == []


def test_a_repository_that_forbids_actions_pull_requests_fails_naming_the_setting(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, origin, merge = _merged_repository(tmp_path, {"a-skill": "v1"})
    _evidence(api, merge, [_summary("a-skill", _payload(repo / "examples/skills/a-skill"))])
    api.create_pull_status = 403
    runner = _run(repo, tmp_path, api, merge)
    assert runner.failed
    result = runner.result("Open the baseline pull request")
    assert result.returncode == 3 and "Allow GitHub Actions to create" in result.output
    # The proposal is not lost: the branch was pushed and can be opened by hand.
    assert "bellwether/baseline-pr-12" in _git(origin, "branch", "--list")


def test_a_manual_run_baselines_the_named_run(api: FakeGitHub, tmp_path: Path) -> None:
    repo, _origin, merge = _merged_repository(tmp_path, {"a-skill": "v1"})
    api.artifacts = {91: [{"id": 910, "name": "bellwether-evidence", "expired": False}]}
    api.blobs[910] = _artifact([_summary("a-skill", _payload(repo / "examples/skills/a-skill"))])
    runner = _run(repo, tmp_path, api, merge, inputs={"run-id": "91"})
    assert not runner.failed, _explain(runner)
    [pull] = api.pulls
    assert pull["head"] == "bellwether/baseline-run-91"
    assert pull["title"] == f"chore: update baseline ({merge[:12]})"
    assert "a manual run" in pull["body"]


def test_the_workflow_is_shaped_as_documented() -> None:
    import yaml

    document = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    triggers = document[True]  # YAML 1.1 reads the bare key `on` as true
    assert triggers["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in triggers
    assert "pull_request" not in triggers and "pull_request_target" not in triggers
    assert document["permissions"] == {"contents": "read"}
    job = document["jobs"]["baseline-pr"]
    assert job["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
        "actions": "read",
    }
    text = _WORKFLOW.read_text(encoding="utf-8")
    # Inputs reach scripts through env, never interpolated into the script body.
    for step in job["steps"]:
        assert "inputs." not in str(step.get("run", ""))
    # The job never pushes to the branch it runs on.
    assert "refs/heads/${branch}" in text and "push origin main" not in text
    assert "ANTHROPIC_API_KEY" not in text
    # The token is never in .git/config, a script body or a command line: the push hands it to
    # git through a helper that reads the step's environment.
    steps = {step.get("name"): step for step in job["steps"]}
    push = str(steps["Push the baseline branch"]["run"])
    assert "'credential.helper=!f() {" in push and "password=${GITHUB_TOKEN}" in push
    assert all("github.token" not in str(step.get("run", "")) for step in job["steps"])


def test_a_manual_run_without_evidence_fails_naming_the_run(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, _origin, merge = _merged_repository(tmp_path, {"a-skill": "v1"})
    runner = _run(repo, tmp_path, api, merge, inputs={"run-id": "91"})
    assert runner.failed
    result = runner.result("Fetch the evaluation")
    assert result.returncode == 3
    assert "run 91 has no unexpired artifact named 'bellwether-evidence'" in result.output
    assert api.pulls == []
