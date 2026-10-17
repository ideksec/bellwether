"""The live workflows' commit statuses (§18.2), executed step by step.

The paid workflows (``bellwether.yml``, ``bellwether-claude-code.yml``) post one commit status per
gate group so branch protection can require them. These tests run the workflows' own scripts
(``tests/workflow_harness.py``) against scratch repositories and a fake GitHub API, through every
branch a pull request can take: no skill changed, not labelled, labelled without a key, evaluated
(a real mix of verdicts), an evaluation that broke, and a fork.

What is substituted, and only this: ``bellwether run`` is a script that drops a committed demo
evaluation tree (``examples/reports/``) into ``--out`` and exits with the code that evaluation
would — so the evaluate loop, the evidence digest, ``pr-comment`` and ``commit-status`` all run for
real against what a real run writes; the docker image builds are skipped; ``uv run`` is this venv.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

from tests.workflow_harness import (
    Event,
    FakeGitHub,
    WorkflowRunner,
    bellwether_wrapper,
)

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_REPORTS = _ROOT / "examples" / "reports"
_GROUPS = (
    "static",
    "functional",
    "consistency",
    "security",
    "evidence",
    "budget",
    "regression",
    "review",
)
_SKIP = (
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "Install uv",
    "Install Bellwether",
    "Build the recording-proxy sidecar image",
    "Build the controlled-resolver sidecar image",
    "Build the claude-code sandbox image",
)


@pytest.fixture(autouse=True)
def _passwordless_sudo() -> None:
    """The evaluate loop runs `bellwether run` under `sudo` (the overlay needs root). Where sudo
    would prompt, the step would hang; skip with the reason instead. CI runners and this
    project's container sessions have passwordless sudo."""
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if shutil.which("sudo") is None or probe.returncode != 0:
        pytest.skip("the live workflow's evaluate loop needs passwordless sudo")


@pytest.fixture
def api() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    yield fake
    fake.close()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _repository(tmp_path: Path, *, skills: tuple[str, ...]) -> tuple[Path, str, str]:
    """A base commit with docs only, then a head commit adding ``skills`` (or another doc)."""
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "a.md").write_text("a\n", encoding="utf-8")
    shutil.copytree(_ROOT / "examples" / "live", repo / "examples" / "live")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    for name in skills:
        skill = repo / "examples" / "skills" / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Counts lines in Markdown files.\n---\nx\n",
            encoding="utf-8",
        )
    if not skills:
        (repo / "docs" / "b.md").write_text("b\n", encoding="utf-8")
    # A skill-shaped fixture outside the real root: never evaluated, never reported.
    hostile = repo / "tests" / "corpus" / "hostile"
    hostile.mkdir(parents=True)
    (hostile / "SKILL.md").write_text("---\nname: hostile\ndescription: d\n---\nx\n", "utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "head")
    return repo, base, _git(repo, "rev-parse", "HEAD")


def _fake_run(tmp: Path, outcomes: Mapping[str, tuple[str | Path | None, int]]) -> Path:
    """``bellwether run`` that writes ``examples/reports/<demo>`` for each skill and exits as
    that evaluation would. ``None`` writes nothing (the run broke before any tree existed).
    The map is baked into the script because the loop runs it under ``sudo``, which resets the
    environment."""
    cases = []
    for skill, (demo, code) in outcomes.items():
        source = demo if isinstance(demo, Path) else _REPORTS / str(demo)
        copy = f'cp -r "{source}" "$out/eval-{skill}"' if demo else ":"
        cases.append(f'  "examples/skills/{skill}") {copy}; exit {code} ;;')
    script = tmp / "fake-bellwether-run"
    script.write_text(
        "#!/bin/bash\n"
        f'printf "%s\\n" "$@" > "{tmp}/run-args-$(echo "$2" | tr / -)"\n'
        'skill="$2"; out=""\n'
        'while [ $# -gt 0 ]; do if [ "$1" = "--out" ]; then out="$2"; fi; shift; done\n'
        'mkdir -p "$out"\n'
        'case "$skill" in\n'
        + "\n".join(cases)
        + '\n  *) echo "unexpected skill $skill" >&2; exit 9 ;;\nesac\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _run(
    workflow: str,
    repo: Path,
    tmp: Path,
    api: FakeGitHub,
    *,
    event: Event,
    key: str = "",
    outcomes: Mapping[str, tuple[str | Path | None, int]] | None = None,
) -> WorkflowRunner:
    bellwether = Path(sys.executable).parent / "bellwether"
    wrapper = bellwether_wrapper(tmp, str(bellwether), api)
    fake_run = _fake_run(tmp, outcomes or {})
    runner = WorkflowRunner(
        _WORKFLOWS / workflow,
        "evaluate",
        repo,
        tmp,
        event=event,
        api=api,
        secrets={"ANTHROPIC_API_KEY": key},
        substitutions=[
            ('bw="$(pwd)/.venv/bin/bellwether"', f'bw="{fake_run}"'),
            ("uv run python tools/", f"{sys.executable} {_ROOT}/tools/"),
            ("uv run bellwether", str(wrapper)),
        ],
        skip=_SKIP,
    )
    runner.run()
    return runner


def _states(api: FakeGitHub, prefix: str = "bellwether") -> dict[str, str]:
    latest = api.latest_statuses()
    return {
        context.removeprefix(f"{prefix}/"): status["state"]
        for context, status in latest.items()
        if context.startswith(f"{prefix}/")
    }


def _every_context(prefix: str = "bellwether") -> set[str]:
    return {f"{prefix}/{name}" for name in (*_GROUPS, "verdict", "ready")}


# ---------------------------------------------------------------------------


def test_a_pull_request_changing_no_skill_passes_every_context(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, base, head = _repository(tmp_path, skills=())
    runner = _run("bellwether.yml", repo, tmp_path, api, event=Event(base_sha=base, head_sha=head))
    assert not runner.failed, [(r.name, r.output[-400:]) for r in runner.results if r.returncode]
    assert set(api.latest_statuses()) == _every_context()
    assert all(s["state"] == "success" for s in api.statuses)
    assert {s["sha"] for s in api.statuses} == {head}
    assert all("no skill changed" in s["description"] for s in api.statuses)


def test_an_unlabelled_skill_change_is_pending_and_spends_nothing(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, base, head = _repository(tmp_path, skills=("a",))
    runner = _run("bellwether.yml", repo, tmp_path, api, event=Event(base_sha=base, head_sha=head))
    assert not runner.failed
    assert "Evaluate and comment" not in runner.ran()
    assert set(_states(api).values()) == {"pending"}
    assert set(api.latest_statuses()) == _every_context()
    assert "bellwether-run label" in api.statuses[0]["description"]


def test_a_labelled_change_without_a_key_is_pending_not_passed(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, base, head = _repository(tmp_path, skills=("a",))
    event = Event(base_sha=base, head_sha=head, labels=("bellwether-run",))
    runner = _run("bellwether.yml", repo, tmp_path, api, event=event, key="")
    assert not runner.failed
    assert runner.outputs["evaluate"]["status"] == "skipped"
    assert set(_states(api).values()) == {"pending"}
    assert "ANTHROPIC_API_KEY is not set" in api.statuses[-1]["description"]


def test_evaluated_skills_report_the_worst_gate_per_group(api: FakeGitHub, tmp_path: Path) -> None:
    """Two skills: a conditional one and a not_ready one. Each group reports the worse; the
    verdict fails on not_ready; `ready` fails because neither is ready; each evaluation gets its
    own PR comment; the hostile fixture outside the root is never run."""
    repo, base, head = _repository(tmp_path, skills=("a", "b"))
    event = Event(base_sha=base, head_sha=head, labels=("bellwether-run",))
    runner = _run(
        "bellwether.yml",
        repo,
        tmp_path,
        api,
        event=event,
        key="sk-test",
        outcomes={"a": ("demo-benign-note-taker", 0), "b": ("demo-sneaky-exfiltrator", 2)},
    )
    # The evaluate step fails on the not_ready verdict; the statuses still post.
    assert runner.result("Evaluate and comment").returncode == 2
    assert runner.outputs["evaluate"]["status"] == "2"
    assert "Commit statuses" in runner.ran()
    states = _states(api)
    assert states["verdict"] == "failure" and states["ready"] == "failure"
    assert states["static"] == "failure" and states["security"] == "failure"
    assert states["review"] == "failure"
    assert states["consistency"] == "success" and states["regression"] == "success"
    assert {s["sha"] for s in api.statuses} == {head}
    latest = api.latest_statuses()
    assert "sneaky-exfiltrator" in latest["bellwether/verdict"]["description"]
    assert all(len(s["description"]) <= 140 for s in api.statuses)
    # One comment per evaluation, keyed apart.
    assert len(api.comments) == 2
    assert api.unauthorised == 0
    listed = (repo / ".bellwether-out" / "evaluations.txt").read_text("utf-8").splitlines()
    assert len(listed) == 2 and not any("hostile" in line for line in listed)


def test_an_all_ready_evaluation_passes_verdict_and_ready(api: FakeGitHub, tmp_path: Path) -> None:
    """The committed demos are all short of ready, so readiness is checked on a copy (in the
    test's own directory) whose verdict is ready — the case a repository requiring
    `bellwether/ready` merges on."""
    import json

    ready_demo = tmp_path / "demo-ready"
    shutil.copytree(_REPORTS / "demo-benign-note-taker", ready_demo)
    summary = ready_demo / "summary.json"
    data = json.loads(summary.read_text("utf-8"))
    data["verdict"]["status"] = "ready"
    data["verdict"]["gates"] = [{**g, "status": "pass"} for g in data["verdict"]["gates"]]
    summary.write_text(json.dumps(data), encoding="utf-8")
    repo, base, head = _repository(tmp_path, skills=("a",))
    event = Event(base_sha=base, head_sha=head, labels=("bellwether-run",))
    runner = _run(
        "bellwether.yml",
        repo,
        tmp_path,
        api,
        event=event,
        key="sk-test",
        outcomes={"a": (ready_demo, 0)},
    )
    assert not runner.failed, [(r.name, r.output[-400:]) for r in runner.results if r.returncode]
    assert set(_states(api).values()) == {"success"}


def test_an_infrastructure_failure_before_any_tree_fails_every_context(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, base, head = _repository(tmp_path, skills=("a",))
    event = Event(base_sha=base, head_sha=head, labels=("bellwether-run",))
    _run(
        "bellwether.yml", repo, tmp_path, api, event=event, key="sk-test", outcomes={"a": (None, 3)}
    )
    assert set(_states(api).values()) == {"failure"}
    assert "did not complete" in api.statuses[-1]["description"]


def test_an_infrastructure_failure_is_not_hidden_by_a_later_verdict(
    api: FakeGitHub, tmp_path: Path
) -> None:
    """The loop kept the *last* non-zero exit: skill `a` breaking (3) and skill `b` landing
    not_ready (2) reported 2, and the statuses would then have been read from the summaries —
    `a`'s broken evaluation counted as evidence. The worst code wins now."""
    repo, base, head = _repository(tmp_path, skills=("a", "b"))
    event = Event(base_sha=base, head_sha=head, labels=("bellwether-run",))
    runner = _run(
        "bellwether.yml",
        repo,
        tmp_path,
        api,
        event=event,
        key="sk-test",
        outcomes={"a": ("demo-benign-note-taker", 3), "b": ("demo-sneaky-exfiltrator", 2)},
    )
    assert runner.outputs["evaluate"]["status"] == "3"
    assert set(_states(api).values()) == {"failure"}
    assert "exit 3" in api.statuses[-1]["description"]


@pytest.mark.parametrize("labels", [(), ("bellwether-run",)])
def test_a_fork_posts_no_status(api: FakeGitHub, tmp_path: Path, labels: tuple[str, ...]) -> None:
    repo, base, head = _repository(tmp_path, skills=("a",))
    event = Event(base_sha=base, head_sha=head, labels=labels, fork=True)
    runner = _run("bellwether.yml", repo, tmp_path, api, event=event, key="")
    assert not runner.failed
    assert api.statuses == []


def test_the_claude_code_workflow_posts_under_its_own_prefix(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, base, head = _repository(tmp_path, skills=())
    runner = _run(
        "bellwether-claude-code.yml", repo, tmp_path, api, event=Event(base_sha=base, head_sha=head)
    )
    assert not runner.failed
    assert set(api.latest_statuses()) == _every_context("bellwether-claude-code")


@pytest.mark.parametrize("workflow", ["bellwether.yml", "bellwether-claude-code.yml"])
def test_statuses_are_written_with_the_permission_and_on_the_head_sha(workflow: str) -> None:
    import yaml

    document = yaml.safe_load((_WORKFLOWS / workflow).read_text("utf-8"))
    assert document["permissions"]["statuses"] == "write"
    text = (_WORKFLOWS / workflow).read_text("utf-8")
    # On a pull request, never GITHUB_SHA: it is the merge commit, invisible on the PR. The
    # one use is a manual (workflow_dispatch) run's, which has no pull request and posts on the
    # dispatched commit — and it sits inside that branch of the detect step.
    assert "PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in text
    body = text.split("jobs:")[1]
    assert "github.sha" not in body
    assert body.count("${GITHUB_SHA}") == 1 and "$GITHUB_SHA" not in body
    detect = {s.get("name"): s for s in document["jobs"]["evaluate"]["steps"]}[
        "Detect changed skills"
    ]["run"]
    dispatch_branch = detect.split('if [ "${GITHUB_EVENT_NAME}" = "workflow_dispatch" ]; then')[
        1
    ].split("else")[0]
    assert 'sha="${GITHUB_SHA}"' in dispatch_branch
    assert 'sha="${PR_HEAD_SHA}"' in detect.split(dispatch_branch)[1]
    for step in document["jobs"]["evaluate"]["steps"]:
        if "HEAD_SHA" in (step.get("env") or {}):
            assert step["env"]["HEAD_SHA"] == "${{ steps.detect.outputs.sha }}"
    steps = {s.get("name"): s for s in document["jobs"]["evaluate"]["steps"]}
    assert steps["Commit statuses"]["if"].strip().startswith("always()")
    # The loop appends to .bellwether-out/ as the runner user; `sudo … run` would otherwise
    # create it as root first. A test run as root cannot see this, so it is pinned here too.
    loop = steps["Evaluate and comment"]["run"]
    assert loop.index("mkdir -p .bellwether-out") < loop.index("sudo --preserve-env")


# ---------------------------------------------------------------------------
# A manual run (§18.1 workflow_dispatch)
# ---------------------------------------------------------------------------


def _dispatch(**inputs: str) -> Event:
    return Event(name="workflow_dispatch", action="", inputs=inputs)


def _run_args(tmp: Path, skill: str) -> list[str]:
    return (tmp / f"run-args-{skill.replace('/', '-')}").read_text("utf-8").splitlines()


@pytest.mark.parametrize("workflow", ["bellwether.yml", "bellwether-claude-code.yml"])
def test_a_dispatch_evaluates_the_named_skill_and_posts_on_the_dispatched_commit(
    api: FakeGitHub, tmp_path: Path, workflow: str
) -> None:
    repo, _base, head = _repository(tmp_path, skills=("a", "b"))
    event = _dispatch(skill="examples/skills/a", depth="configured")
    event.merge_sha = head  # github.sha on a dispatch is the dispatched ref's head
    runner = _run(
        workflow,
        repo,
        tmp_path,
        api,
        event=event,
        key="sk-test",
        outcomes={"a": ("demo-benign-note-taker", 0)},
    )
    assert not runner.failed, [(r.name, r.output[-600:]) for r in runner.results if r.returncode]
    assert "Evaluate and comment" in runner.ran()
    # Only the named skill, with no matrix override: `configured` passes nothing.
    assert not (tmp_path / "run-args-examples-skills-b").exists()
    args = _run_args(tmp_path, "examples/skills/a")
    assert "--depth" not in args and "--profile" not in args and "--targets" not in args
    # No pull request: no comment, and the statuses land on the dispatched commit.
    assert api.comments == []
    prefix = "bellwether-claude-code" if "claude" in workflow else "bellwether"
    assert set(api.latest_statuses()) == _every_context(prefix)
    assert {status["sha"] for status in api.statuses} == {head}


def test_a_dispatch_passes_each_choice_as_one_argument(api: FakeGitHub, tmp_path: Path) -> None:
    repo, _base, head = _repository(tmp_path, skills=("a",))
    event = _dispatch(
        skill="examples/skills/a/",
        profile="strict",
        depth="deep",
        targets="small --no-cache",
    )
    event.merge_sha = head
    runner = _run(
        "bellwether.yml",
        repo,
        tmp_path,
        api,
        event=event,
        key="sk-test",
        outcomes={"a": ("demo-benign-note-taker", 0)},
    )
    assert not runner.failed
    args = _run_args(tmp_path, "examples/skills/a")
    assert args[args.index("--profile") + 1] == "strict"
    assert args[args.index("--depth") + 1] == "deep"
    # Free text from the form stays one argument: never split into a further option.
    assert args[args.index("--targets") + 1] == "small --no-cache"
    assert "--no-cache" not in args


@pytest.mark.parametrize(
    "skill",
    [
        "tests/corpus/hostile",  # skill-shaped, outside the root
        "examples/skills/../../tests/corpus/hostile",  # climbs out
        "examples/skills/missing",  # no such skill
        "/etc",
        "",
    ],
)
def test_a_dispatch_of_anything_but_a_skill_under_the_root_is_refused(
    api: FakeGitHub, tmp_path: Path, skill: str
) -> None:
    repo, _base, head = _repository(tmp_path, skills=("a",))
    event = _dispatch(skill=skill)
    event.merge_sha = head
    runner = _run("bellwether.yml", repo, tmp_path, api, event=event, key="sk-test")
    assert runner.failed
    assert runner.result("Detect changed skills").returncode == 3
    assert "Evaluate and comment" not in runner.ran()
    assert not list(tmp_path.glob("run-args-*"))
    assert api.statuses == [] and api.comments == []


def test_a_dispatch_without_the_key_spends_nothing_and_says_so(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, _base, head = _repository(tmp_path, skills=("a",))
    event = _dispatch(skill="examples/skills/a")
    event.merge_sha = head
    runner = _run("bellwether.yml", repo, tmp_path, api, event=event)
    assert not runner.failed
    assert not list(tmp_path.glob("run-args-*"))
    assert set(_states(api).values()) == {"pending"}
