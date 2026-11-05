"""The scheduled coexistence run (§7.4 item 1, §18.4): the reading, the issue, the report command
and ``bellwether-coexistence.yml`` executed.

Mirrors ``test_drift.py``: the matrix is read into one of three states, a collision or a change
keeps the library's one issue open, and the workflow is run step by step in the harness with a
fake ``bellwether coexistence`` dropping a matrix and the real ``coexistence-report`` reading it
against a fake GitHub.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bellwether.cli.app import app
from bellwether.cli.coexistence import (
    COEXISTENCE_N,
    NO_ACTIVATION,
    CoexistenceMatrix,
    ProbeCell,
    coexistence_findings,
    coexistence_status,
    compare_with_baseline,
    render_coexistence_issue,
    render_coexistence_json,
    upsert_coexistence_issue,
)
from bellwether.cli.pr import github_transport
from tests.workflow_harness import (
    FAKE_TOKEN,
    Event,
    FakeGitHub,
    WorkflowRunner,
    bellwether_wrapper,
)

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "bellwether-coexistence.yml"
runner = CliRunner()


@pytest.fixture
def api() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    yield fake
    fake.close()


# ---------------------------------------------------------------------------
# Matrices
# ---------------------------------------------------------------------------


def _cell(skill: str, probe: str, winners: dict[str, int]) -> ProbeCell:
    return ProbeCell(
        skill=skill,
        probe_id=probe,
        probe_kind="activation",
        source="marked",
        runs=COEXISTENCE_N,
        winners=dict(sorted(winners.items())),
    )


def _matrix(cells: list[ProbeCell], *, key: str = "sha256:" + "1" * 64) -> CoexistenceMatrix:
    return CoexistenceMatrix(
        library_key=key,
        members=("alpha", "beta"),
        member_digests={"alpha": "sha256:" + "a" * 64, "beta": "sha256:" + "b" * 64},
        target="claude-code-anthropic-haiku",
        harness="claude-code",
        portable=True,
        n=COEXISTENCE_N,
        created_at="2026-11-05T05:23:00+00:00",
        bellwether_version="0.1.0",
        cells=tuple(cells),
    )


_CLEAN = _matrix([_cell("alpha", "act", {"alpha": 12}), _cell("beta", "act", {"beta": 12})])
_COLLIDING = _matrix([_cell("alpha", "act", {"beta": 12}), _cell("beta", "act", {"beta": 12})])
_MOVED = _matrix(
    [_cell("alpha", "act", {"alpha": 8, NO_ACTIVATION: 4}), _cell("beta", "act", {"beta": 12})]
)


# ---------------------------------------------------------------------------
# The reading
# ---------------------------------------------------------------------------


def test_a_probe_won_by_another_skill_is_a_collision() -> None:
    delta = compare_with_baseline(_COLLIDING, None)
    assert coexistence_status(_COLLIDING, delta) == "collisions"
    findings = coexistence_findings(_COLLIDING, delta)
    assert findings == ("`alpha`'s `act` probe (activation) was won by `beta` on 12 of 12 runs",)


def test_a_moved_matrix_with_no_collision_is_changed_only_against_a_comparable_baseline() -> None:
    assert coexistence_status(_MOVED, compare_with_baseline(_MOVED, None)) == "clean"
    delta = compare_with_baseline(_MOVED, _CLEAN)
    assert delta.comparable and delta.changes
    assert coexistence_status(_MOVED, delta) == "changed"
    assert coexistence_findings(_MOVED, delta) == delta.changes


def test_a_clean_matrix_is_clean_whether_or_not_it_can_be_compared() -> None:
    assert coexistence_status(_CLEAN, compare_with_baseline(_CLEAN, None)) == "clean"
    assert coexistence_status(_CLEAN, compare_with_baseline(_CLEAN, _CLEAN)) == "clean"
    other = _matrix(list(_CLEAN.cells), key="sha256:" + "2" * 64)
    assert coexistence_status(_CLEAN, compare_with_baseline(_CLEAN, other)) == "clean"


def test_the_issue_body_is_inert_and_carries_both_markers() -> None:
    hostile = _matrix(
        [_cell("alpha", "act", {"@everyone <img src=x onerror=1>": 12})],
    )
    title, body = render_coexistence_issue(
        hostile, compare_with_baseline(hostile, None), run_url="https://example/run"
    )
    assert title.startswith("Bellwether coexistence: 1 probe(s) won by another skill")
    # The name is inside a code span, where a mention notifies nobody and a tag is text.
    assert "`@everyone <img src=x onerror=1>`" in body
    assert body.count("<img") == 1
    assert body.rstrip().endswith("<!-- bellwether-coexistence -->")
    assert "<!-- bellwether-coexistence-findings:" in body
    assert "https://example/run" in body


# ---------------------------------------------------------------------------
# The issue
# ---------------------------------------------------------------------------


def _upsert(api: FakeGitHub, matrix: CoexistenceMatrix, baseline: CoexistenceMatrix | None) -> str:
    return upsert_coexistence_issue(
        github_transport(),
        "o/r",
        matrix,
        compare_with_baseline(matrix, baseline),
        token=FAKE_TOKEN,
        run_url="https://example/run",
        api_root=api.url,
    )


def test_a_collision_opens_one_issue_and_an_unchanged_run_adds_nothing(api: FakeGitHub) -> None:
    assert _upsert(api, _COLLIDING, None) == "opened"
    [issue] = api.issues
    assert "won by `beta`" in issue["body"]
    assert _upsert(api, _COLLIDING, None) == "unchanged"
    assert len(api.issues) == 1 and not api.comments


def test_changed_findings_edit_the_issue_and_say_so(api: FakeGitHub) -> None:
    _upsert(api, _COLLIDING, None)
    worse = _matrix(
        [_cell("alpha", "act", {"beta": 12}), _cell("beta", "act", {"alpha": 3, "beta": 9})]
    )
    assert _upsert(api, worse, None) == "updated"
    [issue] = api.issues
    assert "`beta`'s `act` probe" in issue["body"]
    [comment] = api.comments
    assert "matrix changed" in comment["body"]


def test_a_clean_run_closes_the_issue(api: FakeGitHub) -> None:
    _upsert(api, _COLLIDING, None)
    assert _upsert(api, _CLEAN, _CLEAN) == "closed"
    [issue] = api.issues
    assert issue["state"] == "closed"
    [comment] = api.comments
    assert "Closing" in comment["body"]


def test_a_clean_run_with_no_issue_opens_nothing(api: FakeGitHub) -> None:
    assert _upsert(api, _CLEAN, None) == "none"
    assert not api.issues


def test_an_issue_a_person_wrote_with_the_marker_is_never_touched(api: FakeGitHub) -> None:
    api.issues.append(
        {
            "number": 41,
            "state": "open",
            "title": "mine",
            "body": "notes\n<!-- bellwether-coexistence -->\n",
            "user": {"type": "User", "login": "someone"},
        }
    )
    assert _upsert(api, _COLLIDING, None) == "opened"
    assert len(api.issues) == 2 and api.issues[0]["title"] == "mine"


# ---------------------------------------------------------------------------
# The report command
# ---------------------------------------------------------------------------


def _write(path: Path, matrix: CoexistenceMatrix) -> Path:
    path.write_text(render_coexistence_json(matrix), encoding="utf-8")
    return path


def test_the_report_exits_two_on_collisions_and_zero_when_clean(tmp_path: Path) -> None:
    colliding = _write(tmp_path / "colliding.json", _COLLIDING)
    result = runner.invoke(
        app, ["coexistence-report", str(colliding), "--markdown", str(tmp_path / "r.md"), "--json"]
    )
    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "collisions" and not payload["comparable"]
    assert "| `alpha` | `act` (activation, marked) | `beta` 12/12 |" in (
        tmp_path / "r.md"
    ).read_text(encoding="utf-8")
    clean = _write(tmp_path / "clean.json", _CLEAN)
    baseline = _write(tmp_path / "_library.coexistence.json", _CLEAN)
    result = runner.invoke(
        app, ["coexistence-report", str(clean), "--baseline", str(baseline), "--json"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "status": "clean",
        "findings": [],
        "comparable": True,
        "reason": "same library, target and N as the stored baseline",
        "issue": "none",
    }


def test_the_report_refuses_what_is_not_a_matrix(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.json"
    bogus.write_text('{"hello": 1}', encoding="utf-8")
    result = runner.invoke(app, ["coexistence-report", str(bogus)])
    assert result.exit_code == 3
    assert "not a coexistence matrix" in result.output
    missing = runner.invoke(app, ["coexistence-report", str(tmp_path / "missing.json")])
    assert missing.exit_code == 3


# ---------------------------------------------------------------------------
# The workflow
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("event", "runs"),
    [
        (Event(name="schedule", action=""), False),
        (Event(name="schedule", action="", vars={"BELLWETHER_COEXISTENCE": "false"}), False),
        (Event(name="schedule", action="", vars={"BELLWETHER_COEXISTENCE": "true"}), True),
        (Event(name="workflow_dispatch", action=""), True),
    ],
)
def test_the_schedule_spends_nothing_until_a_maintainer_opts_in(
    tmp_path: Path, event: Event, runs: bool
) -> None:
    runner_ = WorkflowRunner(_WORKFLOW, "coexistence", tmp_path, tmp_path, event=event)
    assert runner_.job_runs() is runs


def test_the_workflow_is_shaped_as_documented() -> None:
    import yaml

    document = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    triggers = document[True]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert document["permissions"] == {"contents": "read"}
    job = document["jobs"]["coexistence"]
    assert job["permissions"] == {"contents": "read", "issues": "write"}
    steps = {s.get("name"): s for s in job["steps"]}
    matrix = steps["Run the matrix"]["run"]
    # §9.4: the harness is claude-code; api-loop only by an explicit dispatch input.
    assert "config-claude-code.yaml" in document["env"]["BELLWETHER_CONFIG"]
    assert "--force" in matrix and 'DISPATCH_FORCE:-false}" = "true"' in matrix
    assert matrix.index("mkdir -p .bellwether-out") < matrix.index("sudo --preserve-env")
    assert "--targets" in matrix and "--yes" in matrix
    report = steps["Read the matrix"]["run"]
    assert "coexistence-report" in report and "--issues" in report
    assert "_library.coexistence.json" in report
    for step in job["steps"]:
        if str(step.get("uses", "")).startswith("actions/checkout"):
            assert step["with"]["persist-credentials"] is False


@pytest.fixture
def _passwordless_sudo() -> None:
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if shutil.which("sudo") is None or probe.returncode != 0:
        pytest.skip("the coexistence step needs passwordless sudo")


def _repository(tmp_path: Path, baseline: CoexistenceMatrix | None) -> Path:
    repo = tmp_path / "repo"
    for name in ("alpha", "beta"):
        skill = repo / "examples" / "skills" / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Does {name} things.\n---\nx\n", encoding="utf-8"
        )
    baselines = repo / "examples" / "live" / "baselines"
    baselines.mkdir(parents=True)
    if baseline is not None:
        _write(baselines / "_library.coexistence.json", baseline)
    else:
        (baselines / ".keep").write_text("", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "m",
        ],
        check=True,
    )
    return repo


def _fake_coexistence(tmp: Path, matrix: CoexistenceMatrix | None, code: int) -> Path:
    """A ``bellwether`` whose ``coexistence`` drops ``matrix`` under ``--out`` and exits ``code``."""
    source = tmp / "fixture-coexistence.json"
    if matrix is not None:
        _write(source, matrix)
    script = tmp / "fake-bellwether"
    script.write_text(
        "#!/bin/bash\n"
        f'printf "%s\\n" "$@" > "{tmp}/coexistence-args"\n'
        'out=""\n'
        'while [ $# -gt 0 ]; do if [ "$1" = "--out" ]; then out="$2"; fi; shift; done\n'
        'mkdir -p "$out/coexistence-20261105T052300Z"\n'
        + (
            f'cp "{source}" "$out/coexistence-20261105T052300Z/coexistence.json"\n'
            'echo "# matrix" > "$out/coexistence-20261105T052300Z/coexistence.md"\n'
            if matrix is not None
            else ""
        )
        + f"exit {code}\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _run_workflow(
    repo: Path,
    tmp: Path,
    api: FakeGitHub,
    matrix: CoexistenceMatrix | None,
    *,
    code: int = 0,
    event: Event | None = None,
) -> WorkflowRunner:
    wrapper = bellwether_wrapper(tmp, str(Path(sys.executable).parent / "bellwether"), api)
    runner_ = WorkflowRunner(
        _WORKFLOW,
        "coexistence",
        repo,
        tmp,
        event=event or Event(name="schedule", action="", vars={"BELLWETHER_COEXISTENCE": "true"}),
        api=api,
        secrets={"ANTHROPIC_API_KEY": "sk-test"},
        substitutions=[
            ('bw="$(pwd)/.venv/bin/bellwether"', f'bw="{_fake_coexistence(tmp, matrix, code)}"'),
            ("uv run bellwether", str(wrapper)),
        ],
        skip=(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
            "Install uv",
            "Install Bellwether",
            "Build the claude-code sandbox image",
            "Build the recording-proxy sidecar image",
            "Build the controlled-resolver sidecar image",
        ),
    )
    runner_.run()
    return runner_


def _explain(runner_: WorkflowRunner) -> list[tuple[str, int, str]]:
    return [(r.name, r.returncode, r.output[-1200:]) for r in runner_.results if r.ran]


@pytest.mark.usefixtures("_passwordless_sudo")
def test_a_colliding_run_opens_the_issue_and_fails(api: FakeGitHub, tmp_path: Path) -> None:
    repo = _repository(tmp_path, baseline=_CLEAN)
    runner_ = _run_workflow(repo, tmp_path, api, _COLLIDING)
    assert runner_.failed
    assert runner_.result("Read the matrix").returncode == 2, _explain(runner_)
    [issue] = api.issues
    assert issue["title"].startswith("Bellwether coexistence: 1 probe(s)")
    summary = runner_.summary.read_text(encoding="utf-8")
    assert "Bellwether coexistence matrix" in summary and "`beta` 12/12" in summary
    args = (tmp_path / "coexistence-args").read_text(encoding="utf-8").splitlines()
    # The library root, the claude-code live config, one target, no estimate prompt, no --force
    # unless dispatched with it.
    assert args[:2] == ["coexistence", "examples/skills"]
    assert "examples/live/config-claude-code.yaml" in args
    assert "--targets" in args and args[args.index("--targets") + 1] == "haiku"
    assert "--yes" in args and "--force" not in args
    assert "Upload the matrix and the evidence" in runner_.ran()


@pytest.mark.usefixtures("_passwordless_sudo")
def test_a_clean_run_passes_and_opens_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    repo = _repository(tmp_path, baseline=_CLEAN)
    runner_ = _run_workflow(repo, tmp_path, api, _CLEAN)
    assert not runner_.failed, _explain(runner_)
    assert not api.issues
    assert "No change against the stored library baseline." in runner_.summary.read_text(
        encoding="utf-8"
    )


@pytest.mark.usefixtures("_passwordless_sudo")
def test_a_dispatch_passes_its_target_and_force_through(api: FakeGitHub, tmp_path: Path) -> None:
    repo = _repository(tmp_path, baseline=None)
    event = Event(name="workflow_dispatch", action="", inputs={"targets": "small", "force": "true"})
    runner_ = _run_workflow(repo, tmp_path, api, _CLEAN, event=event)
    assert not runner_.failed, _explain(runner_)
    args = (tmp_path / "coexistence-args").read_text(encoding="utf-8").splitlines()
    assert args[args.index("--targets") + 1] == "small" and "--force" in args
    # No baseline stored: said so, never diffed against nothing.
    assert "no library baseline stored" in runner_.summary.read_text(encoding="utf-8")


@pytest.mark.usefixtures("_passwordless_sudo")
def test_a_broken_matrix_run_fails_as_infrastructure(api: FakeGitHub, tmp_path: Path) -> None:
    repo = _repository(tmp_path, baseline=None)
    runner_ = _run_workflow(repo, tmp_path, api, None, code=3)
    assert runner_.failed
    assert runner_.result("Run the matrix").returncode == 3, _explain(runner_)
    assert not runner_.result("Read the matrix").ran
    assert not api.issues
    assert "Upload the matrix and the evidence" in runner_.ran()


def test_the_schedule_is_off_without_the_key_too(tmp_path: Path, api: FakeGitHub) -> None:
    """Opted in but no key: the first step refuses as a configuration error (exit 3), and
    nothing is read or opened."""
    repo = _repository(tmp_path, baseline=None)
    wrapper = bellwether_wrapper(tmp_path, str(Path(sys.executable).parent / "bellwether"), api)
    runner_ = WorkflowRunner(
        _WORKFLOW,
        "coexistence",
        repo,
        tmp_path,
        event=Event(name="schedule", action="", vars={"BELLWETHER_COEXISTENCE": "true"}),
        api=api,
        secrets={},
        substitutions=[("uv run bellwether", str(wrapper))],
        skip=(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
            "Install uv",
            "Install Bellwether",
            "Build the claude-code sandbox image",
            "Build the recording-proxy sidecar image",
            "Build the controlled-resolver sidecar image",
        ),
    )
    runner_.run()
    assert runner_.result("Run the matrix").returncode == 3, _explain(runner_)
    assert not runner_.result("Read the matrix").ran
    assert not api.issues
