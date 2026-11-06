"""The library baseline-update pull request (§7.4, §17.5, §18.4 step 5): the artifact reader,
the tree check, the body, ``bellwether baseline library`` and both jobs of
``bellwether-coexistence.yml`` executed.

Mirrors ``test_baseline_pr.py``: the matrix job runs in the harness with a fake ``bellwether
coexistence`` dropping a matrix of the scratch repository's real skills, the test stands in for
``actions/upload-artifact`` (the one hop the harness cannot execute — it zips the matrix the job
selected and registers it as the run's artifact on the fake GitHub), and the baseline job then
runs its own steps in a fresh clone of the bare ``origin``, so the branch push and the pull
request are the real ones the job would make.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import zipfile
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from bellwether.cli.app import app
from bellwether.cli.coexistence import (
    COEXISTENCE_N,
    NO_ACTIVATION,
    CoexistenceMatrix,
    ProbeCell,
    compare_with_baseline,
    library_key,
    library_members,
    render_coexistence_json,
    write_library_baseline,
)
from bellwether.cli.library_baseline import (
    library_mismatch,
    plan_library_baseline,
    read_matrix_artifact,
    render_library_baseline_pr_body,
)
from bellwether.errors import BellwetherError
from tests.workflow_harness import Event, FakeGitHub, WorkflowRunner, bellwether_wrapper

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "bellwether-coexistence.yml"
_ARTIFACT = "bellwether-coexistence-matrix"
_SKIP = (
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "Install uv",
    "Install Bellwether",
    "Build the claude-code sandbox image",
    "Build the recording-proxy sidecar image",
    "Build the controlled-resolver sidecar image",
)
runner = CliRunner()


@pytest.fixture
def api() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    yield fake
    fake.close()


# ---------------------------------------------------------------------------
# Fixtures: a library on disk, and matrices of it
# ---------------------------------------------------------------------------


def _skill(root: Path, name: str, description: str | None = None) -> Path:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description or f'Does {name} things.'}\n---\nx\n",
        encoding="utf-8",
    )
    return directory


def _library(root: Path, *names: str) -> Path:
    for name in names:
        _skill(root, name)
    return root


def _cell(skill: str, probe: str, winners: Mapping[str, int]) -> ProbeCell:
    return ProbeCell(
        skill=skill,
        probe_id=probe,
        probe_kind="activation",
        source="marked",
        runs=COEXISTENCE_N,
        winners=dict(sorted(winners.items())),
    )


def _matrix_of(
    root: Path, cells: list[ProbeCell] | None = None, **overrides: object
) -> CoexistenceMatrix:
    """A matrix whose members, digests and key are those of the skills under ``root``."""
    packages = [member.package for member in library_members(root)]
    members = tuple(package.name for package in packages)
    fields: dict[str, object] = {
        "library_key": library_key(packages),
        "members": members,
        "member_digests": {package.name: package.package_digest for package in packages},
        "target": "claude-code-anthropic-haiku",
        "harness": "claude-code",
        "portable": True,
        "n": COEXISTENCE_N,
        "created_at": "2026-11-06T05:23:00+00:00",
        "bellwether_version": "0.1.0",
        "cells": tuple(
            cells
            if cells is not None
            else [_cell(name, "act", {name: COEXISTENCE_N}) for name in members]
        ),
    }
    fields.update(overrides)
    return CoexistenceMatrix.model_validate(fields)


def _zip(members: Mapping[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _artifact(matrix: CoexistenceMatrix, *, root: str = "") -> bytes:
    return _zip({f"{root}coexistence.json": render_coexistence_json(matrix).encode("utf-8")})


def _publish(
    api: FakeGitHub, run_id: int, matrix: CoexistenceMatrix | bytes, **entry: object
) -> None:
    """Register ``matrix`` as run ``run_id``'s matrix artifact on the fake GitHub."""
    artifact_id = 7000 + run_id
    api.artifacts[run_id] = [{"id": artifact_id, "name": _ARTIFACT, "expired": False, **entry}]
    api.blobs[artifact_id] = matrix if isinstance(matrix, bytes) else _artifact(matrix)


# ---------------------------------------------------------------------------
# Reading the artifact
# ---------------------------------------------------------------------------


def test_the_matrix_is_read_wherever_upload_artifact_rooted_it(tmp_path: Path) -> None:
    matrix = _matrix_of(_library(tmp_path, "alpha", "beta"))
    assert read_matrix_artifact(_artifact(matrix)) == matrix
    assert read_matrix_artifact(_artifact(matrix, root="coexistence-20261106T052300Z/")) == matrix


def test_an_artifact_with_no_matrix_or_two_is_refused(tmp_path: Path) -> None:
    matrix = _matrix_of(_library(tmp_path, "alpha", "beta"))
    with pytest.raises(BellwetherError, match="holds 0 member"):
        read_matrix_artifact(_zip({"coexistence.md": b"# matrix"}))
    rendered = render_coexistence_json(matrix).encode("utf-8")
    with pytest.raises(BellwetherError, match=r"holds 2 member.*exactly one"):
        read_matrix_artifact(_zip({"a/coexistence.json": rendered, "b/coexistence.json": rendered}))


def test_what_is_not_a_matrix_or_not_a_zip_is_refused() -> None:
    with pytest.raises(BellwetherError, match="not a coexistence matrix"):
        read_matrix_artifact(_zip({"coexistence.json": b'{"hello": 1}'}))
    with pytest.raises(BellwetherError, match="not a zip"):
        read_matrix_artifact(b"not a zip at all")


def test_an_oversized_member_is_refused_before_it_is_decompressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bellwether.cli.library_baseline as module

    monkeypatch.setattr(module, "_MAX_MATRIX_BYTES", 64)
    big = _zip({"coexistence.json": b"{" + b" " * 4096 + b"}"})

    def never(self: zipfile.ZipFile, *args: object, **kwargs: object) -> bytes:
        raise AssertionError("decompressed a member the header already said was over the cap")

    monkeypatch.setattr(zipfile.ZipFile, "read", never)
    with pytest.raises(BellwetherError, match="over 64"):
        read_matrix_artifact(big)


# ---------------------------------------------------------------------------
# The tree check
# ---------------------------------------------------------------------------


def test_a_matrix_of_this_tree_passes_the_check(tmp_path: Path) -> None:
    root = _library(tmp_path, "alpha", "beta")
    packages = [m.package for m in library_members(root)]
    assert library_mismatch(_matrix_of(root), packages) is None


def test_a_changed_added_or_removed_member_is_named(tmp_path: Path) -> None:
    root = _library(tmp_path / "then", "alpha", "beta", "gamma")
    matrix = _matrix_of(root)
    now = _library(tmp_path / "now", "alpha", "delta")
    _skill(now, "beta", "Does other things now.")
    packages = [m.package for m in library_members(now)]
    reason = library_mismatch(matrix, packages)
    assert reason is not None
    assert "added: delta" in reason and "removed: gamma" in reason and "changed: beta" in reason
    assert "re-run the matrix" in reason


def test_a_key_that_disagrees_with_its_members_is_refused(tmp_path: Path) -> None:
    root = _library(tmp_path, "alpha", "beta")
    forged = _matrix_of(root, library_key="sha256:" + "f" * 64)
    packages = [m.package for m in library_members(root)]
    reason = library_mismatch(forged, packages)
    assert reason is not None and "library key" in reason


# ---------------------------------------------------------------------------
# The plan and the body
# ---------------------------------------------------------------------------


def test_the_same_record_again_is_unchanged(tmp_path: Path) -> None:
    matrix = _matrix_of(_library(tmp_path / "lib", "alpha", "beta"))
    baselines = tmp_path / "baselines"
    assert plan_library_baseline(
        matrix, baselines, delta=compare_with_baseline(matrix, None)
    ).changed
    write_library_baseline(matrix, baselines)
    plan = plan_library_baseline(matrix, baselines, delta=compare_with_baseline(matrix, matrix))
    assert not plan.changed and plan.previous == matrix


def test_a_stored_file_that_is_not_a_baseline_is_replaced_and_said_so(tmp_path: Path) -> None:
    matrix = _matrix_of(_library(tmp_path / "lib", "alpha", "beta"))
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    (baselines / "_library.coexistence.json").write_text("not json", encoding="utf-8")
    plan = plan_library_baseline(matrix, baselines, delta=compare_with_baseline(matrix, None))
    assert plan.changed and plan.previous is None
    body = render_library_baseline_pr_body(
        matrix, plan, run_id=7, run_url=None, baselines_dir="examples/live/baselines"
    )
    assert "Replaces: a stored file that is not a valid library baseline" in body


def test_the_body_names_the_run_what_it_replaces_and_what_was_not_re_run(tmp_path: Path) -> None:
    root = _library(tmp_path / "lib", "alpha", "beta")
    stored = _matrix_of(root)
    moved = _matrix_of(
        root,
        [_cell("alpha", "act", {"alpha": 8, NO_ACTIVATION: 4}), _cell("beta", "act", {"beta": 12})],
    )
    baselines = tmp_path / "baselines"
    write_library_baseline(stored, baselines)
    plan = plan_library_baseline(moved, baselines, delta=compare_with_baseline(moved, stored))
    body = render_library_baseline_pr_body(
        moved,
        plan,
        run_id=77,
        run_url="https://example/run/77",
        baselines_dir="examples/live/baselines",
    )
    assert "coexistence run 77" in body and "https://example/run/77" in body
    assert "`examples/live/baselines/_library.coexistence.json`" in body
    assert "Replaces: the stored baseline of 2 skill(s)" in body
    assert "No probe's activation was won by another skill." in body
    assert "`alpha` lost 4 of 12 activations" in body
    assert "was not re-run" in body
    assert "regenerate it on `main`" in body


def test_values_the_run_chose_are_inert_in_the_body(tmp_path: Path) -> None:
    root = tmp_path / "lib"
    _skill(root, "alpha", "@everyone <img src=x onerror=1> | pipes")
    _skill(root, "beta")
    hostile = _matrix_of(
        root,
        [_cell("alpha", "act", {"@everyone <img src=x onerror=1>": 12})],
        target="@everyone <img src=x onerror=1>",
    )
    plan = plan_library_baseline(
        hostile, tmp_path / "none", delta=compare_with_baseline(hostile, None)
    )
    body = render_library_baseline_pr_body(hostile, plan, run_id=1, run_url=None, baselines_dir="b")
    # Every occurrence is inside a code span, where a mention notifies nobody and a tag is text.
    assert body.count("<img") == 2
    for line in body.splitlines():
        if "<img" in line:
            assert re.search(r"`[^`]*<img src=x onerror=1>[^`]*`", line), line
    assert "@everyone" not in re.sub(r"`[^`]*`", "", body)


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


def _invoke(api: FakeGitHub, tmp_path: Path, *args: str, env: Mapping[str, str] | None = None):  # type: ignore[no-untyped-def]
    return runner.invoke(
        app,
        [
            "baseline",
            "library",
            "--repo",
            "owner/repo",
            "--api-root",
            api.url,
            "--skill-root",
            str(tmp_path / "repo" / "examples" / "skills"),
            "--baselines",
            str(tmp_path / "repo" / "examples" / "live" / "baselines"),
            *args,
        ],
        env={"GITHUB_TOKEN": "ghs_fake-token-for-the-workflow-harness", **(env or {})},
    )


def test_the_command_writes_the_baseline_and_the_body(api: FakeGitHub, tmp_path: Path) -> None:
    root = _library(tmp_path / "repo" / "examples" / "skills", "alpha", "beta")
    matrix = _matrix_of(root)
    _publish(api, 77, matrix)
    body = tmp_path / "body.md"
    result = _invoke(api, tmp_path, "--run-id", "77", "--body", str(body), "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["changed"] is True and payload["written"] is True
    assert payload["run_id"] == 77 and payload["status"] == "clean"
    assert "actions/runs/77" in payload["run_url"]
    stored = tmp_path / "repo" / "examples" / "live" / "baselines" / "_library.coexistence.json"
    assert stored.read_text(encoding="utf-8") == render_coexistence_json(matrix)
    assert "coexistence run 77" in body.read_text(encoding="utf-8")
    # The token went to the API, never to the storage host the download redirected to.
    assert api.blob_auth == 0 and api.unauthorised == 0


def test_the_same_record_again_is_not_rewritten(api: FakeGitHub, tmp_path: Path) -> None:
    root = _library(tmp_path / "repo" / "examples" / "skills", "alpha", "beta")
    matrix = _matrix_of(root)
    baselines = tmp_path / "repo" / "examples" / "live" / "baselines"
    path = write_library_baseline(matrix, baselines)
    before = path.stat().st_mtime_ns
    _publish(api, 78, matrix)
    result = _invoke(api, tmp_path, "--run-id", "78", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["changed"] is False and payload["written"] is False
    assert payload["comparable"] is True
    assert path.stat().st_mtime_ns == before


def test_a_matrix_of_a_changed_library_is_refused_not_proposed(
    api: FakeGitHub, tmp_path: Path
) -> None:
    then = _library(tmp_path / "then", "alpha", "beta")
    _publish(api, 79, _matrix_of(then))
    now = tmp_path / "repo" / "examples" / "skills"
    _skill(now, "alpha", "A different description now.")
    _skill(now, "beta")
    result = _invoke(api, tmp_path, "--run-id", "79", "--json")
    assert result.exit_code == 3, result.output
    assert "changed: alpha" in result.output
    assert not (tmp_path / "repo" / "examples" / "live" / "baselines").exists()


def test_a_run_without_the_artifact_is_refused_naming_it(api: FakeGitHub, tmp_path: Path) -> None:
    _library(tmp_path / "repo" / "examples" / "skills", "alpha", "beta")
    result = _invoke(api, tmp_path, "--run-id", "80")
    assert result.exit_code == 3
    assert f"run 80 has no unexpired artifact named '{_ARTIFACT}'" in result.output
    _publish(api, 81, _matrix_of(tmp_path / "repo" / "examples" / "skills"), expired=True)
    assert _invoke(api, tmp_path, "--run-id", "81").exit_code == 3


def test_a_dry_run_decides_but_writes_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    root = _library(tmp_path / "repo" / "examples" / "skills", "alpha", "beta")
    _publish(api, 82, _matrix_of(root))
    result = _invoke(api, tmp_path, "--run-id", "82", "--dry-run", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["changed"] is True and payload["written"] is False
    assert not (tmp_path / "repo" / "examples" / "live" / "baselines").exists()


def test_a_colliding_matrix_is_proposed_and_the_body_says_so(
    api: FakeGitHub, tmp_path: Path
) -> None:
    root = _library(tmp_path / "repo" / "examples" / "skills", "alpha", "beta")
    colliding = _matrix_of(
        root, [_cell("alpha", "act", {"beta": 12}), _cell("beta", "act", {"beta": 12})]
    )
    _publish(api, 83, colliding)
    body = tmp_path / "body.md"
    result = _invoke(api, tmp_path, "--run-id", "83", "--body", str(body), "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "collisions"
    text = body.read_text(encoding="utf-8")
    assert "`alpha`'s `act` probe (activation) was won by `beta` on 12 of 12 runs" in text
    assert "still opens the library's issue" in text


# ---------------------------------------------------------------------------
# The workflow
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _repository(
    tmp_path: Path, baseline: CoexistenceMatrix | None = None
) -> tuple[Path, Path, str]:
    """A repository on ``main`` holding two skills and a bare ``origin``; the working copy, the
    origin and ``main``'s SHA."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    repo = tmp_path / "repo"
    _library(repo / "examples" / "skills", "alpha", "beta")
    baselines = repo / "examples" / "live" / "baselines"
    baselines.mkdir(parents=True)
    if baseline is not None:
        write_library_baseline(baseline, baselines)
    else:
        (baselines / ".keep").write_text("", encoding="utf-8")
    _git(repo.parent, "init", "-q", "-b", "main", str(repo))
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "m")
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")
    return repo, origin, _git(repo, "rev-parse", "HEAD")


def _fake_coexistence(tmp: Path, matrix: CoexistenceMatrix) -> Path:
    """A ``bellwether`` whose ``coexistence`` drops ``matrix`` under ``--out`` and exits 0."""
    source = tmp / "fixture-coexistence.json"
    source.write_text(render_coexistence_json(matrix), encoding="utf-8")
    script = tmp / "fake-bellwether"
    script.write_text(
        "#!/bin/bash\n"
        'out=""\n'
        'while [ $# -gt 0 ]; do if [ "$1" = "--out" ]; then out="$2"; fi; shift; done\n'
        'mkdir -p "$out/coexistence-20261106T052300Z"\n'
        f'cp "{source}" "$out/coexistence-20261106T052300Z/coexistence.json"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _run_job(
    job: str,
    repo: Path,
    tmp: Path,
    api: FakeGitHub,
    event: Event,
    *,
    fake_coexistence: Path | None = None,
) -> WorkflowRunner:
    tmp.mkdir(exist_ok=True)
    wrapper = bellwether_wrapper(tmp, str(Path(sys.executable).parent / "bellwether"), api)
    substitutions = [("uv run bellwether", str(wrapper))]
    if fake_coexistence is not None:
        substitutions.insert(0, ('bw="$(pwd)/.venv/bin/bellwether"', f'bw="{fake_coexistence}"'))
    runner_ = WorkflowRunner(
        _WORKFLOW,
        job,
        repo,
        tmp,
        event=event,
        api=api,
        secrets={"ANTHROPIC_API_KEY": "sk-test"},
        substitutions=substitutions,
        skip=_SKIP,
    )
    runner_.run()
    return runner_


def _upload_artifact(api: FakeGitHub, runner_: WorkflowRunner, run_id: int) -> None:
    """Stand in for ``actions/upload-artifact`` on the "Upload the matrix" step: zip the one
    file the step's ``path`` names, at the archive root, as the run's matrix artifact."""
    assert "Upload the matrix" in runner_.ran()
    step = next(s for s in runner_.steps if s.get("name") == "Upload the matrix")
    path = runner_.interpolate(str(step["with"]["path"]))
    assert path.endswith("/coexistence.json")
    data = (runner_.repo / path).read_bytes()
    _publish(api, run_id, _zip({"coexistence.json": data}))


def _explain(runner_: WorkflowRunner) -> list[tuple[str, int, str]]:
    return [(r.name, r.returncode, r.output[-1500:]) for r in runner_.results if r.ran]


def _clone(origin: Path, into: Path) -> Path:
    subprocess.run(["git", "clone", "-q", "-b", "main", str(origin), str(into)], check=True)
    return into


@pytest.fixture
def _passwordless_sudo() -> None:
    import shutil

    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if shutil.which("sudo") is None or probe.returncode != 0:
        pytest.skip("the coexistence step needs passwordless sudo")


_DISPATCH = {"targets": "haiku", "force": "false", "set_baseline": "true", "baseline_run_id": ""}


@pytest.mark.usefixtures("_passwordless_sudo")
def test_a_dispatch_with_set_baseline_proposes_the_run_matrix_from_a_bot_branch(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, origin, main = _repository(tmp_path)
    matrix = _matrix_of(repo / "examples" / "skills")
    event = Event(name="workflow_dispatch", action="", inputs=_DISPATCH, run_id=91)

    first = _run_job(
        "coexistence",
        repo,
        tmp_path,
        api,
        event,
        fake_coexistence=_fake_coexistence(tmp_path, matrix),
    )
    assert not first.failed, _explain(first)
    _upload_artifact(api, first, 91)

    # The baseline job runs on its own runner: a fresh checkout, and the matrix comes from the
    # artifact, not from the first job's working copy.
    second = _run_job(
        "library-baseline-pr",
        _clone(origin, tmp_path / "runner2"),
        tmp_path / "second",
        api,
        Event(
            name="workflow_dispatch",
            action="",
            inputs=_DISPATCH,
            run_id=91,
            needs={"coexistence": "success"},
        ),
    )
    assert second.job_runs()
    assert not second.failed, _explain(second)
    assert "Open the library baseline pull request" in second.ran()

    # The branch on origin holds exactly the library file, and main is untouched.
    branch = "bellwether/library-baseline-run-91"
    assert _git(origin, "rev-parse", "refs/heads/main") == main
    files = _git(origin, "diff", "--name-only", f"{main}..refs/heads/{branch}").splitlines()
    assert files == ["examples/live/baselines/_library.coexistence.json"]
    stored = _git(
        origin, "show", f"refs/heads/{branch}:examples/live/baselines/_library.coexistence.json"
    )
    assert stored + "\n" == render_coexistence_json(matrix)
    assert _git(origin, "log", "-1", "--format=%an %s", f"refs/heads/{branch}") == (
        "github-actions[bot] chore: update library baseline (run 91)"
    )
    [pull] = api.pulls
    assert pull["head"] == branch and pull["base"] == "main"
    assert pull["title"] == "chore: update library baseline (run 91)"
    assert "coexistence run 91" in pull["body"] and "actions/runs/91" in pull["body"]
    assert "Replaces: no stored baseline" in pull["body"]
    assert api.blob_auth == 0 and api.unauthorised == 0
    assert "Bellwether library baseline update" in second.summary.read_text(encoding="utf-8")


@pytest.mark.usefixtures("_passwordless_sudo")
def test_the_matrix_is_uploaded_after_a_colliding_run_too(api: FakeGitHub, tmp_path: Path) -> None:
    """The report step exits 2 on collisions and the matrix job fails; the matrix is still
    uploaded, because a colliding matrix is the library's state and may be the one proposed."""
    repo, _origin, _main = _repository(tmp_path)
    colliding = _matrix_of(
        repo / "examples" / "skills",
        [_cell("alpha", "act", {"beta": 12}), _cell("beta", "act", {"beta": 12})],
    )
    event = Event(name="workflow_dispatch", action="", inputs=_DISPATCH, run_id=92)
    first = _run_job(
        "coexistence",
        repo,
        tmp_path,
        api,
        event,
        fake_coexistence=_fake_coexistence(tmp_path, colliding),
    )
    assert first.failed and first.result("Read the matrix").returncode == 2, _explain(first)
    _upload_artifact(api, first, 92)
    assert read_matrix_artifact(api.blobs[7092]) == colliding


def test_an_earlier_run_is_proposed_without_running_the_matrix(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, origin, main = _repository(tmp_path)
    _publish(api, 70, _matrix_of(repo / "examples" / "skills"))
    inputs = {**_DISPATCH, "baseline_run_id": "70"}
    event = Event(name="workflow_dispatch", action="", inputs=inputs, run_id=95)
    # The matrix job is skipped: nothing is spent for a matrix that already exists.
    assert not WorkflowRunner(_WORKFLOW, "coexistence", repo, tmp_path, event=event).job_runs()
    second = _run_job(
        "library-baseline-pr",
        _clone(origin, tmp_path / "runner2"),
        tmp_path / "second",
        api,
        Event(
            name="workflow_dispatch",
            action="",
            inputs=inputs,
            run_id=95,
            needs={"coexistence": "skipped"},
        ),
    )
    assert second.job_runs()
    assert not second.failed, _explain(second)
    assert _git(origin, "rev-parse", "refs/heads/main") == main
    assert "bellwether/library-baseline-run-70" in _git(origin, "branch", "--list")
    [pull] = api.pulls
    assert pull["head"] == "bellwether/library-baseline-run-70"
    assert "coexistence run 70" in pull["body"]


def test_a_colliding_run_that_failed_the_matrix_job_is_still_proposed(
    api: FakeGitHub, tmp_path: Path
) -> None:
    """The matrix job exits 2 on collisions (its issue opens); the baseline job runs after a
    failed matrix job too, and the pull request names the collision."""
    repo, origin, _main = _repository(tmp_path)
    colliding = _matrix_of(
        repo / "examples" / "skills",
        [_cell("alpha", "act", {"beta": 12}), _cell("beta", "act", {"beta": 12})],
    )
    _publish(api, 96, colliding)
    second = _run_job(
        "library-baseline-pr",
        _clone(origin, tmp_path / "runner2"),
        tmp_path / "second",
        api,
        Event(
            name="workflow_dispatch",
            action="",
            inputs=_DISPATCH,
            run_id=96,
            needs={"coexistence": "failure"},
        ),
    )
    assert second.job_runs()
    assert not second.failed, _explain(second)
    [pull] = api.pulls
    assert "was won by `beta` on 12 of 12 runs" in pull["body"]


def test_a_stored_baseline_that_already_matches_proposes_nothing(
    api: FakeGitHub, tmp_path: Path
) -> None:
    matrix_dir = _library(tmp_path / "lib", "alpha", "beta")
    matrix = _matrix_of(matrix_dir)
    repo, origin, _main = _repository(tmp_path, baseline=matrix)
    assert _matrix_of(repo / "examples" / "skills").library_key == matrix.library_key
    _publish(api, 97, matrix)
    second = _run_job(
        "library-baseline-pr",
        _clone(origin, tmp_path / "runner2"),
        tmp_path / "second",
        api,
        Event(
            name="workflow_dispatch",
            action="",
            inputs=_DISPATCH,
            run_id=97,
            needs={"coexistence": "success"},
        ),
    )
    assert not second.failed, _explain(second)
    assert second.outputs["update"]["changed"] == "false"
    assert "Push the library baseline branch" not in second.ran()
    assert api.pulls == [] and _git(origin, "branch", "--list").split() == ["main"]


def test_a_matrix_of_a_library_that_has_since_changed_fails_and_pushes_nothing(
    api: FakeGitHub, tmp_path: Path
) -> None:
    then = _library(tmp_path / "then", "alpha", "beta", "gamma")
    _publish(api, 60, _matrix_of(then))
    _repo, origin, _main = _repository(tmp_path)
    inputs = {**_DISPATCH, "baseline_run_id": "60"}
    second = _run_job(
        "library-baseline-pr",
        _clone(origin, tmp_path / "runner2"),
        tmp_path / "second",
        api,
        Event(
            name="workflow_dispatch",
            action="",
            inputs=inputs,
            run_id=98,
            needs={"coexistence": "skipped"},
        ),
    )
    assert second.failed
    result = second.result("Write the library baseline")
    assert result.returncode == 3 and "removed: gamma" in result.output, _explain(second)
    assert api.pulls == [] and _git(origin, "branch", "--list").split() == ["main"]


def test_a_repository_that_forbids_actions_pull_requests_fails_naming_the_setting(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo, origin, _main = _repository(tmp_path)
    _publish(api, 99, _matrix_of(repo / "examples" / "skills"))
    api.create_pull_status = 403
    second = _run_job(
        "library-baseline-pr",
        _clone(origin, tmp_path / "runner2"),
        tmp_path / "second",
        api,
        Event(
            name="workflow_dispatch",
            action="",
            inputs=_DISPATCH,
            run_id=99,
            needs={"coexistence": "success"},
        ),
    )
    assert second.failed
    result = second.result("Open the library baseline pull request")
    assert result.returncode == 3 and "Allow GitHub Actions to create" in result.output
    # The proposal is not lost: the branch was pushed and can be opened by hand.
    assert "bellwether/library-baseline-run-99" in _git(origin, "branch", "--list")


@pytest.mark.parametrize(
    ("event", "runs"),
    [
        (
            Event(
                name="schedule",
                action="",
                vars={"BELLWETHER_COEXISTENCE": "true"},
                needs={"coexistence": "success"},
            ),
            False,
        ),
        (
            Event(
                name="workflow_dispatch",
                action="",
                inputs={**_DISPATCH, "set_baseline": "false"},
                needs={"coexistence": "success"},
            ),
            False,
        ),
        (
            Event(
                name="workflow_dispatch",
                action="",
                inputs=_DISPATCH,
                needs={"coexistence": "cancelled"},
            ),
            False,
        ),
        (
            Event(
                name="workflow_dispatch",
                action="",
                inputs=_DISPATCH,
                needs={"coexistence": "failure"},
            ),
            True,
        ),
        (
            Event(
                name="workflow_dispatch",
                action="",
                inputs=_DISPATCH,
                needs={"coexistence": "skipped"},
            ),
            True,
        ),
    ],
)
def test_the_baseline_job_runs_only_on_a_dispatch_that_asked_for_it(
    tmp_path: Path, event: Event, runs: bool
) -> None:
    runner_ = WorkflowRunner(_WORKFLOW, "library-baseline-pr", tmp_path, tmp_path, event=event)
    assert runner_.job_runs() is runs


def test_a_dispatch_naming_an_earlier_run_does_not_run_the_matrix(tmp_path: Path) -> None:
    spends = Event(name="workflow_dispatch", action="", inputs=_DISPATCH)
    assert WorkflowRunner(_WORKFLOW, "coexistence", tmp_path, tmp_path, event=spends).job_runs()
    reuses = Event(
        name="workflow_dispatch", action="", inputs={**_DISPATCH, "baseline_run_id": "70"}
    )
    assert not WorkflowRunner(_WORKFLOW, "coexistence", tmp_path, tmp_path, event=reuses).job_runs()
    # The variable alone still fires only the schedule, not a dispatch naming a run.
    both = Event(
        name="workflow_dispatch",
        action="",
        inputs={**_DISPATCH, "baseline_run_id": "70"},
        vars={"BELLWETHER_COEXISTENCE": "true"},
    )
    assert not WorkflowRunner(_WORKFLOW, "coexistence", tmp_path, tmp_path, event=both).job_runs()


def test_the_baseline_job_is_shaped_as_documented() -> None:
    document = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    inputs = document[True]["workflow_dispatch"]["inputs"]
    assert (
        inputs["set_baseline"]["type"] == "boolean" and inputs["set_baseline"]["default"] is False
    )
    assert inputs["baseline_run_id"]["default"] == ""
    jobs = document["jobs"]
    # The job that runs skill content never holds a token that can push; the one that can push
    # never runs a skill.
    assert jobs["coexistence"]["permissions"] == {"contents": "read", "issues": "write"}
    job = jobs["library-baseline-pr"]
    assert job["needs"] == "coexistence"
    assert job["permissions"] == {"contents": "write", "pull-requests": "write", "actions": "read"}
    scripts = [str(s.get("run", "")) for s in job["steps"]]
    assert not any(re.search(r"\bsudo\b", script) for script in scripts)
    assert not any(re.search(r'(bellwether|\$\{bw\}")\s+coexistence\b', s) for s in scripts)
    steps = {s.get("name"): s for s in job["steps"]}
    for step in job["steps"]:
        # Inputs reach scripts through env, never interpolated into the script body.
        assert "inputs." not in str(step.get("run", ""))
        assert "github.token" not in str(step.get("run", ""))
    write = str(steps["Write the library baseline"]["run"])
    assert (
        "baseline library" in write
        and "--skill-root" in write
        and "git status --porcelain" in write
    )
    push = str(steps["Push the library baseline branch"]["run"])
    assert "'credential.helper=!f() {" in push and "password=${GITHUB_TOKEN}" in push
    assert "refs/heads/${branch}" in push and "push origin main" not in push
    assert "open-pr" in str(steps["Open the library baseline pull request"]["run"])
    upload = next(s for s in jobs["coexistence"]["steps"] if s.get("name") == "Upload the matrix")
    assert upload["with"]["name"] == _ARTIFACT
    assert upload["with"]["path"].endswith("/coexistence.json")
    assert upload["if"].startswith("always()")
