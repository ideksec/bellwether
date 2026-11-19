"""BW-29: the supply-chain pin lint also covers container/service images and ``docker run``.

``tools/pin_lint.py`` already pinned ``uses:`` actions, ``*_IMAGE`` env vars, ``docker pull``,
and Dockerfile ``FROM``. A mutable image can also enter a workflow through a job/step
``container:`` (inline or its ``image:`` mapping), a ``services:`` entry's ``image:``, or a
``docker run`` in a step — those are covered here. The lint flags an unpinned *tagged* image in
each, while never mistaking a job whose id is ``container`` (a mapping key with no inline value)
or a ``-p host:port`` mapping for an image, and never flagging a ``${{ var }}`` reference.

``pin_lint`` lives in ``tools/`` outside the package; ``conftest.py`` puts that directory on
``sys.path`` (the same way ``test_language_lint.py`` imports its tool).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import pin_lint

REPO_ROOT = Path(__file__).resolve().parent.parent


def _check(tmp_path: Path, body: str) -> list[str]:
    workflow = tmp_path / "wf.yml"
    workflow.write_text(body, encoding="utf-8")
    return pin_lint.check_workflow(workflow)


def test_a_container_with_an_inline_tagged_image_is_flagged(tmp_path: Path) -> None:
    """The BW-29 anchor case: ``container: node:18`` is a mutable tag and must be flagged."""
    problems = _check(tmp_path, "jobs:\n  build:\n    container: node:18\n")
    assert len(problems) == 1
    assert "node:18" in problems[0]


def test_a_container_mapping_image_is_flagged(tmp_path: Path) -> None:
    problems = _check(tmp_path, "jobs:\n  build:\n    container:\n      image: node:18\n")
    assert len(problems) == 1
    assert "node:18" in problems[0]


def test_a_services_image_is_flagged(tmp_path: Path) -> None:
    body = "jobs:\n  build:\n    services:\n      db:\n        image: postgres:16\n"
    problems = _check(tmp_path, body)
    assert len(problems) == 1
    assert "postgres:16" in problems[0]


def test_a_docker_run_image_is_flagged_but_a_port_mapping_is_not(tmp_path: Path) -> None:
    """The image is resolved past the flags: ``-p 8080:80`` is a value-taking flag, so its
    ``host:port`` argument is neither scanned as nor mistaken for the image."""
    body = "jobs:\n  build:\n    steps:\n      - run: docker run --rm -p 8080:80 redis:7 serve\n"
    problems = _check(tmp_path, body)
    assert len(problems) == 1
    assert "redis:7" in problems[0]
    assert "8080" not in problems[0]


def test_a_digest_pinned_container_is_accepted(tmp_path: Path) -> None:
    body = "jobs:\n  build:\n    container: node:18@sha256:" + "a" * 64 + "\n"
    assert _check(tmp_path, body) == []


def test_a_job_named_container_is_not_mistaken_for_an_image(tmp_path: Path) -> None:
    """A job whose id is ``container`` is a mapping key with no inline value; it must not be
    read as ``container: <image>``. The project's own ci.yml relies on this."""
    body = "jobs:\n  container:\n    runs-on: ubuntu-26.04\n"
    assert _check(tmp_path, body) == []


def test_a_var_image_is_not_flagged(tmp_path: Path) -> None:
    body = "jobs:\n  build:\n    container: ${{ matrix.image }}\n"
    assert _check(tmp_path, body) == []


def test_an_untagged_bare_image_is_left_alone(tmp_path: Path) -> None:
    """Only a value that carries a tag is flagged, so a non-image token can never trip the
    scan; a bare ``node`` (no tag) is out of scope here as the task specifies."""
    assert _check(tmp_path, "jobs:\n  build:\n    container: node\n") == []


def test_the_repo_workflows_still_pass(tmp_path: Path) -> None:
    """No false positive on the project's own workflows — in particular ci.yml's ``container:``
    *job* and the digest-pinned ``BELLWETHER_TEST_IMAGE``."""
    for name in ("bellwether.yml", "ci.yml"):
        assert pin_lint.check_workflow(REPO_ROOT / ".github" / "workflows" / name) == []


# --- Rule 5: every job names its runner image by release ---------------------------------------
#
# `ubuntu-latest` moved to a new OS release under a green build and hid sixteen container tests
# for twelve merges (spec-notes, "the container job's silent skips"). The rule is an allowlist
# of one form, judged on what the YAML means, so the refusals below are a corpus of *spellings*
# of "not one named release" — none of which the rule lists.


def _runners(tmp_path: Path, body: str) -> list[str]:
    workflow = tmp_path / "wf.yml"
    workflow.write_text(body, encoding="utf-8")
    return pin_lint.check_runners(workflow)


def _job(runs_on: str) -> str:
    return f"on: push\njobs:\n  build:\n    runs-on: {runs_on}\n    steps: []\n"


@pytest.mark.parametrize(
    "runs_on",
    [
        "ubuntu-26.04",
        "ubuntu-24.04",
        '"ubuntu-26.04"',
        "ubuntu-24.04-arm",
        "macos-15",
        "windows-2025",
    ],
)
def test_a_runner_named_by_its_release_is_accepted(tmp_path: Path, runs_on: str) -> None:
    assert _runners(tmp_path, _job(runs_on)) == []


@pytest.mark.parametrize(
    ("runs_on", "says"),
    [
        ("ubuntu-latest", "mutable label"),
        ("'ubuntu-latest'", "mutable label"),
        ("macos-latest", "mutable label"),
        ("windows-latest", "mutable label"),
        ("ubuntu-latest # the default", "mutable label"),
        ("${{ matrix.os }}", "is an expression"),
        ("${{ inputs.runner || 'ubuntu-26.04' }}", "is an expression"),
        ("ubuntu-${{ matrix.version }}", "is an expression"),
        ("[ubuntu-latest]", "a list of labels"),
        ("[ubuntu-26.04]", "a list of labels"),
        ("[self-hosted, linux]", "a list of labels"),
        ("\n      - ubuntu-latest", "a list of labels"),
        ("\n      group: big-runners\n      labels: ubuntu-latest", "a runner group or mapping"),
        ("self-hosted", "not a hosted-runner label that names its OS release"),
        ("ubuntu", "not a hosted-runner label that names its OS release"),
        ("ubuntu-slim", "not a hosted-runner label that names its OS release"),
        ("Ubuntu-26.04", "not a hosted-runner label that names its OS release"),
        ("ubuntu-26.04 ubuntu-latest", "mutable label"),
        ("ubuntu-latest ubuntu-26.04", "not a hosted-runner label that names its OS release"),
        # A block scalar keeps its newline: not the label it looks like, in either direction.
        ("|\n      ubuntu-latest", "not a hosted-runner label that names its OS release"),
        ("|\n      ubuntu-26.04", "not a hosted-runner label that names its OS release"),
        ("26.04", "a float"),
        ("null", "a NoneType"),
    ],
)
def test_anything_but_one_named_release_is_refused(tmp_path: Path, runs_on: str, says: str) -> None:
    problems = _runners(tmp_path, _job(runs_on))
    assert len(problems) == 1, problems
    assert "job 'build'" in problems[0] and says in problems[0]
    assert ":4: " in problems[0] or ":5: " in problems[0]  # on the runs-on, or its first item


def test_a_runner_that_arrives_through_an_alias_or_a_merge_key_is_judged(tmp_path: Path) -> None:
    """The line says nothing about the runner; the document does. A line-by-line scan for
    ``runs-on: …-latest`` would pass both of these."""
    alias = (
        "x-runner: &runner ubuntu-latest\njobs:\n  a:\n    runs-on: *runner\n"
        "  b:\n    runs-on: ubuntu-26.04\n"
    )
    assert ["job 'a'" in p and "mutable label" in p for p in _runners(tmp_path, alias)] == [True]
    merged = (
        "x-defaults: &defaults\n  runs-on: ubuntu-latest\n  timeout-minutes: 5\n"
        "jobs:\n  a:\n    <<: *defaults\n    steps: []\n"
    )
    [problem] = _runners(tmp_path, merged)
    assert "job 'a'" in problem and "mutable label" in problem
    assert f"{tmp_path / 'wf.yml'}:5: " in problem  # no runs-on line of its own: the job's key


def test_every_job_is_judged_and_each_problem_names_its_line(tmp_path: Path) -> None:
    body = (
        "jobs:\n"
        "  good:\n    runs-on: ubuntu-26.04\n"
        "  bad:\n    timeout-minutes: 5\n    runs-on: ubuntu-latest\n"
        "  calls:\n    uses: ./.github/workflows/other.yml\n"
        "  worse:\n    runs-on: ${{ matrix.os }}\n"
    )
    problems = _runners(tmp_path, body)
    path = tmp_path / "wf.yml"
    assert [p.split(": job ")[0] for p in problems] == [f"{path}:6", f"{path}:10"]
    assert ["'bad'" in problems[0], "'worse'" in problems[1]] == [True, True]


def test_a_workflow_that_does_not_parse_is_refused_not_passed(tmp_path: Path) -> None:
    """A file the lint cannot read is a file whose runners it has not judged."""
    [problem] = _runners(tmp_path, "jobs:\n  a:\n    runs-on: [ubuntu-latest\n")
    assert "not parseable as YAML" in problem and "cannot be judged" in problem


def test_the_lint_fails_the_build_on_a_mutable_runner(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """At the entry point CI runs, not at the helper: a rule ``main`` never calls is a rule
    that is printed in the docstring and enforced nowhere."""
    (tmp_path / "wf.yml").write_text(_job("ubuntu-latest"), encoding="utf-8")
    assert pin_lint.main(["pin_lint", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "runs-on 'ubuntu-latest' is a mutable label" in err and "1 unpinned" in err
    (tmp_path / "wf.yml").write_text(_job("ubuntu-26.04"), encoding="utf-8")
    assert pin_lint.main(["pin_lint", str(tmp_path)]) == 0
    assert "runner is pinned" in capsys.readouterr().out


def _project_runners() -> dict[str, str]:
    import yaml

    runners: dict[str, str] = {}
    for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        for job_id, job in yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"].items():
            runners[f"{path.name}:{job_id}"] = job["runs-on"]
    return runners


def test_every_project_job_runs_on_one_named_release() -> None:
    """Two properties. Every job is pinned (the lint, over the real files). And every job is
    pinned to the *same* image: CI's ``container`` job stands in for the workflows that spend
    money — its sudo probe asks, for free, the question a paid run would otherwise be the first
    to ask — and that only means something while they share a runner. A bump is one change to
    all of them, never a drift of one."""
    runners = _project_runners()
    assert len(runners) == 10, sorted(runners)
    for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        assert pin_lint.check_runners(path) == [], path.name
    assert set(runners.values()) == {runners["ci.yml:container"]}, runners
    assert runners["ci.yml:container"] == "ubuntu-26.04"


# --- Rule 4: every install comes from a lock that records its bytes ---------------------------


@pytest.mark.parametrize(
    "command",
    [
        "pip install mitmproxy==12.2.3",
        "pip install --no-cache-dir --constraint /app/constraints.txt /app",
        "pip3 --no-cache-dir install -r requirements.txt",
        "python -m pip install requests",
        "python3.12 -m pip install requests",
        "uv pip install requests",
        "/usr/local/bin/pip install requests",
        "sudo -E pip install requests",
        "PIP_INDEX_URL=x pip install requests",
        "cd /app && pip install requests",
        'RUN ["pip", "install", "requests"]',
        "npm install -g @anthropic-ai/claude-code@2.1.257",
        "npm i left-pad",
        "npm add left-pad",
        "npm isntall left-pad",
        "npm --prefix x install",
        "npm update",
        "npm exec cowsay",
        "npx cowsay",
        "yarn add left-pad",
        "pnpm add left-pad",
        "run: npm install",
        "- run: pip install requests",
    ],
)
def test_an_unlocked_install_is_flagged(command: str) -> None:
    assert pin_lint.install_problems(command), command


@pytest.mark.parametrize(
    "command",
    [
        "pip install --no-cache-dir --require-hashes --only-binary :all: -r /app/requirements.txt",
        "pip install --no-cache-dir --no-index --no-deps --no-build-isolation /app && pip check",
        "npm ci --prefix sandbox/claude-code/cli --omit=dev",
        "npm cache clean --force",
        "npm --version",
        "uv sync --frozen",
        "uv run pytest -m 'not docker'",
        "uv run pip-audit",
        "echo pip install is documented here",
        "- name: Install the Claude Code CLI",
        "apt-get install -y git",
    ],
)
def test_a_locked_or_non_install_command_passes(command: str) -> None:
    assert pin_lint.install_problems(command) == [], command


def test_a_continued_dockerfile_run_is_judged_as_one_command(tmp_path: Path) -> None:
    """A flag on the next line still belongs to the command, and the line number is the RUN's."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM x@sha256:" + "0" * 64 + "\n"
        "RUN pip install \\\n    --require-hashes -r r.txt\n"
        "# pip install requests  (a comment is not a command)\n"
        "RUN cd /opt \\\n    && npm install -g thing\n",
        encoding="utf-8",
    )
    problems = pin_lint.check_installs(dockerfile)
    assert len(problems) == 1
    assert ":5:" in problems[0] and "npm install" in problems[0]


def test_every_repo_install_is_locked() -> None:
    """The project's own Dockerfiles, workflows and scripts pass rule 4."""
    inputs = [
        *sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")),
        *sorted(REPO_ROOT.glob("s*/**/Dockerfile")),
        *sorted((REPO_ROOT / ".claude").rglob("*.sh")),
    ]
    assert len(inputs) >= 7  # four workflows, three Dockerfiles, the session hook
    assert [problem for path in inputs for problem in pin_lint.check_installs(path)] == []
