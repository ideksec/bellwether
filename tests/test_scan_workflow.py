"""The Gate 0 workflow (``.github/workflows/bellwether-scan.yml``), read and *run*.

Two layers. The structural tests read the YAML and pin what makes the workflow trustworthy: no
secret, no ``pull_request_target``, uploads that survive a failing scan, a fork guard on the
Security-tab upload, the gate decided *after* the upload, a pinned scanner image.

The docker-marked tests go further, because a workflow that parses and lints is not a workflow
that works — every defect this project's CI has had looked clean on the page. They lift each
step's ``run:`` script out of the YAML, evaluate its ``if:`` against the outputs the previous steps
wrote, and execute it with bash against a real git repository: the real Gitleaks image (the
digest the workflow pins), the real ``changed-skills`` and ``scan``. Only two substitutions are
made, both stated: ``uv run bellwether`` becomes this environment's ``bellwether`` (the venv is
already built), and ``uses:`` steps are evaluated for whether they would run, not run.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.test_sarif import assert_valid_sarif
from tests.workflow_harness import Event, FakeGitHub, WorkflowRunner, bellwether_wrapper, git_repo

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "bellwether-scan.yml"
_FIXTURES = _ROOT / "tests" / "fixtures" / "sarif"


def _workflow() -> dict[str, Any]:
    document = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _steps() -> list[dict[str, Any]]:
    return list(_workflow()["jobs"]["scan"]["steps"])


def _step(name: str) -> dict[str, Any]:
    return next(step for step in _steps() if step.get("name") == name)


def _triggers() -> dict[str, Any]:
    # PyYAML reads the bare key `on` as the boolean True.
    document = _workflow()
    return document.get("on") or document[True]  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_it_runs_on_every_pull_request_and_on_main_without_pull_request_target() -> None:
    triggers = _triggers()
    assert "pull_request" in triggers and triggers["pull_request"] in (None, {})
    assert triggers["push"] == {"branches": ["main"]}
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request_target" not in text.split("\non:")[1]


def test_it_uses_no_secret_and_writes_only_security_events_and_its_comment() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text
    assert _workflow()["permissions"] == {"contents": "read"}
    assert _workflow()["jobs"]["scan"]["permissions"] == {
        "contents": "read",
        "security-events": "write",
        "actions": "read",
        "pull-requests": "write",
    }
    checkout = _steps()[0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["persist-credentials"] is False


def test_the_uploads_survive_a_failing_scan_and_the_gate_comes_after_them() -> None:
    names = [step.get("name") for step in _steps()]
    assert names.index("Scan") < names.index("Upload to code scanning")
    assert names.index("Upload to code scanning") < names.index("Static gate")
    assert names.index("Upload the scan") < names.index("Static gate")
    assert names.index("Comment on the pull request") < names.index("Static gate")
    for upload in ("Upload to code scanning", "Upload the scan", "Comment on the pull request"):
        assert _step(upload)["if"].strip().startswith("always()")
    assert _step("Upload the scan")["with"]["if-no-files-found"] == "error"


def test_the_security_tab_upload_is_skipped_for_a_fork() -> None:
    condition = " ".join(_step("Upload to code scanning")["if"].split())
    assert "github.event.pull_request.head.repo.full_name == github.repository" in condition
    assert "github.event_name != 'pull_request'" in condition
    # One category, set in the SARIF (`automationDetails`), never overridden here: the action's
    # `category` input would re-key the run.
    assert "category" not in _step("Upload to code scanning")["with"]
    comment = " ".join(_step("Comment on the pull request")["if"].split())
    assert "github.event.pull_request.head.repo.full_name == github.repository" in comment
    assert "github.event_name == 'pull_request'" in comment


def test_the_scanner_image_is_pinned_by_digest_to_the_recorded_version() -> None:
    image = _workflow()["env"]["GITLEAKS_IMAGE"]
    assert re.fullmatch(r"ghcr\.io/gitleaks/gitleaks:v8\.24\.3@sha256:[0-9a-f]{64}", image)
    # The recorded fixtures were produced by this exact digest.
    digest = image.split("@sha256:")[1]
    assert digest[:8] in (_FIXTURES / "README.md").read_text(encoding="utf-8")


def test_the_scanner_runs_offline_from_a_same_path_read_only_mount() -> None:
    script = _step("Gitleaks")["run"]
    assert "--network none" in script
    assert '-v "${GITHUB_WORKSPACE}:${GITHUB_WORKSPACE}:ro" -w "${GITHUB_WORKSPACE}"' in script
    assert "--redact" in script and "--exit-code 0" in script
    # What attribution actually rests on (measured: a foreign mount *and* an absolute path is the
    # shape that loses every result): the scan root is relative, from the repository root.
    assert '"${GITLEAKS_IMAGE}" dir "${root}"' in script
    roots = _workflow()["env"]["BELLWETHER_SKILL_ROOTS"].split()
    assert roots and not any(root.startswith("/") for root in roots)


def test_the_scan_is_scoped_to_the_real_skill_roots_and_judged_by_the_policy() -> None:
    env = _workflow()["env"]
    assert env["BELLWETHER_SKILL_ROOTS"] == "examples/skills"
    select = _step("Select the skills")["run"]
    assert "changed-skills -z" in select and "--under" in select and "set -euo pipefail" in select
    scan = _step("Scan")["run"]
    assert '--policy "${BELLWETHER_POLICY}"' in scan and "--skills-from" in scan
    # The policy that judges the scan floors the delegated scanner, or its leak reads `medium`.
    from bellwether.config import load_policy

    policy = load_policy(_ROOT / env["BELLWETHER_POLICY"])
    for name in ("low", "medium", "high"):
        assert policy.profile(name).gates.static.scanner_min_severity == {"gitleaks": "high"}


def test_the_live_workflows_evaluate_only_skills_under_the_real_roots() -> None:
    """The paid workflows used to hand every changed skill-shaped directory to `run` — the
    hostile test fixtures under tests/ included."""
    for name in ("bellwether.yml", "bellwether-claude-code.yml"):
        text = (_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        assert 'changed-skills -z --under "${BELLWETHER_SKILL_ROOT}"' in text, name
        assert "BELLWETHER_SKILL_ROOT: examples/skills" in text, name


# ---------------------------------------------------------------------------
# Running it (tests/workflow_harness.py)
# ---------------------------------------------------------------------------

_IMAGE = _workflow()["env"]["GITLEAKS_IMAGE"]
#: A GitHub-token-shaped string, assembled at run time so no secret-shaped literal is committed.
_FAKE_TOKEN = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5"
_SETUP = (
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "Install uv",
    "Install Bellwether",
)


@pytest.fixture(scope="module")
def gitleaks_image() -> str:
    if shutil.which("docker") is None:
        pytest.skip("no docker CLI")
    pulled = subprocess.run(
        ["docker", "pull", "-q", _IMAGE], capture_output=True, text=True, check=False
    )
    if pulled.returncode != 0:
        pytest.skip(f"cannot pull the pinned Gitleaks image: {pulled.stderr.strip()[:200]}")
    return _IMAGE


@pytest.fixture
def api() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    yield fake
    fake.close()


def _repository(tmp_path: Path, *, leak: bool) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(_ROOT / "examples" / "skills" / "workspace-stats", repo / "examples/skills/ws")
    shutil.copytree(_ROOT / "tests" / "corpus-static" / "fetch-and-exec", repo / "tests/fx")
    shutil.copy(_ROOT / "examples" / "live" / "policy.yaml", repo / "examples/live-policy.yaml")
    if leak:
        _leak(repo)
    git_repo(repo)
    return repo


def _leak(repo: Path) -> None:
    skill = repo / "examples" / "skills" / "leaky"
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text(
        "---\nname: leaky\ndescription: Publishes the release notes to the team wiki.\n---\n"
        f"\nAuthenticate with {_FAKE_TOKEN} when you post.\n",
        encoding="utf-8",
    )
    # A secret in the skill's own test fixture is machinery, not the skill (§15).
    fixtures = skill / "evals" / "fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    (fixtures / "token.txt").write_text(f"{_FAKE_TOKEN}\n", encoding="utf-8")


def _run(repo: Path, tmp: Path, api: FakeGitHub, *, event: Event) -> WorkflowRunner:
    bellwether = Path(sys.executable).parent / "bellwether"
    wrapper = bellwether_wrapper(tmp, str(bellwether), api)
    runner = WorkflowRunner(
        _WORKFLOW,
        "scan",
        repo,
        tmp,
        event=event,
        api=api,
        substitutions=[("uv run bellwether", str(wrapper))],
        skip=_SETUP,
        env={"BELLWETHER_POLICY": "examples/live-policy.yaml"},
    )
    runner.run()
    return runner


@pytest.mark.docker
def test_a_clean_repository_passes_and_scans_only_the_real_roots(
    gitleaks_image: str, api: FakeGitHub, tmp_path: Path
) -> None:
    repo = _repository(tmp_path, leak=False)
    runner = _run(repo, tmp_path, api, event=Event())
    assert not runner.failed, [r for r in runner.results if r.returncode]
    out = repo / ".bellwether-static"
    # tests/fx is a hostile fixture (curl | sh); it is not under the roots and is never scanned.
    assert (out / "skills.txt").read_text("utf-8").splitlines() == ["examples/skills/ws"]
    assert runner.outputs["scan"]["status"] == "0"
    assert runner.ran()[-1] == "Static gate"
    assert {"Upload to code scanning", "Upload the scan", "Comment on the pull request"} <= set(
        runner.ran()
    )
    # Clean, and never red before: `--update-only` finds no comment and posts none.
    assert api.comments == []
    assert api.unauthorised == 0
    document = assert_valid_sarif((out / "bellwether-static.sarif").read_text("utf-8"))
    assert len(document["runs"]) == 1
    assert document["runs"][0]["automationDetails"] == {"id": "bellwether-static/"}
    summary = runner.summary.read_text("utf-8")
    assert summary.startswith("<!-- bellwether-static -->")
    assert "nothing above policy" in summary and "`gitleaks`" in summary


@pytest.mark.docker
@pytest.mark.parametrize("fork", [False, True])
def test_a_leaked_token_fails_the_gate_after_the_uploads_and_the_comment(
    gitleaks_image: str, api: FakeGitHub, tmp_path: Path, fork: bool
) -> None:
    repo = _repository(tmp_path, leak=True)
    runner = _run(repo, tmp_path, api, event=Event(fork=fork))
    # The scan itself completes (exit 2 is a verdict, not a crash); the gate step fails last.
    assert runner.outputs["scan"]["status"] == "2"
    failed = [r for r in runner.results if r.ran and r.returncode]
    assert [(r.name, r.returncode) for r in failed] == [("Static gate", 2)]
    assert ("Upload to code scanning" in runner.ran()) is (not fork)
    assert ("Comment on the pull request" in runner.ran()) is (not fork)
    assert "Upload the scan" in runner.ran()

    if fork:
        assert api.comments == []
    else:
        (comment,) = api.comments
        assert comment["body"].startswith("<!-- bellwether-static -->")
        assert "finding(s) above policy" in comment["body"]
        assert _FAKE_TOKEN not in comment["body"]

    out = repo / ".bellwether-static"
    document = assert_valid_sarif((out / "bellwether-static.sarif").read_text("utf-8"))
    results = document["runs"][0]["results"]
    gitleaks = [r for r in results if r["ruleId"] == "gitleaks:github-pat"]
    # Attributed to the skill's SKILL.md (a relative scan root from the repository root),
    # floored to high → `error`; the fixture under evals/ is machinery and is not attributed.
    assert [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in gitleaks] == [
        "examples/skills/leaky/SKILL.md"
    ]
    assert gitleaks[0]["level"] == "error"
    text = json.dumps(document) + runner.summary.read_text("utf-8")
    for leaked in (out / "gitleaks-1.sarif").read_text("utf-8"), text:
        assert _FAKE_TOKEN not in leaked
    summary = runner.summary.read_text("utf-8")
    assert "finding(s) above policy" in summary and "gitleaks:github-pat" in summary
    assert "evals/ machinery" in summary


@pytest.mark.docker
def test_fixing_the_leak_updates_the_red_comment_instead_of_leaving_it(
    gitleaks_image: str, api: FakeGitHub, tmp_path: Path
) -> None:
    """Push 1 leaks: one comment, red. Push 2 fixes it: the *same* comment turns clean — a
    fixed PR must not keep a stale red comment, nor collect a second one."""
    repo = _repository(tmp_path, leak=True)
    (tmp_path / "1").mkdir()
    first = _run(repo, tmp_path / "1", api, event=Event())
    assert first.outputs["scan"]["status"] == "2"
    (comment,) = api.comments
    assert "finding(s) above policy" in comment["body"]

    shutil.rmtree(repo / "examples" / "skills" / "leaky")
    shutil.rmtree(repo / ".bellwether-static")
    (tmp_path / "2").mkdir()
    second = _run(repo, tmp_path / "2", api, event=Event())
    assert not second.failed, [r for r in second.results if r.returncode]
    (comment,) = api.comments
    assert "nothing above policy" in comment["body"]
    assert [method for method, _ in api.requests].count("PATCH") == 1


@pytest.mark.docker
def test_a_repository_with_no_skills_is_a_quiet_pass(
    gitleaks_image: str, api: FakeGitHub, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "x.md").write_text("x\n", encoding="utf-8")
    git_repo(repo)
    runner = _run(repo, tmp_path, api, event=Event(name="push"))
    assert not runner.failed
    assert runner.ran() == ["Select the skills", "No skills"]
    assert api.requests == []
