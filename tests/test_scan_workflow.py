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
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.test_sarif import assert_valid_sarif

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


def test_it_uses_no_secret_and_writes_nothing_but_security_events() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text
    assert _workflow()["permissions"] == {"contents": "read"}
    assert _workflow()["jobs"]["scan"]["permissions"] == {
        "contents": "read",
        "security-events": "write",
        "actions": "read",
    }
    checkout = _steps()[0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["persist-credentials"] is False


def test_the_uploads_survive_a_failing_scan_and_the_gate_comes_after_them() -> None:
    names = [step.get("name") for step in _steps()]
    assert names.index("Scan") < names.index("Upload to code scanning")
    assert names.index("Upload to code scanning") < names.index("Static gate")
    assert names.index("Upload the scan") < names.index("Static gate")
    for upload in ("Upload to code scanning", "Upload the scan"):
        assert _step(upload)["if"].strip().startswith("always()")
    assert _step("Upload the scan")["with"]["if-no-files-found"] == "error"


def test_the_security_tab_upload_is_skipped_for_a_fork() -> None:
    condition = " ".join(_step("Upload to code scanning")["if"].split())
    assert "github.event.pull_request.head.repo.full_name == github.repository" in condition
    assert "github.event_name != 'pull_request'" in condition
    # One category, set in the SARIF (`automationDetails`), never overridden here: the action's
    # `category` input would re-key the run.
    assert "category" not in _step("Upload to code scanning")["with"]


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
# Running it
# ---------------------------------------------------------------------------

_IMAGE = _workflow()["env"]["GITLEAKS_IMAGE"]
#: A GitHub-token-shaped string, assembled at run time so no secret-shaped literal is committed.
_FAKE_TOKEN = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5"


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


def _repository(tmp_path: Path, *, leak: bool) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(_ROOT / "examples" / "skills" / "workspace-stats", repo / "examples/skills/ws")
    shutil.copytree(_ROOT / "tests" / "corpus-static" / "fetch-and-exec", repo / "tests/fx")
    shutil.copy(_ROOT / "examples" / "live" / "policy.yaml", repo / "policy.yaml")
    if leak:
        skill = repo / "examples" / "skills" / "leaky"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            "---\nname: leaky\ndescription: Publishes the release notes to the team wiki.\n---\n"
            f"\nAuthenticate with {_FAKE_TOKEN} when you post.\n",
            encoding="utf-8",
        )
        # A secret in the skill's own test fixture is machinery, not the skill (§15).
        fixtures = skill / "evals" / "fixtures"
        fixtures.mkdir(parents=True)
        (fixtures / "token.txt").write_text(f"{_FAKE_TOKEN}\n", encoding="utf-8")

    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

    git("init", "-q")
    git("add", "-A")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "fixture")
    return repo


class _Runner:
    """Runs the workflow's steps in order, the way the Actions runner would."""

    def __init__(self, repo: Path, tmp: Path, *, event: str, fork: bool) -> None:
        self.repo = repo
        self.outputs: dict[str, dict[str, str]] = {}
        self.summary = tmp / "step_summary.md"
        self.summary.write_text("", encoding="utf-8")
        self.failed = False
        self.ran: list[str] = []
        self.event = event
        self.fork = fork
        bellwether = Path(sys.executable).parent / "bellwether"
        assert bellwether.exists(), bellwether
        self.bellwether = str(bellwether)
        workflow_env = {k: str(v) for k, v in _workflow()["env"].items()}
        workflow_env["BELLWETHER_POLICY"] = "policy.yaml"
        self.env = {**os.environ, **workflow_env, "GITHUB_WORKSPACE": str(repo)}

    def _expression(self, text: str) -> str:
        def lookup(match: re.Match[str]) -> str:
            step, key = match.group(1), match.group(2)
            return repr(self.outputs.get(step, {}).get(key, ""))

        python = re.sub(r"steps\.(\w+)\.outputs\.(\w+)", lookup, " ".join(text.split()))
        python = python.replace("always()", "True").replace("&&", " and ").replace("||", " or ")
        python = python.replace("!=", " != ").replace("==", " == ")
        head = "fork/repo" if self.fork else "owner/repo"
        python = python.replace("github.event.pull_request.head.repo.full_name", repr(head))
        python = python.replace("github.event_name", repr(self.event))
        python = python.replace("github.repository", repr("owner/repo"))
        return python

    def condition(self, step: dict[str, Any]) -> bool:
        if "if" not in step:
            return not self.failed
        expression = str(step["if"])
        if not expression.strip().startswith("always()") and self.failed:
            return False
        return bool(eval(self._expression(expression), {"__builtins__": {}}, {}))

    def run(self) -> None:
        for step in _steps():
            name = step.get("name", "checkout")
            if name in ("checkout", "Install uv", "Install Bellwether"):
                continue
            if not self.condition(step):
                continue
            self.ran.append(name)
            if "uses" in step:
                continue
            script = re.sub(
                r"\$\{\{\s*steps\.(\w+)\.outputs\.(\w+)\s*\}\}",
                lambda m: self.outputs.get(m.group(1), {}).get(m.group(2), ""),
                step["run"],
            ).replace("uv run bellwether", self.bellwether)
            output = self.repo / ".github_output"
            output.write_text("", encoding="utf-8")
            completed = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                cwd=self.repo,
                env={
                    **self.env,
                    "GITHUB_OUTPUT": str(output),
                    "GITHUB_STEP_SUMMARY": str(self.summary),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.last = completed
            if "id" in step:
                values = dict(
                    line.split("=", 1) for line in output.read_text("utf-8").splitlines() if line
                )
                self.outputs[step["id"]] = values
            if completed.returncode != 0:
                self.failed = True
                self.failure = (name, completed.returncode, completed.stdout + completed.stderr)


@pytest.mark.docker
def test_a_clean_repository_passes_and_scans_only_the_real_roots(
    gitleaks_image: str, tmp_path: Path
) -> None:
    repo = _repository(tmp_path, leak=False)
    runner = _Runner(repo, tmp_path, event="pull_request", fork=False)
    runner.run()
    assert not runner.failed, runner.failure
    out = repo / ".bellwether-static"
    # tests/fx is a hostile fixture (curl | sh); it is not under the roots and is never scanned.
    assert (out / "skills.txt").read_text("utf-8").splitlines() == ["examples/skills/ws"]
    assert runner.outputs["scan"]["status"] == "0"
    assert runner.ran[-1] == "Static gate"
    assert "Upload to code scanning" in runner.ran and "Upload the scan" in runner.ran
    document = assert_valid_sarif((out / "bellwether-static.sarif").read_text("utf-8"))
    assert len(document["runs"]) == 1
    assert document["runs"][0]["automationDetails"] == {"id": "bellwether-static/"}
    summary = runner.summary.read_text("utf-8")
    assert summary.startswith("<!-- bellwether-static -->")
    assert "nothing above policy" in summary and "`gitleaks`" in summary


@pytest.mark.docker
@pytest.mark.parametrize("fork", [False, True])
def test_a_leaked_token_fails_the_gate_after_the_upload(
    gitleaks_image: str, tmp_path: Path, fork: bool
) -> None:
    repo = _repository(tmp_path, leak=True)
    runner = _Runner(repo, tmp_path, event="pull_request", fork=fork)
    runner.run()
    # The scan itself completes (exit 2 is a verdict, not a crash); the gate step fails last.
    assert runner.outputs["scan"]["status"] == "2"
    assert runner.failed and runner.failure[0] == "Static gate" and runner.failure[1] == 2
    assert ("Upload to code scanning" in runner.ran) is (not fork)
    assert "Upload the scan" in runner.ran

    out = repo / ".bellwether-static"
    document = assert_valid_sarif((out / "bellwether-static.sarif").read_text("utf-8"))
    results = document["runs"][0]["results"]
    gitleaks = [r for r in results if r["ruleId"] == "gitleaks:github-pat"]
    # Attributed to the skill's SKILL.md (a relative scan root from the repository root), floored to high → `error`; the
    # fixture under evals/ is machinery and is not attributed.
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
def test_a_repository_with_no_skills_is_a_quiet_pass(gitleaks_image: str, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "x.md").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"],
        check=True,
    )
    runner = _Runner(repo, tmp_path, event="push", fork=False)
    runner.run()
    assert not runner.failed, runner.failure
    assert runner.ran == ["Select the skills", "No skills"]
