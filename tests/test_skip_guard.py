"""A skip must not be able to colour the container job green — the guard, and its wiring.

CI's container job ran ``sudo -E … pytest -m docker``. When ``ubuntu-latest`` moved to an image
whose sudo ignores ``-E``, the ``CI`` variable stopped reaching pytest, every test gated on it
skipped, and the job stayed green for twelve merges (#112, #114–#124). Two things changed, and
each is tested here **at the step the workflow runs**, not on a helper:

* the step hands the variables to the root process by name (``sudo env NAME=value …``);
* the step passes ``--skips-are-failures`` (``tests/skip_guard.py``), so a skip on that job is
  red whatever caused it.

The step is executed, not read: ``WorkflowRunner`` runs the workflow's own ``run:`` text under
bash, in a scratch checkout holding one ``CI``-gated test, with a stand-in ``sudo`` on ``PATH``.
The stand-in models the one property the incident turned on — the command starts from a reset
environment, and ``-E`` is refused with the runner's own warning. The first test below runs the
*old* step under it and gets the incident back, green and skipped; a stand-in that could not
reproduce that would make every other test here meaningless.

Not modelled: the real ubuntu-26.04 sudo. That is measured by the container job itself, which
runs this step for real, and by its "Assert sudo carries a named variable" step.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.skip_guard import FLAG
from tests.workflow_harness import Event, WorkflowRunner

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CI_WORKFLOW = WORKFLOWS / "ci.yml"
TEST_STEP = "Container integration tests"
PROBE_STEP = "Assert sudo carries a named variable"
OLD_STEP = 'sudo -E "$(pwd)/.venv/bin/python" -m pytest -m docker -v --no-header'
SUDO_WARNING = "sudo: preserving the entire environment is not supported, '-E' is ignored"

# A sudo that starts the command from a reset environment — the default (`env_reset`) of every
# sudo — and treats the flags as the runner's does: `-E` refused with a warning, a named
# `--preserve-env=A,B` honoured. PATH is the fixed one sudo installs (`secure_path`).
_SUDO = f"""#!/bin/bash
keep=()
while [ $# -gt 0 ]; do
  case "$1" in
    -E|--preserve-env) echo "{SUDO_WARNING}" >&2; shift ;;
    --preserve-env=*)
      if [ "${{BW_FAKE_SUDO_IGNORES_NAMES:-}}" != "1" ]; then
        IFS=, read -ra names <<< "${{1#--preserve-env=}}"
        for name in "${{names[@]}}"; do
          [ -n "${{!name+set}}" ] && keep+=("$name=${{!name}}")
        done
      fi
      shift ;;
    --version) echo "fake sudo for tests"; exit 0 ;;
    -n) shift ;;
    *) break ;;
  esac
done
exec /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \\
  "${{keep[@]}}" "$@"
"""

_GATED_TEST = """
import json
import os
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not os.environ.get("CI"), reason="needs open egress; CI only"),
]


def test_gated() -> None:
    seen = {name: os.environ.get(name) for name in
            ("CI", "BELLWETHER_TEST_IMAGE", "PYTHONHASHSEED", "LC_ALL", "LANG", "LEAKED")}
    Path(__file__).with_name("seen.json").write_text(json.dumps(seen), encoding="utf-8")
"""


def _checkout(tmp_path: Path) -> Path:
    """A scratch checkout: the project's interpreter at ``.venv/bin/python``, the guard plugin,
    and one ``CI``-gated container test. Nothing in it names the variables the step carries."""
    repo = tmp_path / "checkout"
    (repo / ".venv" / "bin").mkdir(parents=True)
    python = repo / ".venv" / "bin" / "python"
    python.write_text(f'#!/bin/bash\nexec "{sys.executable}" -B "$@"\n', encoding="utf-8")
    python.chmod(0o755)
    (repo / "pytest.ini").write_text(
        "[pytest]\naddopts = -p no:cacheprovider --strict-markers\nmarkers =\n    docker: container\n",
        encoding="utf-8",
    )
    (repo / "conftest.py").write_text(
        f"import sys\nsys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "from tests.skip_guard import pytest_addoption, pytest_runtest_makereport  # noqa\n",
        encoding="utf-8",
    )
    (repo / "test_gated.py").write_text(_GATED_TEST, encoding="utf-8")
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "sudo").write_text(_SUDO, encoding="utf-8")
    (shim / "sudo").chmod(0o755)
    return repo


def _run_step(
    tmp_path: Path,
    step: str,
    *,
    substitutions: tuple[tuple[str, str], ...] = (),
    env: dict[str, str] | None = None,
) -> tuple[int | None, str]:
    repo = _checkout(tmp_path)
    document = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    names = [str(s.get("name", s.get("uses"))) for s in document["jobs"]["container"]["steps"]]
    assert step in names
    scratch = tmp_path / "harness"
    scratch.mkdir()
    runner = WorkflowRunner(
        CI_WORKFLOW,
        "container",
        repo,
        scratch,
        event=Event(name="pull_request"),
        skip=[name for name in names if name != step],
        substitutions=substitutions,
        # What the runner sets for every step, plus a variable nothing asked sudo to carry.
        env={
            "CI": "true",
            "LEAKED": "from-the-caller",
            "PATH": f"{tmp_path / 'shim'}:{os.environ['PATH']}",
            **(env or {}),
        },
    )
    runner.run()
    result = runner.result(step)
    assert result.ran
    return result.returncode, result.output


def _seen(tmp_path: Path) -> dict[str, str | None]:
    import json

    seen: dict[str, str | None] = json.loads(
        (tmp_path / "checkout" / "seen.json").read_text(encoding="utf-8")
    )
    return seen


def _new_step() -> str:
    document = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    [step] = [s for s in document["jobs"]["container"]["steps"] if s.get("name") == TEST_STEP]
    return str(step["run"])


# ---------------------------------------------------------------------------
# The incident, reproduced — then the step as it is now
# ---------------------------------------------------------------------------


def test_the_old_step_under_a_sudo_that_ignores_dash_e_skips_and_stays_green(
    tmp_path: Path,
) -> None:
    """What CI did from #112 to #124. This is the stand-in earning its keep: the step as it was,
    under a sudo that behaves as the runner's log shows, exits 0 having run nothing."""
    code, output = _run_step(tmp_path, TEST_STEP, substitutions=((_new_step(), OLD_STEP),))
    assert SUDO_WARNING in output
    assert code == 0
    assert "1 skipped" in output and "passed" not in output
    assert not (tmp_path / "checkout" / "seen.json").exists()


def test_the_step_carries_ci_to_the_root_process(tmp_path: Path) -> None:
    code, output = _run_step(tmp_path, TEST_STEP)
    assert code == 0, output
    assert "1 passed" in output and "skipped" not in output
    assert SUDO_WARNING not in output
    workflow_env = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))["env"]
    assert _seen(tmp_path) == {
        "CI": "true",
        "BELLWETHER_TEST_IMAGE": workflow_env["BELLWETHER_TEST_IMAGE"],
        "PYTHONHASHSEED": workflow_env["PYTHONHASHSEED"],
        "LC_ALL": workflow_env["LC_ALL"],
        "LANG": workflow_env["LANG"],
        # The reset is real: only what the step names arrives.
        "LEAKED": None,
    }


def test_the_step_names_every_workflow_variable(tmp_path: Path) -> None:
    """A variable added to the workflow's ``env:`` and not to the step's list would be set for
    every job but the one that runs as root — the same failure, one variable at a time."""
    workflow_env = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))["env"]
    carried = set(re.findall(r'"([A-Z_]+)=\$\{\1\}"', _new_step()))
    assert carried == {"CI", *workflow_env}


def test_a_skip_fails_the_step_even_when_the_variable_is_lost(tmp_path: Path) -> None:
    """The guard on its own: the old way of passing the environment, with the flag. The gated
    test still skips — and now the job is red and says which test and why."""
    old_with_flag = f"{OLD_STEP} -rs {FLAG}"
    code, output = _run_step(tmp_path, TEST_STEP, substitutions=((_new_step(), old_with_flag),))
    assert code == 1
    assert "1 error" in output and "skipped" not in output.split(SUDO_WARNING)[0].splitlines()[-1]
    assert "test_gated.py::test_gated was skipped" in output
    assert "needs open egress; CI only" in output


def test_the_step_passes_the_flag(tmp_path: Path) -> None:
    """Without the flag, a runner that does not set ``CI`` at all is green again."""
    step = _new_step()
    assert FLAG in step
    code, output = _run_step(tmp_path, TEST_STEP, env={"CI": ""})
    assert code == 1, output
    assert "test_gated.py::test_gated was skipped" in output
    code, output = _run_step(
        tmp_path / "unflagged", TEST_STEP, substitutions=((FLAG, ""),), env={"CI": ""}
    )
    assert code == 0 and "1 skipped" in output  # the hole the flag closes


# ---------------------------------------------------------------------------
# The probe for the form the paid workflows use
# ---------------------------------------------------------------------------


def test_the_probe_passes_where_sudo_carries_a_named_variable(tmp_path: Path) -> None:
    code, output = _run_step(tmp_path, PROBE_STEP)
    assert code == 0, output
    assert "carries a named variable" in output


def test_the_probe_fails_where_sudo_drops_a_named_variable(tmp_path: Path) -> None:
    code, output = _run_step(tmp_path, PROBE_STEP, env={"BW_FAKE_SUDO_IGNORES_NAMES": "1"})
    assert code == 1
    assert "::error::sudo --preserve-env=NAME did not carry the variable" in output


def test_the_probe_runs_before_root_touches_the_checkout() -> None:
    document = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    names = [str(s.get("name", s.get("uses"))) for s in document["jobs"]["container"]["steps"]]
    assert names.index(PROBE_STEP) < names.index(TEST_STEP)
    assert names[-1] == TEST_STEP


def test_no_workflow_asks_sudo_for_the_whole_environment() -> None:
    """Fix the class: ``-E`` (and its long form with no names) is the spelling that failed
    without an error. Every sudo in every workflow names what it carries, or carries nothing."""
    whole_environment = re.compile(r"\bsudo\b[^\n|;&]*?\s(-E\b|--preserve-env(?!=))")
    offenders = [
        f"{path.name}:{number}: {line.strip()}"
        for path in sorted(WORKFLOWS.glob("*.yml"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if not line.lstrip().startswith("#") and whole_environment.search(line)
    ]
    assert offenders == []
    assert whole_environment.search(f"  run: {OLD_STEP}")
    assert whole_environment.search("sudo -n --preserve-env ./x")
    assert not whole_environment.search('sudo --preserve-env=ANTHROPIC_API_KEY "${bw}" run')


# ---------------------------------------------------------------------------
# The guard itself
# ---------------------------------------------------------------------------

_SAMPLES = {
    "mark": "import pytest\n\n@pytest.mark.skipif(True, reason='gate closed')\ndef test_it():\n    pass\n",
    "body": "import pytest\n\ndef test_it():\n    pytest.skip('no daemon here')\n",
    "fixture": (
        "import pytest\n\n@pytest.fixture\ndef daemon():\n    pytest.skip('no daemon in setup')\n\n"
        "def test_it(daemon):\n    pass\n"
    ),
}
_REASONS = {"mark": "gate closed", "body": "no daemon here", "fixture": "no daemon in setup"}


def _pytest(tmp_path: Path, body: str, *flags: str) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "test_sample.py").write_text(body, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    return subprocess.run(
        [
            *(sys.executable, "-B", "-m", "pytest", "-p", "tests.skip_guard"),
            *("-p", "no:cacheprovider", "-rs", *flags, str(tmp_path)),
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("how", sorted(_SAMPLES))
def test_a_skip_is_a_failure_under_the_flag_however_it_was_raised(tmp_path: Path, how: str) -> None:
    plain = _pytest(tmp_path / "plain", _SAMPLES[how])
    assert plain.returncode == 0 and "1 skipped" in plain.stdout
    flagged = _pytest(tmp_path / "flagged", _SAMPLES[how], FLAG)
    assert flagged.returncode == 1, flagged.stdout
    # A skip raised before the test body (a mark, a fixture) is reported as an error in setup;
    # one raised inside the body as a failure. Both are red, and neither is counted as a skip.
    summary = flagged.stdout.splitlines()[-1]
    assert ("1 failed" if how == "body" else "1 error") in summary and "skipped" not in summary
    assert "test_sample.py::test_it was skipped" in flagged.stdout
    assert _REASONS[how] in flagged.stdout


def test_an_expected_failure_is_not_a_skip(tmp_path: Path) -> None:
    """§24 keeps deliberately-failing corpus tests visible as ``xfail``; they ran, and the flag
    is about tests that did not."""
    body = (
        "import pytest\n\n@pytest.mark.xfail(reason='documented')\ndef test_it():\n    assert False\n\n"
        "@pytest.mark.xfail(run=False, reason='not run, declared')\ndef test_other():\n    pass\n"
    )
    flagged = _pytest(tmp_path, body, FLAG)
    assert flagged.returncode == 0, flagged.stdout
    assert "2 xfailed" in flagged.stdout


def test_a_passing_run_is_untouched_by_the_flag(tmp_path: Path) -> None:
    flagged = _pytest(tmp_path, "def test_it():\n    pass\n", FLAG)
    assert flagged.returncode == 0 and "1 passed" in flagged.stdout


def test_the_suite_registers_the_flag(request: pytest.FixtureRequest) -> None:
    """The workflow passes the flag to *this* suite; ``conftest.py`` must be what defines it, or
    the container job dies on an unknown argument. Off unless asked for."""
    assert request.config.getoption(FLAG) in (False, True)
    conftest = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert "from tests.skip_guard import pytest_addoption, pytest_runtest_makereport" in conftest
