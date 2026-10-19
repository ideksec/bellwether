"""The nightly drift run (§18.1, §18.4 step 6): served models, the drift reading, the issues,
and ``bellwether-nightly.yml`` executed.

* ``matrix.models`` — the model ids that answered, read off the ``model_turn`` actions the
  real harnesses write, aggregated per target into the summary;
* ``read_drift`` — each status from the evaluation's own regression gate and verdict;
* the issues — through the real transport against the harness's fake GitHub: opened once,
  left alone while unchanged, edited and commented on when the findings change, closed when
  stable, and a human's issue carrying the marker never touched;
* the workflow — its job-level opt-in evaluated (a scheduled run with the variable unset runs
  nothing), and its steps executed with a fake ``run`` dropping in prepared evaluations.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from bellwether.cli.baselines import baseline_from_summary, write_baseline
from bellwether.cli.drift import (
    DriftReading,
    drift_key,
    read_drift,
    render_drift_issue,
    render_drift_markdown,
    upsert_drift_issues,
)
from bellwether.cli.orchestrator import served_models
from bellwether.cli.pr import github_transport
from bellwether.report import Summary
from bellwether.trace import Action
from tests.workflow_harness import FAKE_TOKEN, Event, FakeGitHub, WorkflowRunner, bellwether_wrapper

_ROOT = Path(__file__).resolve().parents[1]
_DEMO = _ROOT / "examples" / "reports" / "demo-benign-note-taker"
_WORKFLOW = _ROOT / ".github" / "workflows" / "bellwether-nightly.yml"
_SLUG = "api-loop-scripted-frontier"


@pytest.fixture
def api() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    yield fake
    fake.close()


def _summary(
    *,
    skill: str = "a-skill",
    verdict: str = "ready",
    regression: tuple[str, str] | None = None,
    deltas: Mapping[str, object] | None = None,
    models: Mapping[str, Sequence[str]] | None = None,
    notes: Sequence[str] = (),
    eval_id: str = "tonight",
    blocks: Sequence[tuple[str, str]] = (),
) -> Summary:
    """The committed demo summary, re-cut: its verdict, regression gate, deltas and models."""
    data = json.loads((_DEMO / "summary.json").read_text(encoding="utf-8"))
    data["skill"]["name"] = skill
    data["eval_id"] = eval_id
    data["verdict"]["status"] = verdict
    data["verdict"]["notes"] = list(notes)
    gates = [g for g in data["verdict"]["gates"] if g["status"] != "block"]
    gates += [{"name": n, "status": "block", "reason": r, "required": True} for n, r in blocks]
    if regression is not None:
        gates.append({"name": "regression", "status": regression[0], "reason": regression[1]})
        data["regression"] = {"baseline_eval_id": "then", "deltas": dict(deltas or {})}
    data["verdict"]["gates"] = gates
    chosen = {_SLUG: ["m-1"]} if models is None else models
    data["matrix"]["models"] = {k: list(v) for k, v in chosen.items()}
    return Summary.model_validate(data)


def _baseline(verdict: str = "ready", models: Mapping[str, Sequence[str]] | None = None) -> Any:
    return baseline_from_summary(_summary(verdict=verdict, models=models, eval_id="then"))


# ---------------------------------------------------------------------------
# Served models
# ---------------------------------------------------------------------------


def _turn(seq: int, *, reported: str | None, requested: str = "alias-id") -> Action:
    return Action.model_validate(
        {
            "type": "action",
            "seq": seq,
            "ts": "2026-01-01T00:00:00Z",
            "plane": "harness",
            "kind": "model_turn",
            "actor": {"role": "assistant", "turn": seq},
            "action": {"model_id_requested": requested, "model_id_reported": reported},
        }
    )


def test_served_models_prefer_the_reported_id() -> None:
    actions = [
        _turn(1, reported="claude-x-20260101"),
        _turn(2, reported="claude-x-20260301"),  # a silent update mid-run
        _turn(3, reported=None, requested="unreported-alias"),  # nothing reported: as asked
        _turn(4, reported="claude-x-20260101"),
    ]
    # The requested id of a turn that *did* report is not a model that served anything.
    assert served_models(actions) == (
        "claude-x-20260101",
        "claude-x-20260301",
        "unreported-alias",
    )


def test_the_demo_summary_records_what_its_turns_report() -> None:
    """End to end through the real pipeline (`bellwether demo`): the scripted transcript reports
    ``demo-model-v1`` and the committed summary carries it under its target."""
    data = json.loads((_DEMO / "summary.json").read_text(encoding="utf-8"))
    assert data["matrix"]["models"] == {_SLUG: ["demo-model-v1"]}
    assert data["schema_version"] == "1.5"


# ---------------------------------------------------------------------------
# Reading drift
# ---------------------------------------------------------------------------


def test_no_baseline() -> None:
    reading = read_drift(_summary(), None)
    assert reading.status == "no_baseline" and reading.baseline_verdict is None


def test_a_baseline_the_key_rules_out_is_not_comparable_and_says_why() -> None:
    note = "regression not composed: baseline 'then' was captured on a different target set"
    reading = read_drift(_summary(notes=[note]), _baseline())
    assert reading.status == "not_comparable" and reading.reason == note


def test_a_blocking_regression_gate_is_drift() -> None:
    reading = read_drift(
        _summary(
            regression=("block", "tier-1 expansion: network_egress"),
            deltas={"capabilities_added": ["network_egress"]},
        ),
        _baseline(),
    )
    assert reading.status == "drift"
    assert reading.findings[0] == "regression gate blocks: tier-1 expansion: network_egress"
    assert "new tier-1 capabilities: network_egress" in reading.findings


def test_a_worse_verdict_is_drift_even_where_the_regression_gate_passes() -> None:
    """A security gate that newly blocks is drift though no tier-1 class was added."""
    reading = read_drift(
        _summary(
            verdict="not_ready",
            regression=("pass", "no regression"),
            blocks=[("security_runtime.egress", "blocked host x.example")],
        ),
        _baseline("ready"),
    )
    assert reading.status == "drift"
    assert reading.findings[:2] == (
        "verdict ready → not_ready",
        "gate security_runtime.egress blocks: blocked host x.example",
    )


def test_a_better_or_equal_verdict_with_a_passing_gate_is_stable() -> None:
    for before, after in (("conditional", "ready"), ("ready", "ready")):
        reading = read_drift(_summary(verdict=after, regression=("pass", "ok")), _baseline(before))
        assert reading.status == "stable", (before, after)


def test_a_warning_regression_gate_is_warn_not_drift() -> None:
    reading = read_drift(
        _summary(regression=("warn", "new sensitive hit ~/.ssh"), deltas={}), _baseline()
    )
    assert reading.status == "warn"


def test_pass_rate_and_bci_drops_are_findings() -> None:
    reading = read_drift(
        _summary(
            regression=("block", "lower bound drop 0.3"),
            deltas={
                "lower_bound": {"before": 0.9, "after": 0.6, "drop": 0.3},
                "bci": {"before": 80, "after": 80, "drop": 0},
            },
        ),
        _baseline(),
    )
    assert "pass-rate lower bound 0.9 → 0.6 (drop 0.3)" in reading.findings
    assert not any(f.startswith("BCI") for f in reading.findings)


def test_a_model_change_is_reported_but_is_not_drift_on_its_own() -> None:
    reading = read_drift(
        _summary(regression=("pass", "ok"), models={_SLUG: ["m-2"]}),
        _baseline(models={_SLUG: ["m-1"]}),
    )
    assert reading.status == "stable"
    assert reading.model_changes == {_SLUG: (("m-1",), ("m-2",))}


def test_a_baseline_from_before_models_were_recorded_reads_as_unknown() -> None:
    reading = read_drift(
        _summary(regression=("block", "x"), models={_SLUG: ["m-2"]}), _baseline(models={})
    )
    title, body = render_drift_issue(reading, run_url=None)
    assert "`m-2` — baseline: not recorded" in body
    assert title == "Bellwether drift: a-skill"


def test_the_findings_digest_moves_with_the_findings_only() -> None:
    def drifted(added: str, eval_id: str) -> DriftReading:
        return read_drift(
            _summary(
                regression=("block", "x"),
                deltas={"capabilities_added": [added]},
                eval_id=eval_id,
            ),
            _baseline(),
        )

    assert drifted("a", "night-1").findings_digest == drifted("a", "night-2").findings_digest
    assert drifted("a", "night-1").findings_digest != drifted("b", "night-1").findings_digest


def test_what_the_skill_chose_is_inert_in_the_issue_and_the_summary() -> None:
    hostile = "x\n## ready @maintainers <img src=x>"
    reading = read_drift(
        _summary(regression=("block", hostile), deltas={"capabilities_added": [hostile]}),
        _baseline(),
    )
    _title, body = render_drift_issue(reading, run_url=None)
    summary = render_drift_markdown([reading], run_url=None)
    for rendered in (body, summary):
        assert "\n## ready" not in rendered
        assert "@maintainers" not in rendered
        assert "<img" not in rendered.replace("\\<img", "")


def test_the_issue_key_is_per_skill_and_domain_separated() -> None:
    assert drift_key("a") != drift_key("b")
    assert len(drift_key("a")) == 16
    # Not the static-scan key, not an evaluation's comment key.
    from bellwether.cli.pr import STATIC_SCAN_KEY, report_key

    assert drift_key("a") not in (STATIC_SCAN_KEY, report_key("a", [_SLUG]))


# ---------------------------------------------------------------------------
# Issues, through the real transport
# ---------------------------------------------------------------------------


def _drifting(added: str = "network_egress", *, skill: str = "a-skill") -> DriftReading:
    return read_drift(
        _summary(
            skill=skill, regression=("block", "expansion"), deltas={"capabilities_added": [added]}
        ),
        _baseline(),
    )


def _stable(skill: str = "a-skill") -> DriftReading:
    return read_drift(_summary(skill=skill, regression=("pass", "ok")), _baseline())


def _upsert(api: FakeGitHub, readings: Sequence[DriftReading]) -> dict[str, str]:
    return dict(
        upsert_drift_issues(
            github_transport(),
            "owner/repo",
            readings,
            token=FAKE_TOKEN,
            run_url="https://github.com/owner/repo/actions/runs/9",
            api_root=api.url,
        )
    )


def test_a_drifting_skill_gets_one_issue_and_an_unchanged_night_adds_nothing(
    api: FakeGitHub,
) -> None:
    assert _upsert(api, [_drifting()]) == {"a-skill": "opened"}
    [issue] = api.issues
    assert issue["title"] == "Bellwether drift: a-skill"
    assert "network\\_egress" in issue["body"] and "actions/runs/9" in issue["body"]
    assert _upsert(api, [_drifting()]) == {"a-skill": "unchanged"}
    assert len(api.issues) == 1 and api.comments == []


def test_changed_findings_edit_the_issue_and_say_so(api: FakeGitHub) -> None:
    _upsert(api, [_drifting("network_egress")])
    assert _upsert(api, [_drifting("process_exec")]) == {"a-skill": "updated"}
    [issue] = api.issues
    assert "process\\_exec" in issue["body"] and "network\\_egress" not in issue["body"]
    [comment] = api.comments
    assert comment["issue"] == issue["number"] and "drift changed" in comment["body"]


def test_a_stable_night_closes_the_issue(api: FakeGitHub) -> None:
    _upsert(api, [_drifting()])
    assert _upsert(api, [_stable()]) == {"a-skill": "closed"}
    [issue] = api.issues
    assert issue["state"] == "closed" and issue["state_reason"] == "completed"
    assert "No longer drifting" in api.comments[0]["body"]
    # Drifting again later opens a fresh issue: the closed one is history.
    assert _upsert(api, [_drifting()]) == {"a-skill": "opened"}
    assert [i["state"] for i in api.issues] == ["closed", "open"]


def test_a_night_that_cannot_compare_leaves_the_issue_open(api: FakeGitHub) -> None:
    _upsert(api, [_drifting()])
    note = "regression not composed: different target set"
    not_comparable = read_drift(_summary(notes=[note]), _baseline())
    assert _upsert(api, [not_comparable]) == {"a-skill": "none"}
    assert api.issues[0]["state"] == "open"


def test_a_stable_skill_with_no_issue_opens_nothing(api: FakeGitHub) -> None:
    assert _upsert(api, [_stable()]) == {"a-skill": "none"}
    assert api.issues == []


def test_each_skill_has_its_own_issue(api: FakeGitHub) -> None:
    _upsert(api, [_drifting(skill="a-skill"), _drifting(skill="b-skill")])
    assert sorted(i["title"] for i in api.issues) == [
        "Bellwether drift: a-skill",
        "Bellwether drift: b-skill",
    ]
    assert _upsert(api, [_stable("a-skill"), _drifting(skill="b-skill")]) == {
        "a-skill": "closed",
        "b-skill": "unchanged",
    }


def test_an_issue_a_person_wrote_with_the_marker_is_never_touched(api: FakeGitHub) -> None:
    """Only the bot's own issues are matched: anyone can paste a marker into an issue."""
    _title, body = render_drift_issue(_drifting(), run_url=None)
    api.issues.append(
        {
            "number": 1,
            "title": "copied",
            "body": body,
            "state": "open",
            "user": {"login": "someone", "type": "User"},
        }
    )
    assert _upsert(api, [_stable()]) == {"a-skill": "none"}
    assert _upsert(api, [_drifting()]) == {"a-skill": "opened"}
    assert api.issues[0]["state"] == "open" and api.issues[0]["title"] == "copied"


def test_a_pull_request_in_the_issue_list_is_not_an_issue(api: FakeGitHub) -> None:
    _title, body = render_drift_issue(_drifting(), run_url=None)
    api.issues.append(
        {
            "number": 2,
            "title": "pr",
            "body": body,
            "state": "open",
            "pull_request": {},
            "user": {"login": "github-actions[bot]", "type": "Bot"},
        }
    )
    assert _upsert(api, [_drifting()]) == {"a-skill": "opened"}


def test_the_existing_issue_is_found_past_the_first_page(api: FakeGitHub) -> None:
    for number in range(150):
        api.issues.append(
            {
                "number": number,
                "title": f"other {number}",
                "body": "unrelated",
                "state": "open",
                "user": {"login": "x", "type": "User"},
            }
        )
    _upsert(api, [_drifting()])
    assert _upsert(api, [_drifting()]) == {"a-skill": "unchanged"}


# ---------------------------------------------------------------------------
# The workflow
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("event", "runs"),
    [
        (Event(name="schedule", action=""), False),
        (Event(name="schedule", action="", vars={"BELLWETHER_NIGHTLY": "false"}), False),
        (Event(name="schedule", action="", vars={"BELLWETHER_NIGHTLY": "true"}), True),
        (Event(name="workflow_dispatch", action=""), True),
    ],
)
def test_the_schedule_spends_nothing_until_a_maintainer_opts_in(
    tmp_path: Path, event: Event, runs: bool
) -> None:
    runner = WorkflowRunner(_WORKFLOW, "nightly", tmp_path, tmp_path, event=event)
    assert runner.job_runs() is runs


def test_the_workflow_is_shaped_as_documented() -> None:
    import yaml

    document = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    triggers = document[True]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert document["permissions"] == {"contents": "read"}
    job = document["jobs"]["nightly"]
    assert job["permissions"] == {"contents": "read", "issues": "write"}
    evaluate = {s.get("name"): s for s in job["steps"]}["Evaluate every skill"]["run"]
    # The cache would replay last night's model: off, on every run.
    assert "--no-cache" in evaluate
    assert evaluate.index("mkdir -p .bellwether-out") < evaluate.index("sudo --preserve-env")


@pytest.fixture
def _passwordless_sudo() -> None:
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if shutil.which("sudo") is None or probe.returncode != 0:
        pytest.skip("the nightly evaluate loop needs passwordless sudo")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _nightly_repository(tmp_path: Path, skills: Sequence[str]) -> Path:
    repo = tmp_path / "repo"
    for name in skills:
        skill = repo / "examples" / "skills" / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Counts lines.\n---\nx\n", encoding="utf-8"
        )
    hostile = repo / "tests" / "corpus" / "hostile"
    hostile.mkdir(parents=True)
    (hostile / "SKILL.md").write_text("---\nname: hostile\ndescription: d\n---\nx\n", "utf-8")
    baselines = repo / "examples" / "live" / "baselines"
    for name in skills:
        record = baseline_from_summary(_summary(skill=name, verdict="ready", eval_id="then"))
        write_baseline(record, baselines)
    _git(tmp_path, "init", "-q", str(repo))
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "main")
    return repo


def _evaluation(tmp: Path, summary: Summary) -> Path:
    directory = tmp / "evals" / summary.skill.name / summary.eval_id
    directory.mkdir(parents=True)
    (directory / "summary.json").write_text(summary.model_dump_json(), encoding="utf-8")
    return directory


def _fake_run(tmp: Path, outcomes: Mapping[str, tuple[Path | None, int]]) -> Path:
    cases = []
    for skill, (source, code) in outcomes.items():
        copy = f'cp -r "{source}" "$out/"' if source else ":"
        cases.append(f'  "examples/skills/{skill}") {copy}; exit {code} ;;')
    script = tmp / "fake-bellwether-run"
    script.write_text(
        "#!/bin/bash\n"
        f'printf "%s\\n" "$@" > "{tmp}/run-args-$(echo "$2" | tr / -)"\n'
        'skill="$2"; out=""\n'
        'while [ $# -gt 0 ]; do if [ "$1" = "--out" ]; then out="$2"; fi; shift; done\n'
        'mkdir -p "$out"\n'
        'case "$skill" in\n' + "\n".join(cases) + "\n  *) exit 9 ;;\nesac\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _run_nightly(
    repo: Path,
    tmp: Path,
    api: FakeGitHub,
    outcomes: Mapping[str, tuple[Path | None, int]],
    *,
    key: str = "sk-test",
) -> WorkflowRunner:
    wrapper = bellwether_wrapper(tmp, str(Path(sys.executable).parent / "bellwether"), api)
    runner = WorkflowRunner(
        _WORKFLOW,
        "nightly",
        repo,
        tmp,
        event=Event(name="schedule", action="", vars={"BELLWETHER_NIGHTLY": "true"}),
        api=api,
        secrets={"ANTHROPIC_API_KEY": key},
        substitutions=[
            ('bw="$(pwd)/.venv/bin/bellwether"', f'bw="{_fake_run(tmp, outcomes)}"'),
            ("uv run bellwether", str(wrapper)),
        ],
        skip=(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
            "Install uv",
            "Install Bellwether",
            "Build the recording-proxy sidecar image",
            "Build the controlled-resolver sidecar image",
        ),
    )
    runner.run()
    return runner


def _explain(runner: WorkflowRunner) -> list[tuple[str, int, str]]:
    return [(r.name, r.returncode, r.output[-1200:]) for r in runner.results if r.ran]


@pytest.mark.usefixtures("_passwordless_sudo")
def test_a_drifting_night_opens_an_issue_and_fails_the_run(api: FakeGitHub, tmp_path: Path) -> None:
    repo = _nightly_repository(tmp_path, ["a-skill", "b-skill"])
    drifted = _evaluation(
        tmp_path,
        _summary(
            skill="a-skill",
            regression=("block", "tier-1 expansion"),
            deltas={"capabilities_added": ["network_egress"]},
            models={_SLUG: ["m-2"]},
        ),
    )
    stable = _evaluation(tmp_path, _summary(skill="b-skill", regression=("pass", "ok")))
    runner = _run_nightly(repo, tmp_path, api, {"a-skill": (drifted, 0), "b-skill": (stable, 0)})
    assert runner.failed
    assert runner.result("Read drift").returncode == 2, _explain(runner)
    assert not runner.result("Infrastructure").ran
    [issue] = api.issues
    assert issue["title"] == "Bellwether drift: a-skill"
    assert "`m-2`" in issue["body"]
    summary = runner.summary.read_text(encoding="utf-8")
    assert "| `a-skill` | **drift**" in summary and "| `b-skill` | **stable**" in summary
    # Every skill under the root, never the fixture; each with the cache off.
    assert sorted(p.name for p in tmp_path.glob("run-args-*")) == [
        "run-args-examples-skills-a-skill",
        "run-args-examples-skills-b-skill",
    ]
    args = (tmp_path / "run-args-examples-skills-a-skill").read_text("utf-8").splitlines()
    assert "--no-cache" in args
    assert "Upload the evidence" in runner.ran()


@pytest.mark.usefixtures("_passwordless_sudo")
def test_a_stable_night_passes_and_opens_nothing(api: FakeGitHub, tmp_path: Path) -> None:
    repo = _nightly_repository(tmp_path, ["a-skill"])
    stable = _evaluation(tmp_path, _summary(skill="a-skill", regression=("pass", "ok")))
    runner = _run_nightly(repo, tmp_path, api, {"a-skill": (stable, 0)})
    assert not runner.failed, _explain(runner)
    assert api.issues == []


@pytest.mark.usefixtures("_passwordless_sudo")
@pytest.mark.parametrize("left_a_tree", [False, True])
def test_a_broken_evaluation_still_reads_the_others_and_fails(
    api: FakeGitHub, tmp_path: Path, left_a_tree: bool
) -> None:
    """Exit 3 with no tree, and exit 3 *with* one (a run that broke after writing): either
    way the run fails, and the other skills are still read."""
    repo = _nightly_repository(tmp_path, ["a-skill", "b-skill"])
    drifted = _evaluation(
        tmp_path,
        _summary(skill="b-skill", regression=("block", "x"), deltas={"capabilities_added": ["y"]}),
    )
    partial = (
        _evaluation(tmp_path, _summary(skill="a-skill", regression=("pass", "ok")))
        if left_a_tree
        else None
    )
    runner = _run_nightly(repo, tmp_path, api, {"a-skill": (partial, 3), "b-skill": (drifted, 0)})
    assert runner.failed
    assert runner.outputs["evaluate"]["status"] == "3"
    assert runner.result("Read drift").returncode == 2
    assert runner.result("Infrastructure").returncode == 3
    assert [i["title"] for i in api.issues] == ["Bellwether drift: b-skill"]


@pytest.mark.usefixtures("_passwordless_sudo")
def test_enabled_without_a_key_is_an_error_not_a_quiet_night(
    api: FakeGitHub, tmp_path: Path
) -> None:
    repo = _nightly_repository(tmp_path, ["a-skill"])
    runner = _run_nightly(repo, tmp_path, api, {}, key="")
    assert runner.failed
    result = runner.result("Evaluate every skill")
    assert result.returncode == 3 and "ANTHROPIC_API_KEY is not set" in result.output
    assert not list(tmp_path.glob("run-args-*"))
    assert api.issues == []
