"""Commit statuses per gate group (§18.2) and the static-scan PR comment.

The group table is held to the allowlist rule the control registry uses: every gate the
composition can produce maps to exactly one group (extracted from the orchestrator's source, so a
new gate cannot ship unmapped), and every table entry is a gate that exists (so a renamed gate
cannot leave a dead mapping behind while its new name reports nowhere).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bellwether.cli.app import ExitCode, app
from bellwether.cli.pr import (
    STATIC_SCAN_KEY,
    GitHubResponse,
    PrContext,
    report_key,
    upsert_pr_comment,
)
from bellwether.cli.status import (
    _GROUP_OF,
    GROUPS,
    GroupStatus,
    check_sha,
    evaluation_statuses,
    gate_group,
    post_statuses,
    run_url,
    uniform_statuses,
)
from bellwether.errors import BellwetherError
from bellwether.report.summary import GateSummary, Summary

_ROOT = Path(__file__).resolve().parents[1]
_REPORTS = _ROOT / "examples" / "reports"
_SHA = "0123456789abcdef0123456789abcdef01234567"
runner = CliRunner()


def _composed_gate_names() -> set[str]:
    source = (_ROOT / "src" / "bellwether" / "cli" / "orchestrator.py").read_text("utf-8")
    return set(re.findall(r'_gate\(\s*"([^"]+)"', source))


# ---------------------------------------------------------------------------
# The group table
# ---------------------------------------------------------------------------


def test_every_composed_gate_belongs_to_exactly_one_group() -> None:
    names = _composed_gate_names()
    assert len(names) >= 20, names  # the extraction itself works
    for name in names:
        assert gate_group(name) in GROUPS


def test_every_mapped_gate_is_one_the_composition_produces() -> None:
    assert set(_GROUP_OF) == _composed_gate_names()


def test_the_scored_security_dispositions_all_report_into_security() -> None:
    from bellwether.cli.orchestrator import ENFORCED_SECURITY_RUNTIME_DISPOSITIONS

    security = {name for name, group in _GROUP_OF.items() if name.startswith("security_runtime.")}
    assert len(security) == len(ENFORCED_SECURITY_RUNTIME_DISPOSITIONS)
    assert all(_GROUP_OF[name] == "security" for name in security)


def test_an_unmapped_gate_refuses_rather_than_reporting_nowhere() -> None:
    with pytest.raises(BellwetherError, match="no commit-status group"):
        gate_group("security_runtime.something_new")


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _summary(name: str, verdict: str, *gates: GateSummary) -> Summary:
    base = Summary.model_validate_json(
        (_REPORTS / "demo-benign-note-taker" / "summary.json").read_text("utf-8")
    )
    skill = base.skill.model_copy(update={"name": name})
    return base.model_copy(
        update={
            "skill": skill,
            "verdict": base.verdict.model_copy(update={"status": verdict, "gates": gates}),
        }
    )


def _gate(name: str, status: str, *, required: bool = True) -> GateSummary:
    return GateSummary(name=name, status=status, required=required)  # type: ignore[arg-type]


def _by_context(statuses: list[GroupStatus]) -> dict[str, GroupStatus]:
    return {s.context.split("/", 1)[1]: s for s in statuses}


@pytest.mark.parametrize(
    ("status", "required", "state", "word"),
    [
        ("block", True, "failure", "blocked"),
        ("block", False, "failure", "blocked"),
        ("not_evaluable", True, "failure", "blocked"),  # a required unknown blocks (§16.2)
        ("not_evaluable", False, "success", "warn"),
        ("warn", True, "success", "warn"),
        ("pass", True, "success", "pass"),
    ],
)
def test_a_groups_state_follows_its_gates(
    status: str, required: bool, state: str, word: str
) -> None:
    statuses = _by_context(
        evaluation_statuses(
            [
                _summary(
                    "s", "conditional", _gate("security_runtime.dns", status, required=required)
                )
            ],
            prefix="bellwether",
        )
    )
    assert statuses["security"].state == state
    assert statuses["security"].description.startswith(word)


def test_the_worst_evaluation_decides_each_group_and_names_its_skill() -> None:
    statuses = _by_context(
        evaluation_statuses(
            [
                _summary("clean", "ready", _gate("scope", "pass"), _gate("evidence", "pass")),
                _summary("dirty", "not_ready", _gate("scope", "block"), _gate("evidence", "pass")),
            ],
            prefix="bw",
        )
    )
    assert statuses["security"].state == "failure"
    assert statuses["security"].description == "blocked: scope (dirty)"
    assert statuses["evidence"].state == "success"
    assert statuses["verdict"].state == "failure" and "dirty" in statuses["verdict"].description
    assert statuses["ready"].state == "failure"
    assert statuses["regression"].description.startswith("no gate in this group")
    assert [s.context for s in evaluation_statuses([_summary("x", "ready")], prefix="bw")] == [
        *(f"bw/{g}" for g in GROUPS),
        "bw/verdict",
        "bw/ready",
    ]


@pytest.mark.parametrize(
    ("verdicts", "verdict_state", "ready_state"),
    [
        (("ready",), "success", "success"),
        (("ready", "conditional"), "success", "failure"),
        (("conditional", "not_ready"), "failure", "failure"),
    ],
)
def test_verdict_and_ready_let_a_repository_choose_whether_conditional_blocks(
    verdicts: tuple[str, ...], verdict_state: str, ready_state: str
) -> None:
    statuses = _by_context(
        evaluation_statuses(
            [_summary(f"s{i}", v) for i, v in enumerate(verdicts)], prefix="bellwether"
        )
    )
    assert statuses["verdict"].state == verdict_state
    assert statuses["ready"].state == ready_state


def test_descriptions_are_one_line_and_within_githubs_limit() -> None:
    hostile = "x\n" * 200 + "\x1b[31m"
    statuses = evaluation_statuses(
        [
            _summary(hostile, "not_ready", *(_gate(n, "block") for n in sorted(_GROUP_OF))),
            _summary("other", "not_ready", _gate("scope", "block")),
        ],
        prefix="bellwether",
    )
    for status in statuses:
        assert len(status.description) <= 140
        assert "\n" not in status.description and "\x1b" not in status.description


def test_no_evaluation_is_an_error_not_a_pass() -> None:
    with pytest.raises(BellwetherError):
        evaluation_statuses([], prefix="bellwether")


def test_a_uniform_state_covers_every_context() -> None:
    statuses = uniform_statuses("pending", "waiting", prefix="bellwether")
    assert {s.state for s in statuses} == {"pending"}
    assert len(statuses) == len(GROUPS) + 2


# ---------------------------------------------------------------------------
# Posting
# ---------------------------------------------------------------------------


class _Transport:
    def __init__(self, *responses: GitHubResponse) -> None:
        self.calls: list[tuple[str, str, Mapping[str, str], bytes | None]] = []
        self._responses = list(responses)

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> GitHubResponse:
        self.calls.append((method, url, headers, body))
        return self._responses.pop(0) if self._responses else GitHubResponse(201, b"{}")


def test_each_status_is_posted_to_the_commit_with_the_token_in_the_header_only() -> None:
    transport = _Transport()
    statuses = uniform_statuses("success", "ok", prefix="bellwether")
    posted = post_statuses(
        transport,
        "owner/repo",
        _SHA,
        statuses,
        token="secret-token",
        target_url="https://github.com/owner/repo/actions/runs/1",
    )
    assert posted == len(statuses) == len(transport.calls)
    for method, url, headers, body in transport.calls:
        assert method == "POST"
        assert url == f"https://api.github.com/repos/owner/repo/statuses/{_SHA}"
        assert headers["authorization"] == "Bearer secret-token"
        payload = json.loads(body or b"{}")
        assert set(payload) == {"state", "context", "description", "target_url"}
        assert "secret-token" not in url and "secret-token" not in (body or b"").decode()


def test_a_rejected_status_fails_loudly_naming_its_context() -> None:
    transport = _Transport(GitHubResponse(201, b"{}"), GitHubResponse(403, b'{"message":"no"}'))
    with pytest.raises(BellwetherError, match=r"bellwether/functional.*403"):
        post_statuses(
            transport,
            "owner/repo",
            _SHA,
            uniform_statuses("success", "ok", prefix="bellwether"),
            token="t",
        )


@pytest.mark.parametrize("bad", ["", "abc123", _SHA[:-1], _SHA + "\n", _SHA.upper(), "HEAD"])
def test_a_malformed_sha_is_refused(bad: str) -> None:
    with pytest.raises(BellwetherError, match="head SHA"):
        check_sha(bad)


def test_a_sha256_commit_id_is_accepted() -> None:
    assert check_sha("a" * 64) == "a" * 64


@pytest.mark.parametrize("repository", ["owner", "owner/repo/x", "../x/y", "o/r?x=1"])
def test_a_malformed_repository_is_refused(repository: str) -> None:
    with pytest.raises(BellwetherError):
        post_statuses(_Transport(), repository, _SHA, [], token="t")


def test_a_non_https_target_url_is_refused() -> None:
    with pytest.raises(BellwetherError, match="https"):
        post_statuses(_Transport(), "o/r", _SHA, [], token="t", target_url="http://x")


def test_the_run_url_comes_from_the_actions_environment() -> None:
    env = {
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "o/r",
        "GITHUB_RUN_ID": "42",
    }
    assert run_url(env) == "https://github.com/o/r/actions/runs/42"
    assert run_url({**env, "GITHUB_RUN_ID": "x"}) is None
    assert run_url({**env, "GITHUB_SERVER_URL": "http://evil"}) is None
    assert run_url({}) is None


# ---------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------


def test_dry_run_reads_the_committed_evaluations() -> None:
    result = runner.invoke(
        app,
        [
            "commit-status",
            str(_REPORTS / "demo-sneaky-exfiltrator"),
            str(_REPORTS / "demo-benign-note-taker"),
            "--dry-run",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    statuses = {s["context"]: s for s in json.loads(result.output)["statuses"]}
    assert statuses["bellwether/verdict"]["state"] == "failure"
    assert statuses["bellwether/security"]["state"] == "failure"
    assert statuses["bellwether/consistency"]["state"] == "success"


@pytest.mark.parametrize(
    ("args", "why"),
    [
        (["--dry-run"], "name the evaluation directories"),
        (["--state", "pending", "--dry-run"], "needs --reason"),
        (["--state", "error", "--reason", "x", "--dry-run"], "must be success, pending or failure"),
        (["--state", "success", "--reason", "x", "some/dir", "--dry-run"], "takes no evaluation"),
        (["/nonexistent", "--dry-run"], "cannot read"),
        (
            ["--context-prefix", "bad prefix", "--state", "success", "--reason", "x", "--dry-run"],
            "prefix",
        ),
        (["--sha", "HEAD", "--state", "success", "--reason", "x", "--dry-run"], "head SHA"),
        (["--state", "success", "--reason", "x"], "head SHA"),  # posting needs a SHA
    ],
)
def test_usage_problems_exit_three(args: list[str], why: str) -> None:
    result = runner.invoke(app, ["commit-status", *args])
    assert result.exit_code == ExitCode.INFRASTRUCTURE, result.output
    assert why in result.output


def test_posting_without_a_token_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    result = runner.invoke(
        app, ["commit-status", "--sha", _SHA, "--state", "success", "--reason", "x"]
    )
    assert result.exit_code == ExitCode.INFRASTRUCTURE and "no GitHub token" in result.output


# ---------------------------------------------------------------------------
# The static-scan comment
# ---------------------------------------------------------------------------


def _bot(body: str, comment_id: int = 5) -> dict[str, object]:
    return {"id": comment_id, "body": body, "user": {"type": "Bot"}}


def test_update_only_creates_nothing_when_no_comment_exists() -> None:
    transport = _Transport(GitHubResponse(200, b"[]"))
    action = upsert_pr_comment(
        transport, PrContext("o", "r", 1), "clean", key=STATIC_SCAN_KEY, token="t", update_only=True
    )
    assert action == "skipped"
    assert [method for method, *_ in transport.calls] == ["GET"]


def test_update_only_edits_the_existing_comment() -> None:
    from bellwether.cli.pr import marked_body

    existing = json.dumps([_bot(marked_body("red", STATIC_SCAN_KEY))]).encode()
    transport = _Transport(GitHubResponse(200, existing), GitHubResponse(200, b"{}"))
    action = upsert_pr_comment(
        transport, PrContext("o", "r", 1), "clean", key=STATIC_SCAN_KEY, token="t", update_only=True
    )
    assert action == "updated"
    assert [method for method, *_ in transport.calls] == ["GET", "PATCH"]


def test_the_static_key_cannot_equal_an_evaluations_key() -> None:
    for name in ("bellwether-static-scan/v1", "", "static", "bellwether-static"):
        for targets in ((), ("t",), ("api-loop-anthropic-frontier",)):
            assert report_key(name, list(targets)) != STATIC_SCAN_KEY


def test_pr_comment_recognises_the_scan_summary(tmp_path: Path) -> None:
    from bellwether.report import render_scan_markdown

    summary = tmp_path / "summary.md"
    summary.write_text(render_scan_markdown([]), encoding="utf-8")
    result = runner.invoke(app, ["pr-comment", str(summary), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert f"key={STATIC_SCAN_KEY}" in result.output
    # A file that is not a scan summary still needs the summary.json beside it.
    other = tmp_path / "other.md"
    other.write_text("hello\n", encoding="utf-8")
    assert runner.invoke(app, ["pr-comment", str(other), "--dry-run"]).exit_code == 3
