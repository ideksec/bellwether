"""Posting the report onto a pull request (§18.2), offline through a fake transport.

The upsert has one job that must not regress: on a re-run it edits the comment a prior run
left instead of stacking a new one, and the token never leaves the auth header. Both are
pinned here without a network or a real token, the same seam the live model client uses.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from bellwether.cli.pr import (
    GitHubResponse,
    PrContext,
    comment_marker,
    find_existing_comment,
    marked_body,
    report_key,
    resolve_pr_context,
    upsert_pr_comment,
)
from bellwether.errors import BellwetherError

_CTX = PrContext(owner="octo", repo="skills", number=7)
_TOKEN = "ghs-secret-do-not-leak"  # a fake token for the leak-guard test
_BOT = {"login": "github-actions[bot]", "type": "Bot"}
_PERSON = {"login": "someone", "type": "User"}
_KEY = report_key("note-taker", ["api-loop-anthropic-haiku"])
_MARKER = comment_marker(_KEY)


class _FakeGitHub:
    """Records every call and replays scripted responses (§24 offline discipline)."""

    def __init__(
        self, existing: list[dict[str, object]] | None = None, *, write_status: int | None = None
    ) -> None:
        self.existing = existing or []
        #: Answer every POST/PATCH with this status instead of success — a refused write.
        self.write_status = write_status
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(self, method, url, headers, body):  # type: ignore[no-untyped-def]
        self.calls.append((method, url, dict(headers), body))
        if method == "GET":
            # Paginated as the real API is: 100 per page, ``page`` 1-based. A fake that returned
            # everything on every call could not express a prior report on page 2.
            query = parse_qs(urlsplit(url).query)
            page = int(query.get("page", ["1"])[0])
            batch = self.existing[(page - 1) * 100 : page * 100]
            return GitHubResponse(200, json.dumps(batch).encode("utf-8"))
        if self.write_status is not None and method in ("POST", "PATCH"):
            return GitHubResponse(self.write_status, b'{"message": "Resource not accessible"}')
        if method == "POST":
            return GitHubResponse(201, b'{"id": 999}')
        if method == "PATCH":
            return GitHubResponse(200, b'{"id": 111}')
        return GitHubResponse(500, b"unexpected")


# ---------------------------------------------------------------------------
# Marker and lookup
# ---------------------------------------------------------------------------


def test_marked_body_appends_the_marker_last() -> None:
    body = marked_body("## Verdict\n\nready\n", _KEY)
    assert body.rstrip().endswith(_MARKER)
    assert body.index("Verdict") < body.index(_MARKER)


def test_find_existing_comment_matches_only_our_marker() -> None:
    comments = [
        {"id": 1, "body": "a human comment"},
        {"id": 2, "body": f"a prior report\n{_MARKER}", "user": _BOT},
    ]
    assert find_existing_comment(comments, _MARKER) == 2
    assert find_existing_comment([{"id": 1, "body": "no marker"}], _MARKER) is None


def test_find_existing_comment_ignores_malformed_entries() -> None:
    comments = [
        {"id": "not-int", "body": _MARKER, "user": _BOT},
        {"body": _MARKER, "user": _BOT},
    ]
    assert find_existing_comment(comments, _MARKER) is None


# ---------------------------------------------------------------------------
# Upsert: create vs edit-in-place
# ---------------------------------------------------------------------------


def test_first_run_creates_a_comment() -> None:
    gh = _FakeGitHub(existing=[])
    action = upsert_pr_comment(gh, _CTX, "## report", key=_KEY, token=_TOKEN)
    assert action == "created"
    methods = [call[0] for call in gh.calls]
    assert methods == ["GET", "POST"]
    post_url, post_body = gh.calls[1][1], gh.calls[1][3]
    assert post_url.endswith("/repos/octo/skills/issues/7/comments")
    assert post_body is not None and _MARKER.encode() in post_body


def test_second_run_edits_the_same_comment() -> None:
    gh = _FakeGitHub(existing=[{"id": 111, "body": f"old report\n{_MARKER}", "user": _BOT}])
    action = upsert_pr_comment(gh, _CTX, "## fresh report", key=_KEY, token=_TOKEN)
    assert action == "updated"
    assert [call[0] for call in gh.calls] == ["GET", "PATCH"]
    assert gh.calls[1][1].endswith("/repos/octo/skills/issues/comments/111")


def test_a_failed_post_raises_rather_than_reporting_success() -> None:
    refused = _FakeGitHub(write_status=403)
    with pytest.raises(BellwetherError, match="HTTP 403"):
        upsert_pr_comment(refused, _CTX, "## report", key=_KEY, token=_TOKEN)
    assert [call[0] for call in refused.calls] == ["GET", "POST"]


def test_the_token_travels_only_in_the_auth_header() -> None:
    """§3.3 reflex: a credential belongs in exactly one place. Assert it is in no URL and no
    request body, only the Authorization header."""
    gh = _FakeGitHub(existing=[])
    upsert_pr_comment(gh, _CTX, "## report", key=_KEY, token=_TOKEN)
    for _method, url, headers, body in gh.calls:
        assert _TOKEN not in url
        assert body is None or _TOKEN.encode() not in body
        assert headers["authorization"] == f"Bearer {_TOKEN}"


# ---------------------------------------------------------------------------
# Resolving the PR from the CI environment
# ---------------------------------------------------------------------------


def test_context_from_github_actions_pull_request_event() -> None:
    ctx = resolve_pr_context(
        {"GITHUB_REPOSITORY": "octo/skills", "GITHUB_REF": "refs/pull/42/merge"}
    )
    assert ctx == PrContext("octo", "skills", 42)


def test_explicit_pr_number_overrides_the_ref() -> None:
    ctx = resolve_pr_context(
        {
            "GITHUB_REPOSITORY": "octo/skills",
            "GITHUB_REF": "refs/pull/42/merge",
            "BELLWETHER_PR_NUMBER": "99",
        }
    )
    assert ctx.number == 99


def test_missing_repository_is_a_clear_refusal() -> None:
    with pytest.raises(BellwetherError, match="GITHUB_REPOSITORY"):
        resolve_pr_context({"GITHUB_REF": "refs/pull/1/merge"})


def test_a_non_pr_ref_refuses_rather_than_guessing() -> None:
    with pytest.raises(BellwetherError, match="pull request number"):
        resolve_pr_context({"GITHUB_REPOSITORY": "octo/skills", "GITHUB_REF": "refs/heads/main"})


# ---------------------------------------------------------------------------
# Whose comment is ours
# ---------------------------------------------------------------------------


def test_a_marked_comment_a_person_posted_is_never_the_one_edited() -> None:
    """The marker is public text. A comment an outsider seeded with it was the one the workflow
    edited — a verdict its author could then rewrite, or a refused edit that posted nothing."""
    gh = _FakeGitHub(
        existing=[
            {"id": 5, "body": f"totally the report\n{_MARKER}", "user": _PERSON},
            {"id": 6, "body": f"the real prior report\n{_MARKER}", "user": _BOT},
        ]
    )
    assert upsert_pr_comment(gh, _CTX, "## report", key=_KEY, token=_TOKEN) == "updated"
    assert gh.calls[-1][1].endswith("/issues/comments/6")


def test_only_a_persons_marked_comment_means_a_fresh_report() -> None:
    gh = _FakeGitHub(existing=[{"id": 5, "body": _MARKER, "user": _PERSON}])
    assert upsert_pr_comment(gh, _CTX, "## report", key=_KEY, token=_TOKEN) == "created"
    assert "PATCH" not in [call[0] for call in gh.calls]


def test_a_prior_report_past_the_first_page_is_found() -> None:
    """Only page one was read, so a PR past 100 comments stacked a new report every run."""
    chatter = [{"id": n, "body": "lgtm", "user": _PERSON} for n in range(1, 151)]
    report = {"id": 999, "body": f"old report\n{_MARKER}", "user": _BOT}
    gh = _FakeGitHub(existing=[*chatter, report])
    assert upsert_pr_comment(gh, _CTX, "## report", key=_KEY, token=_TOKEN) == "updated"
    assert gh.calls[-1][1].endswith("/issues/comments/999")


# ---------------------------------------------------------------------------
# One comment per evaluation (PR #91)
# ---------------------------------------------------------------------------

_OTHER_KEY = report_key("note-taker", ["claude-code-anthropic-haiku"])


def test_each_evaluation_owns_its_own_comment() -> None:
    """PR #91: the api-loop and claude-code workflows evaluated the same skill, shared one
    marker, and the second verdict overwrote the first. Keyed by skill and targets, the second
    post finds no comment of its own and creates one; the first is left as it was."""
    first = {"id": 111, "body": marked_body("api-loop: ready", _KEY), "user": _BOT}
    gh = _FakeGitHub(existing=[first])
    assert upsert_pr_comment(gh, _CTX, "claude-code: ready", key=_OTHER_KEY, token=_TOKEN) == (
        "created"
    )
    assert [call[0] for call in gh.calls] == ["GET", "POST"]


def test_a_later_ready_cannot_replace_another_skills_not_ready() -> None:
    """The case that made one shared marker a security defect rather than a cosmetic one."""
    blocked = report_key("exfiltrator", ["api-loop-anthropic-haiku"])
    benign = report_key("note-taker", ["api-loop-anthropic-haiku"])
    assert blocked != benign
    existing = [{"id": 5, "body": marked_body("not_ready", blocked), "user": _BOT}]
    gh = _FakeGitHub(existing=existing)
    assert upsert_pr_comment(gh, _CTX, "ready", key=benign, token=_TOKEN) == "created"


def test_a_marker_quoted_inside_a_report_does_not_claim_the_comment() -> None:
    """Reports quote skill-chosen text raw inside code spans, and the key is only a hash of a
    skill name and its targets — anyone can compute another evaluation's marker. A report that
    carries it mid-body, with its own marker last, is not that evaluation's comment."""
    forged = marked_body(f"see `{comment_marker(_OTHER_KEY)}` here", _KEY)
    assert comment_marker(_OTHER_KEY) != _MARKER
    assert comment_marker(_OTHER_KEY) in forged
    comments = [{"id": 5, "body": forged, "user": _BOT}]
    assert find_existing_comment(comments, comment_marker(_OTHER_KEY)) is None
    assert find_existing_comment(comments, _MARKER) == 5


def test_the_key_is_order_free_and_carries_no_skill_text() -> None:
    assert report_key("s", ["b", "a"]) == report_key("s", ["a", "b"])
    hostile = report_key("x --><img src=x>", ["t"])
    marker = comment_marker(hostile)
    assert marker.count("-->") == 1 and marker.endswith("-->")
    assert "img" not in marker
    with pytest.raises(BellwetherError):
        comment_marker("x --> <b>")
