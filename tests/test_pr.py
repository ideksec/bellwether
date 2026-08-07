"""Posting the report onto a pull request (§18.2), offline through a fake transport.

The upsert has one job that must not regress: on a re-run it edits the comment a prior run
left instead of stacking a new one, and the token never leaves the auth header. Both are
pinned here without a network or a real token, the same seam the live model client uses.
"""

from __future__ import annotations

import json

import pytest

from bellwether.cli.pr import (
    COMMENT_MARKER,
    GitHubResponse,
    PrContext,
    find_existing_comment,
    marked_body,
    resolve_pr_context,
    upsert_pr_comment,
)
from bellwether.errors import BellwetherError

_CTX = PrContext(owner="octo", repo="skills", number=7)
_TOKEN = "ghs-secret-do-not-leak"  # a fake token for the leak-guard test


class _FakeGitHub:
    """Records every call and replays scripted responses (§24 offline discipline)."""

    def __init__(self, existing: list[dict[str, object]] | None = None) -> None:
        self.existing = existing or []
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(self, method, url, headers, body):  # type: ignore[no-untyped-def]
        self.calls.append((method, url, dict(headers), body))
        if method == "GET":
            return GitHubResponse(200, json.dumps(self.existing).encode("utf-8"))
        if method == "POST":
            return GitHubResponse(201, b'{"id": 999}')
        if method == "PATCH":
            return GitHubResponse(200, b'{"id": 111}')
        return GitHubResponse(500, b"unexpected")


# ---------------------------------------------------------------------------
# Marker and lookup
# ---------------------------------------------------------------------------


def test_marked_body_appends_the_marker_last() -> None:
    body = marked_body("## Verdict\n\nready\n")
    assert body.rstrip().endswith(COMMENT_MARKER)
    assert body.index("Verdict") < body.index(COMMENT_MARKER)


def test_find_existing_comment_matches_only_our_marker() -> None:
    comments = [
        {"id": 1, "body": "a human comment"},
        {"id": 2, "body": f"a prior report\n{COMMENT_MARKER}"},
    ]
    assert find_existing_comment(comments, COMMENT_MARKER) == 2
    assert find_existing_comment([{"id": 1, "body": "no marker"}], COMMENT_MARKER) is None


def test_find_existing_comment_ignores_malformed_entries() -> None:
    comments = [{"id": "not-int", "body": COMMENT_MARKER}, {"body": COMMENT_MARKER}]
    assert find_existing_comment(comments, COMMENT_MARKER) is None


# ---------------------------------------------------------------------------
# Upsert: create vs edit-in-place
# ---------------------------------------------------------------------------


def test_first_run_creates_a_comment() -> None:
    gh = _FakeGitHub(existing=[])
    action = upsert_pr_comment(gh, _CTX, "## report", token=_TOKEN)
    assert action == "created"
    methods = [call[0] for call in gh.calls]
    assert methods == ["GET", "POST"]
    post_url, post_body = gh.calls[1][1], gh.calls[1][3]
    assert post_url.endswith("/repos/octo/skills/issues/7/comments")
    assert post_body is not None and COMMENT_MARKER.encode() in post_body


def test_second_run_edits_the_same_comment() -> None:
    gh = _FakeGitHub(existing=[{"id": 111, "body": f"old report\n{COMMENT_MARKER}"}])
    action = upsert_pr_comment(gh, _CTX, "## fresh report", token=_TOKEN)
    assert action == "updated"
    assert [call[0] for call in gh.calls] == ["GET", "PATCH"]
    assert gh.calls[1][1].endswith("/repos/octo/skills/issues/comments/111")


def test_a_failed_post_raises_rather_than_reporting_success() -> None:
    class _Failing(_FakeGitHub):
        def __call__(self, method, url, headers, body):  # type: ignore[no-untyped-def]
            self.calls.append((method, url, dict(headers), body))
            if method == "GET":
                return GitHubResponse(200, b"[]")
            return GitHubResponse(403, b'{"message": "Resource not accessible"}')

    with pytest.raises(BellwetherError, match="HTTP 403"):
        upsert_pr_comment(_Failing(), _CTX, "## report", token=_TOKEN)


def test_the_token_travels_only_in_the_auth_header() -> None:
    """§3.3 reflex: a credential belongs in exactly one place. Assert it is in no URL and no
    request body, only the Authorization header."""
    gh = _FakeGitHub(existing=[])
    upsert_pr_comment(gh, _CTX, "## report", token=_TOKEN)
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
