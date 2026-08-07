"""Posting a Bellwether report onto a pull request (§18.2).

`bellwether run` renders the PR comment into the artifact tree; this is the piece that puts
it on the pull request. It is deliberately thin and seamed the same way the live model
client is: the HTTP call is a ``transport`` argument, so the upsert logic — find our previous
comment, edit it in place or create a new one — is unit-tested without a network or a token,
and the real transport is a small urllib wrapper.

Two properties matter and are pinned by tests. First, **idempotence**: a hidden marker is
embedded in every comment we post, so a re-run on the same PR *edits* the prior comment
rather than stacking a new one under it every push — a wall of stale verdicts is worse than
one that keeps up. Second, **the token never travels anywhere but the Authorization header**:
it is read from the environment at the call site, put in one header, and never logged, never
placed in a URL, never returned.

The layer is ``cli`` rather than ``report`` on purpose: rendering belongs to ``report`` (and
this reuses :func:`~bellwether.report.render_pr_comment` unchanged), but *doing IO with a
remote service* is orchestration, which is what ``cli`` is for.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import NamedTuple

from bellwether.errors import BellwetherError

__all__ = [
    "COMMENT_MARKER",
    "GITHUB_API_ROOT",
    "GitHubResponse",
    "GitHubTransport",
    "PrContext",
    "find_existing_comment",
    "marked_body",
    "resolve_pr_context",
    "upsert_pr_comment",
]

#: The default GitHub REST root. Overridable for GitHub Enterprise, whose API lives under a
#: different host — an endpoint, not a secret, so it is a plain argument.
GITHUB_API_ROOT = "https://api.github.com"

#: An HTML comment is invisible in the rendered PR but present in the raw body, so we can
#: recognise our own comment on a later run and edit it. Stable forever: changing it would
#: orphan every comment already posted and start stacking again.
COMMENT_MARKER = "<!-- bellwether-report: do not edit; this comment is updated in place -->"


class GitHubResponse(NamedTuple):
    """The minimum of a GitHub API response the poster reads: status and raw body."""

    status: int
    body: bytes


#: The transport seam: ``(method, url, headers, body) -> GitHubResponse``. Injected so the
#: upsert is tested with a fake and the real one is a thin urllib call.
GitHubTransport = Callable[[str, str, Mapping[str, str], bytes | None], GitHubResponse]


class PrContext(NamedTuple):
    """Which pull request to comment on: ``owner/repo`` split out, and the PR number."""

    owner: str
    repo: str
    number: int

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


def marked_body(comment: str) -> str:
    """Append the idempotence marker to a rendered comment (§18.2).

    The marker goes last, on its own line, so it never disturbs the rendered content and a
    reader viewing the raw body sees the rendered report first.
    """
    return f"{comment.rstrip()}\n\n{COMMENT_MARKER}\n"


def find_existing_comment(comments: list[Mapping[str, object]], marker: str) -> int | None:
    """The id of the first comment carrying ``marker``, or None.

    Comments come back oldest-first; we take the first match so re-runs converge on one
    comment even in the unlikely case two ever existed.
    """
    for comment in comments:
        body = comment.get("body")
        comment_id = comment.get("id")
        if isinstance(body, str) and marker in body and isinstance(comment_id, int):
            return comment_id
    return None


def _auth_headers(token: str) -> dict[str, str]:
    """The headers every call carries. The token appears here and nowhere else."""
    return {
        "authorization": f"Bearer {token}",
        "accept": "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "content-type": "application/json",
        "user-agent": "bellwether",
    }


def _decode_comments(response: GitHubResponse) -> list[Mapping[str, object]]:
    if response.status != 200:
        raise BellwetherError(
            f"listing PR comments failed with HTTP {response.status}: "
            f"{response.body[:300].decode('utf-8', 'replace')}"
        )
    payload = json.loads(response.body or b"[]")
    if not isinstance(payload, list):
        raise BellwetherError("GitHub returned a non-list body when listing PR comments")
    return [item for item in payload if isinstance(item, Mapping)]


def upsert_pr_comment(
    transport: GitHubTransport,
    context: PrContext,
    comment: str,
    *,
    token: str,
    api_root: str = GITHUB_API_ROOT,
) -> str:
    """Create the report comment, or edit the one a prior run left, and say which (§18.2).

    Returns ``"created"`` or ``"updated"``. Raises :class:`BellwetherError` on any non-success
    status, with the body excerpt, so a CI step fails loudly rather than reporting a phantom
    success. The token is passed to :func:`_auth_headers` and never otherwise handled here.
    """
    root = api_root.rstrip("/")
    headers = _auth_headers(token)
    body = marked_body(comment)

    list_url = f"{root}/repos/{context.slug}/issues/{context.number}/comments?per_page=100"
    existing = find_existing_comment(
        _decode_comments(transport("GET", list_url, headers, None)), COMMENT_MARKER
    )

    payload = json.dumps({"body": body}).encode("utf-8")
    if existing is not None:
        url = f"{root}/repos/{context.slug}/issues/comments/{existing}"
        response = transport("PATCH", url, headers, payload)
        action = "updated"
    else:
        url = f"{root}/repos/{context.slug}/issues/{context.number}/comments"
        response = transport("POST", url, headers, payload)
        action = "created"

    if response.status not in (200, 201):
        raise BellwetherError(
            f"posting the PR comment failed with HTTP {response.status}: "
            f"{response.body[:300].decode('utf-8', 'replace')}"
        )
    return action


def resolve_pr_context(environ: Mapping[str, str]) -> PrContext:
    """Work out the target PR from the GitHub Actions environment (§18.2).

    ``GITHUB_REPOSITORY`` is ``owner/repo``; the PR number is read from
    ``BELLWETHER_PR_NUMBER`` if set (the explicit override a caller can pass), else parsed from
    ``GITHUB_REF`` (``refs/pull/<n>/merge`` on a ``pull_request`` event). A missing or
    non-PR context is a clear refusal, not a guess — commenting on the wrong issue is worse
    than not commenting.
    """
    repository = environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repository:
        raise BellwetherError(
            "GITHUB_REPOSITORY is unset or malformed (expected 'owner/repo'); this command "
            "expects the GitHub Actions environment, or --repo and --pr passed explicitly"
        )
    owner, repo = repository.split("/", 1)

    number = _pr_number(environ)
    if number is None:
        raise BellwetherError(
            "could not determine the pull request number: set BELLWETHER_PR_NUMBER, or run on "
            "a pull_request event where GITHUB_REF looks like 'refs/pull/<n>/merge'"
        )
    return PrContext(owner=owner, repo=repo, number=number)


def _pr_number(environ: Mapping[str, str]) -> int | None:
    explicit = environ.get("BELLWETHER_PR_NUMBER", "").strip()
    if explicit:
        try:
            return int(explicit)
        except ValueError:
            raise BellwetherError(f"BELLWETHER_PR_NUMBER is not an integer: {explicit!r}") from None

    ref = environ.get("GITHUB_REF", "")
    parts = ref.split("/")
    if len(parts) >= 3 and parts[0] == "refs" and parts[1] == "pull":
        try:
            return int(parts[2])
        except ValueError:
            return None
    return None


def github_transport(timeout: float = 30.0) -> GitHubTransport:
    """The real transport: a urllib call that returns the status instead of raising on 4xx.

    Kept a factory so the timeout is bound once and the call site stays a plain
    :data:`GitHubTransport`. An HTTP error status is *returned*, so the upsert maps it to a
    :class:`BellwetherError` with context rather than an opaque ``HTTPError``.
    """
    import urllib.error
    import urllib.request

    def call(
        method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> GitHubResponse:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return GitHubResponse(int(response.status), response.read())
        except urllib.error.HTTPError as error:
            return GitHubResponse(int(error.code), error.read())

    return call
