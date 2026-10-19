"""Run a GitHub Actions job's own steps, locally, the way the runner would (§18).

Linting a workflow says it parses; it does not say it works. Every defect this project's CI
has had looked clean on the page, and the Gate 0 workflow's first execution here found a
``bash -e`` abort that two linters passed. So the workflow tests execute the YAML:

* each step's ``run:`` script, under the runner's own shell (``bash --noprofile --norc -eo
  pipefail``), in a real git repository, with ``GITHUB_OUTPUT`` / ``GITHUB_STEP_SUMMARY`` files;
* each step's ``if:`` and every ``${{ … }}`` evaluated by a small evaluator of the expression
  language the workflows use (contexts, ``!``, ``&&``, ``||``, ``==``, ``!=``, ``contains``,
  ``always``, ``success``, ``failure``), against the outputs earlier steps wrote — a step whose
  condition names a misspelled output is skipped here exactly as on GitHub;
* ``uses:`` steps are evaluated for whether they would run, and recorded, not run;
* GitHub's REST API is a local :class:`FakeGitHub` that records comments and statuses and
  rejects a call without the expected token.

Substitutions are explicit and per test (``uv run bellwether`` → this venv's binary behind a
wrapper that points ``pr-comment``/``commit-status`` at the fake API, for instance), so a
reader can see exactly what is real.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

FAKE_TOKEN = "ghs_fake-token-for-the-workflow-harness"

# ---------------------------------------------------------------------------
# A fake GitHub REST API
# ---------------------------------------------------------------------------


@dataclass
class FakeGitHub:
    """Issue comments, commit statuses, pull requests and Actions artifacts, in memory, over
    real HTTP on localhost.

    Artifact downloads behave as GitHub's do: the API answers ``/actions/artifacts/{id}/zip``
    with a 302 to a storage URL on a *different path* (here ``/blob/{id}``), and the storage
    URL counts every request that arrives carrying an ``authorization`` header in
    :attr:`blob_auth` — a client that follows the redirect with its headers sends the
    repository token to the storage host.
    """

    comments: list[dict[str, Any]] = field(default_factory=list)
    statuses: list[dict[str, Any]] = field(default_factory=list)
    requests: list[tuple[str, str]] = field(default_factory=list)
    unauthorised: int = 0
    #: merge commit SHA → the pull request ``/commits/{sha}/pulls`` lists for it.
    commit_pulls: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    #: Workflow runs: each ``{"id", "workflow", "head_sha"}``.
    runs: list[dict[str, Any]] = field(default_factory=list)
    #: run id → its artifacts, each ``{"id", "name", "expired"}``.
    artifacts: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    #: artifact id → the zip bytes the storage URL serves.
    blobs: dict[int, bytes] = field(default_factory=dict)
    blob_auth: int = 0
    #: Pull requests opened or updated through ``/pulls``.
    pulls: list[dict[str, Any]] = field(default_factory=list)
    #: The status ``POST /pulls`` answers with when not 201 (a repository that does not let
    #: Actions open pull requests answers 403).
    create_pull_status: int = 201
    #: Issues opened or edited through ``/issues`` (not pull requests), each with its number,
    #: state, body and author; comments on them land in :attr:`comments` with ``issue`` set.
    issues: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # silence the test output
                return

            def _authorised(self) -> bool:
                if self.headers.get("authorization") != f"Bearer {FAKE_TOKEN}":
                    fake.unauthorised += 1
                    self._send(401, {"message": "Bad credentials"})
                    return False
                return True

            def _send(self, status: int, payload: object) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> dict[str, Any]:
                length = int(self.headers.get("content-length", "0"))
                return json.loads(self.rfile.read(length) or b"{}")  # type: ignore[no-any-return]

            def do_GET(self) -> None:
                fake.requests.append(("GET", self.path))
                if blob := re.fullmatch(r"/blob/(\d+)", self.path):
                    if self.headers.get("authorization") is not None:
                        fake.blob_auth += 1
                    data = fake.blobs.get(int(blob.group(1)))
                    if data is None:
                        self._send(404, {"message": "Not Found"})
                        return
                    self.send_response(200)
                    self.send_header("content-type", "application/zip")
                    self.send_header("content-length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if not self._authorised():
                    return
                path, _, query = self.path.partition("?")
                params = dict(urllib.parse.parse_qsl(query))
                if re.match(r"/repos/[^/]+/[^/]+/issues/\d+/comments", path):
                    page = int(params.get("page", "1"))
                    self._send(200, fake.comments if page == 1 else [])
                elif re.fullmatch(r"/repos/[^/]+/[^/]+/issues", path):
                    page, per_page = int(params.get("page", "1")), int(params.get("per_page", "30"))
                    state = params.get("state", "open")
                    listed = [i for i in fake.issues if state == "all" or i["state"] == state]
                    self._send(200, listed[(page - 1) * per_page : page * per_page])
                elif match := re.fullmatch(r"/repos/[^/]+/[^/]+/commits/([0-9a-f]+)/pulls", path):
                    self._send(200, fake.commit_pulls.get(match.group(1), []))
                elif match := re.fullmatch(
                    r"/repos/[^/]+/[^/]+/actions/workflows/([^/]+)/runs", path
                ):
                    runs = [
                        run
                        for run in fake.runs
                        if run["workflow"] == match.group(1)
                        and run["head_sha"] == params.get("head_sha")
                    ]
                    self._send(200, {"total_count": len(runs), "workflow_runs": runs})
                elif match := re.fullmatch(
                    r"/repos/[^/]+/[^/]+/actions/runs/(\d+)/artifacts", path
                ):
                    found = [
                        artifact
                        for artifact in fake.artifacts.get(int(match.group(1)), [])
                        if "name" not in params or artifact["name"] == params["name"]
                    ]
                    self._send(200, {"total_count": len(found), "artifacts": found})
                elif match := re.fullmatch(r"/repos/[^/]+/[^/]+/actions/artifacts/(\d+)/zip", path):
                    self.send_response(302)
                    self.send_header("location", f"{fake.url}/blob/{match.group(1)}")
                    self.send_header("content-length", "0")
                    self.end_headers()
                elif re.fullmatch(r"/repos/[^/]+/[^/]+/pulls", path):
                    head = params.get("head", "")
                    open_pulls = [
                        pull
                        for pull in fake.pulls
                        if f"owner:{pull['head']}" == head and pull["state"] == "open"
                    ]
                    self._send(200, open_pulls)
                else:
                    self._send(404, {"message": "Not Found"})

            def do_POST(self) -> None:
                fake.requests.append(("POST", self.path))
                if not self._authorised():
                    return
                body = self._body()
                if on := re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)/comments", self.path):
                    comment = {
                        "id": 1000 + len(fake.comments),
                        "issue": int(on.group(1)),
                        "body": body["body"],
                        "user": {"login": "github-actions[bot]", "type": "Bot"},
                    }
                    fake.comments.append(comment)
                    self._send(201, comment)
                elif match := re.fullmatch(r"/repos/[^/]+/[^/]+/statuses/([0-9a-f]+)", self.path):
                    fake.statuses.append({**body, "sha": match.group(1)})
                    self._send(201, body)
                elif re.fullmatch(r"/repos/[^/]+/[^/]+/issues", self.path):
                    issue = {
                        "number": 900 + len(fake.issues),
                        "title": body["title"],
                        "body": body["body"],
                        "state": "open",
                        "user": {"login": "github-actions[bot]", "type": "Bot"},
                    }
                    fake.issues.append(issue)
                    self._send(201, issue)
                elif re.fullmatch(r"/repos/[^/]+/[^/]+/pulls", self.path):
                    if fake.create_pull_status != 201:
                        self._send(
                            fake.create_pull_status,
                            {
                                "message": "GitHub Actions is not permitted to create or approve "
                                "pull requests."
                            },
                        )
                        return
                    number = 500 + len(fake.pulls)
                    pull = {
                        **body,
                        "number": number,
                        "state": "open",
                        "html_url": f"https://github.com/owner/repo/pull/{number}",
                    }
                    fake.pulls.append(pull)
                    self._send(201, pull)
                else:
                    self._send(404, {"message": "Not Found"})

            def do_PATCH(self) -> None:
                fake.requests.append(("PATCH", self.path))
                if not self._authorised():
                    return
                if pulled := re.fullmatch(r"/repos/[^/]+/[^/]+/pulls/(\d+)", self.path):
                    pull = next(
                        (p for p in fake.pulls if p["number"] == int(pulled.group(1))), None
                    )
                    if pull is None:
                        self._send(404, {"message": "Not Found"})
                        return
                    pull.update(self._body())
                    self._send(200, pull)
                    return
                if edited := re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)", self.path):
                    issue = next(
                        (i for i in fake.issues if i["number"] == int(edited.group(1))), None
                    )
                    if issue is None:
                        self._send(404, {"message": "Not Found"})
                        return
                    issue.update(self._body())
                    self._send(200, issue)
                    return
                match = re.fullmatch(r"/repos/[^/]+/[^/]+/issues/comments/(\d+)", self.path)
                comment = next(
                    (c for c in fake.comments if match and c["id"] == int(match.group(1))), None
                )
                if comment is None:
                    self._send(404, {"message": "Not Found"})
                    return
                comment["body"] = self._body()["body"]
                self._send(200, comment)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        port = self._server.server_address[1]
        return f"http://127.0.0.1:{port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def latest_statuses(self) -> dict[str, dict[str, Any]]:
        """Context → the last status posted for it, as GitHub shows a commit's state."""
        return {status["context"]: status for status in self.statuses}


# ---------------------------------------------------------------------------
# The expression language
# ---------------------------------------------------------------------------

_TOKEN = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<op>&&|\|\||==|!=|!|\(|\)|,)"
    r"|(?P<num>\d+)|(?P<name>[A-Za-z_][\w.*-]*))"
)


@dataclass
class Event:
    """The parts of the ``github`` context the workflows read."""

    name: str = "pull_request"
    labels: Sequence[str] = ()
    fork: bool = False
    head_sha: str = "a" * 40
    #: ``github.sha`` — on a ``pull_request`` event, the synthetic *merge* commit, which is not
    #: the head: a status posted on it never appears on the pull request.
    merge_sha: str = "b" * 40
    base_sha: str = ""
    pr_number: int = 7
    action: str = "synchronize"
    label: str = ""
    #: ``inputs.*`` of a ``workflow_dispatch``; every other input reads as "".
    inputs: Mapping[str, str] = field(default_factory=dict)
    #: ``vars.*``, the repository's configuration variables; an unset one reads as "".
    vars: Mapping[str, str] = field(default_factory=dict)
    ref_name: str = "main"


class _Expression:
    def __init__(self, contexts: Mapping[str, object], status: Mapping[str, bool]) -> None:
        self.contexts = contexts
        self.status = status

    def python(self, text: str) -> str:
        out: list[str] = []
        position = 0
        text = text.strip()
        while position < len(text):
            match = _TOKEN.match(text, position)
            if match is None or match.end() == position:
                raise ValueError(f"cannot read expression at {text[position:]!r}")
            position = match.end()
            if match.group("str") is not None:
                out.append(repr(match.group("str")[1:-1].replace("''", "'")))
            elif (op := match.group("op")) is not None:
                out.append({"&&": " and ", "||": " or ", "!": " not "}.get(op, f" {op} "))
            elif match.group("num") is not None:
                out.append(match.group("num"))
            else:
                name = match.group("name")
                following = text[position:].lstrip()
                if following.startswith("("):
                    if name not in ("contains", "always", "success", "failure"):
                        raise ValueError(f"unsupported function {name}()")
                    out.append(f"_{name}")
                else:
                    out.append(repr(self.lookup(name)))
        return "".join(out)

    def lookup(self, name: str) -> object:
        if name in ("true", "false"):
            return name == "true"
        value = self.contexts.get(name)
        if value is None and name.startswith(("steps.", "secrets.", "env.", "inputs.", "vars.")):
            return ""
        if value is None:
            raise KeyError(f"the harness does not model the context {name!r}")
        return value

    def evaluate(self, text: str) -> object:
        def contains(haystack: object, needle: object) -> bool:
            if isinstance(haystack, (list, tuple)):
                return needle in haystack
            return str(needle).lower() in str(haystack).lower()

        namespace = {
            "_contains": contains,
            "_always": lambda: True,
            "_success": lambda: not self.status["failed"],
            "_failure": lambda: self.status["failed"],
        }
        return eval(self.python(text), {"__builtins__": {}}, namespace)


def _parse_output_file(path: Path) -> dict[str, str]:
    """``GITHUB_OUTPUT``: ``key=value`` lines and ``key<<DELIM`` … ``DELIM`` blocks."""
    values: dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            key, delimiter = line.split("<<", 1)
            block: list[str] = []
            while index < len(lines) and lines[index] != delimiter:
                block.append(lines[index])
                index += 1
            index += 1
            values[key] = "\n".join(block)
        elif "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


@dataclass
class StepResult:
    name: str
    ran: bool
    returncode: int = 0
    output: str = ""


class WorkflowRunner:
    """Run one job of a workflow file in ``repo``, step by step."""

    def __init__(
        self,
        workflow: Path,
        job: str,
        repo: Path,
        tmp: Path,
        *,
        event: Event,
        api: FakeGitHub | None = None,
        secrets: Mapping[str, str] | None = None,
        substitutions: Sequence[tuple[str, str]] = (),
        skip: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
    ) -> None:
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        self.workflow_env = {k: str(v) for k, v in (document.get("env") or {}).items()}
        self.steps: list[dict[str, Any]] = list(document["jobs"][job]["steps"])
        self.job_if: str | None = document["jobs"][job].get("if")
        self.repo = repo
        self.tmp = tmp
        self.event = event
        self.api = api
        self.secrets = dict(secrets or {})
        self.substitutions = list(substitutions)
        self.skip = set(skip)
        self.extra_env = dict(env or {})
        self.outputs: dict[str, dict[str, str]] = {}
        self.results: list[StepResult] = []
        self.status = {"failed": False}
        self.summary = tmp / "step_summary.md"
        self.summary.write_text("", encoding="utf-8")

    # -- contexts --------------------------------------------------------------------------

    def _contexts(self) -> dict[str, object]:
        event = self.event
        head = "fork/repo" if event.fork else "owner/repo"
        contexts: dict[str, object] = {
            "github.event_name": event.name,
            "github.repository": "owner/repo",
            "github.token": FAKE_TOKEN,
            "github.sha": event.merge_sha,
            "github.event.action": event.action,
            "github.event.label.name": event.label,
            "github.event.pull_request.head.repo.full_name": head,
            "github.event.pull_request.head.sha": event.head_sha,
            "github.event.pull_request.base.sha": event.base_sha,
            "github.event.pull_request.labels.*.name": list(event.labels),
        }
        for step, values in self.outputs.items():
            for key, value in values.items():
                contexts[f"steps.{step}.outputs.{key}"] = value
        for key, value in self.secrets.items():
            contexts[f"secrets.{key}"] = value
        for key, value in event.inputs.items():
            contexts[f"inputs.{key}"] = value
        for key, value in event.vars.items():
            contexts[f"vars.{key}"] = value
        return contexts

    def _expression(self) -> _Expression:
        return _Expression(self._contexts(), self.status)

    def interpolate(self, text: str) -> str:
        expression = self._expression()

        def render(value: object) -> str:
            # GitHub renders a boolean as `true`/`false`, never Python's `True`.
            return str(value).lower() if isinstance(value, bool) else str(value)

        return re.sub(
            r"\$\{\{\s*(.*?)\s*\}\}", lambda m: render(expression.evaluate(m.group(1))), text
        )

    def should_run(self, step: Mapping[str, Any]) -> bool:
        condition = step.get("if")
        if condition is None:
            return not self.status["failed"]
        text = str(condition).strip()
        if text.startswith("${{") and text.endswith("}}"):
            text = text[3:-2]
        has_status = re.search(r"\b(always|success|failure)\(", text)
        if not has_status and self.status["failed"]:
            return False
        return bool(self._expression().evaluate(text))

    # -- execution -------------------------------------------------------------------------

    def job_runs(self) -> bool:
        """The job's own ``if:`` — evaluated as GitHub does, before any step."""
        if self.job_if is None:
            return True
        return bool(self._expression().evaluate(str(self.job_if)))

    def run(self) -> list[StepResult]:
        if not self.job_runs():
            self.results = [
                StepResult(str(s.get("name", s.get("uses", "?"))), False) for s in self.steps
            ]
            return self.results
        for step in self.steps:
            name = str(step.get("name", step.get("uses", "?")))
            if name in self.skip or not self.should_run(step):
                self.results.append(StepResult(name, ran=False))
                continue
            if "uses" in step:
                self.results.append(StepResult(name, ran=True))
                continue
            script = self.interpolate(str(step["run"]))
            for old, new in self.substitutions:
                script = script.replace(old, new)
            output = self.tmp / "github_output"
            output.write_text("", encoding="utf-8")
            step_env = {k: self.interpolate(str(v)) for k, v in (step.get("env") or {}).items()}
            environment = {
                **os.environ,
                **self.workflow_env,
                **self.extra_env,
                **step_env,
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(self.summary),
                "GITHUB_WORKSPACE": str(self.repo),
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_EVENT_NAME": self.event.name,
                "GITHUB_SHA": self.event.merge_sha,
                "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_REF": (
                    f"refs/pull/{self.event.pr_number}/merge"
                    if self.event.name == "pull_request"
                    else f"refs/heads/{self.event.ref_name}"
                ),
                "GITHUB_REF_NAME": (
                    f"{self.event.pr_number}/merge"
                    if self.event.name == "pull_request"
                    else self.event.ref_name
                ),
            }
            completed = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                cwd=self.repo,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            if "id" in step:
                self.outputs[str(step["id"])] = _parse_output_file(output)
            self.results.append(
                StepResult(name, True, completed.returncode, completed.stdout + completed.stderr)
            )
            if completed.returncode != 0:
                self.status["failed"] = True
        return self.results

    def ran(self) -> list[str]:
        return [result.name for result in self.results if result.ran]

    def result(self, name: str) -> StepResult:
        return next(result for result in self.results if result.name == name)

    @property
    def failed(self) -> bool:
        return bool(self.status["failed"])


def bellwether_wrapper(tmp: Path, bellwether: str, api: FakeGitHub) -> Path:
    """A ``bellwether`` that sends ``pr-comment`` and ``commit-status`` to the fake API."""
    wrapper = tmp / "bellwether-wrapper"
    wrapper.write_text(
        "#!/bin/bash\n"
        'cmd="$1"; shift\n'
        'case "$cmd" in\n'
        f'  pr-comment|commit-status|drift) exec "{bellwether}" "$cmd" --api-root "{api.url}" "$@" ;;\n'
        "  baseline)\n"
        '    sub="$1"; shift\n'
        '    case "$sub" in\n'
        f'      fetch|open-pr) exec "{bellwether}" baseline "$sub" --api-root "{api.url}" "$@" ;;\n'
        f'      *) exec "{bellwether}" baseline "$sub" "$@" ;;\n'
        "    esac ;;\n"
        f'  *) exec "{bellwether}" "$cmd" "$@" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return wrapper


def git_repo(path: Path) -> str:
    """Initialise and commit everything under ``path``; the commit's SHA."""

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(path), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "-q")
    git("add", "-A")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "fixture")
    return git("rev-parse", "HEAD")
