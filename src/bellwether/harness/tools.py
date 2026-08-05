"""The api-loop tool set: read, write, bash, fetch (§9.4).

Bellwether implements these itself, which is what gives ``api-loop`` its uncontestable
observability — and every one of them executes **inside the container**, through an
injected exec runner. That placement is load-bearing twice over:

- **Containment is the sandbox's, not the tool's.** Path resolution happens in the
  container's mount namespace, so a symlink planted by a skill resolves against the
  container's filesystem and stays inside it. A host-side implementation that resolved
  paths on the host would turn the read tool into a sandbox escape one ``ln -s`` away.
- **The tools impose no policy.** Reading ``/etc/passwd`` inside the container is
  permitted and *recorded*; whether it exceeded declared scope is the assertion
  engine's judgment (§12), not the tool's. A tool that silently refused would hide
  exactly the behaviour the capture planes exist to observe.

``fetch`` is the exception: it is refused, with the reason in the result the model
sees. The sandbox has no egress path until the recording proxy (WP-13) carries one, and
an unobserved network tool would be the §10.5.3 hole implemented on purpose. The
attempt itself is still evidence — it flows through ``tool_call``/``tool_result``
events like every other call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from bellwether.determinism import stable_hash
from bellwether.sandbox import DockerBackend, PreparedSandbox

__all__ = [
    "ExecResult",
    "SandboxExec",
    "SandboxToolset",
    "ToolOutcome",
    "docker_exec_runner",
]

#: Characters of tool output returned to the model. The full output's digest is always
#: recorded, so truncation loses fidelity in the conversation, never in the evidence.
_MAX_OUTPUT_CHARS = 16_384

#: Per-tool-call timeout. Distinct from the run's wall clock: one hung command must
#: surface as a failed tool call the model can react to, not consume the whole run.
_TOOL_TIMEOUT_SECONDS = 120.0


@dataclass(frozen=True)
class ExecResult:
    """What one in-container execution produced."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class SandboxExec(Protocol):
    """Runs one argv inside the sandbox container.

    Implemented by the Docker backend as ``docker exec`` against the run's persistent
    container; implemented by tests as a plain function. The toolset never learns which.
    """

    def __call__(
        self, argv: list[str], *, stdin: str | None = None, timeout: float
    ) -> ExecResult: ...


@dataclass(frozen=True)
class ToolOutcome:
    """What a tool call produced, in both fidelities.

    ``output`` is what the model sees, truncated at the cap. ``output_digest`` is the
    hash of the *untruncated* output, so the trace can bind the full result even where
    the conversation carried an abbreviation (§11.2 ``result_digest``).
    """

    ok: bool
    output: str
    output_digest: str
    error: str | None = None
    truncated: bool = False


class SandboxToolset:
    """The fixed tool set, dispatching into the sandbox."""

    def __init__(
        self,
        exec_runner: SandboxExec,
        *,
        max_output_chars: int = _MAX_OUTPUT_CHARS,
        tool_timeout: float = _TOOL_TIMEOUT_SECONDS,
    ) -> None:
        self._exec = exec_runner
        self._max_output_chars = max_output_chars
        self._timeout = tool_timeout

    @staticmethod
    def specs() -> tuple[dict[str, Any], ...]:
        """The tool declarations offered to the model, in fixed order (§24 determinism).

        Returned as provider-neutral dicts; the adapter wraps them into
        :class:`~bellwether.harness.provider.ToolSpec`.
        """
        return (
            {
                "name": "read",
                "description": "Read a file. Paths resolve inside the workspace container; "
                "relative paths resolve against the workspace root.",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
            {
                "name": "write",
                "description": "Write content to a file, creating parent directories. "
                "Relative paths resolve against the workspace root.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                },
            },
            {
                "name": "bash",
                "description": "Run a shell command in the workspace.",
                "input_schema": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            },
            {
                "name": "fetch",
                "description": "Fetch a URL. Network access is disabled in this "
                "environment; calls are recorded and refused.",
                "input_schema": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            },
        )

    def execute(self, name: str, tool_input: dict[str, Any]) -> ToolOutcome:
        if name == "read":
            return self._read(tool_input)
        if name == "write":
            return self._write(tool_input)
        if name == "bash":
            return self._bash(tool_input)
        if name == "fetch":
            return self._fetch(tool_input)
        return _error(f"unknown tool: {name!r}")

    # -- individual tools ---------------------------------------------------

    def _read(self, tool_input: dict[str, Any]) -> ToolOutcome:
        path = _required_str(tool_input, "path")
        if path is None:
            return _error("read requires a 'path' string")
        return self._finish(self._exec(["cat", "--", path], timeout=self._timeout))

    def _write(self, tool_input: dict[str, Any]) -> ToolOutcome:
        path = _required_str(tool_input, "path")
        content = tool_input.get("content")
        if path is None or not isinstance(content, str):
            return _error("write requires 'path' and 'content' strings")
        result = self._exec(
            [
                "sh",
                "-c",
                'mkdir -p -- "$(dirname -- "$1")" && cat > "$1"',
                "sh",
                path,
            ],
            stdin=content,
            timeout=self._timeout,
        )
        if result.exit_code == 0 and not result.timed_out:
            confirmation = f"wrote {len(content.encode('utf-8'))} bytes to {path}"
            return ToolOutcome(ok=True, output=confirmation, output_digest=stable_hash(content))
        return self._finish(result)

    def _bash(self, tool_input: dict[str, Any]) -> ToolOutcome:
        command = _required_str(tool_input, "command")
        if command is None:
            return _error("bash requires a 'command' string")
        return self._finish(self._exec(["sh", "-c", command], timeout=self._timeout))

    def _fetch(self, tool_input: dict[str, Any]) -> ToolOutcome:
        url = _required_str(tool_input, "url")
        if url is None:
            return _error("fetch requires a 'url' string")
        return _error(
            f"network access is disabled in this environment; the request to {url} "
            "was recorded and not sent"
        )

    # -- shared -------------------------------------------------------------

    def _finish(self, result: ExecResult) -> ToolOutcome:
        """Shape an exec result for the model, keeping full fidelity in the digest."""
        if result.timed_out:
            return _error(f"the command did not finish within {self._timeout:.0f}s")

        full = result.stdout if result.exit_code == 0 else _failure_text(result)
        digest = stable_hash(full)
        truncated = len(full) > self._max_output_chars
        shown = full[: self._max_output_chars]
        if truncated:
            shown += f"\n[output truncated at {self._max_output_chars} characters]"
        if result.exit_code == 0:
            return ToolOutcome(ok=True, output=shown, output_digest=digest, truncated=truncated)
        return ToolOutcome(
            ok=False,
            output=shown,
            output_digest=digest,
            error=f"exit code {result.exit_code}",
            truncated=truncated,
        )


def _failure_text(result: ExecResult) -> str:
    parts = [f"exit code {result.exit_code}"]
    if result.stdout:
        parts.append(f"stdout:\n{result.stdout}")
    if result.stderr:
        parts.append(f"stderr:\n{result.stderr}")
    return "\n".join(parts)


def _required_str(tool_input: dict[str, Any], key: str) -> str | None:
    value = tool_input.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _error(message: str) -> ToolOutcome:
    return ToolOutcome(ok=False, output=message, output_digest=stable_hash(message), error=message)


def docker_exec_runner(backend: DockerBackend, prepared: PreparedSandbox) -> SandboxExec:
    """Bind the toolset to a run's persistent container.

    The returned runner is the whole coupling between the tool layer and the sandbox
    backend: every tool call becomes one ``docker exec`` against the container
    ``start_persistent`` opened, with the workspace root as its working directory.
    """

    def run(argv: list[str], *, stdin: str | None = None, timeout: float) -> ExecResult:
        result = backend.exec_in(prepared, argv, stdin=stdin, timeout=timeout)
        return ExecResult(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    return run
