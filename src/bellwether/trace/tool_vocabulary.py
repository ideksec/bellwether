"""The harness tool vocabularies the normalizer understands (§11.2, §11.4).

Every harness names its tools its own way. The ``api-loop`` adapter implements ``read`` /
``write`` / ``bash`` / ``fetch`` with a ``path`` argument; the Claude Code CLI exposes
``Read`` / ``Write`` / ``Edit`` / ``Bash`` / ``Glob`` / ``Grep`` / ``WebFetch`` with
``file_path`` / ``command`` / ``url``. The §11.2 example records a ``Read`` call with a
``file_path`` input and expects the normalizer — not the capture plane — to compute the
``workspace_read`` capability from it. This module is that translation, in one place, so
the canonicaliser (capability sets, trajectory) and the evidence index (declared-vs-observed
reads, the ``file_not_read`` assertion) agree on what a tool call touched. A tool this table
does not know keeps its generic ``tool:<name>`` capability rather than being guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["FilesystemAccess", "filesystem_access", "tool_target"]


@dataclass(frozen=True)
class FilesystemAccess:
    """A tool call that reads or writes one path."""

    path: str
    write: bool


#: Tool name → (input key holding the path, whether the call writes). Names are matched
#: case-sensitively: ``read`` is the api-loop tool, ``Read`` the Claude Code one, and they
#: happen to agree; ``Edit``/``MultiEdit``/``NotebookEdit`` are writes to the file they edit.
_FILESYSTEM_TOOLS: dict[str, tuple[str, bool]] = {
    # api-loop (§9.4 adapter 2)
    "read": ("path", False),
    "write": ("path", True),
    # Claude Code (§9.4 adapter 1)
    "Read": ("file_path", False),
    "Write": ("file_path", True),
    "Edit": ("file_path", True),
    "MultiEdit": ("file_path", True),
    "NotebookEdit": ("notebook_path", True),
}

#: Tools whose ``path`` argument names a directory (or file) they read through.
_DIRECTORY_READ_TOOLS: frozenset[str] = frozenset({"Glob", "Grep"})


def filesystem_access(tool: str, tool_input: dict[str, Any]) -> FilesystemAccess | None:
    """The path a tool call reads or writes, or ``None`` for a tool that touches no file.

    ``Glob``/``Grep`` read the directory they are pointed at (``path``); absent a ``path``
    they search the working directory, which is the workspace root — spelled ``"."`` so the
    canonicaliser's relative-path rule resolves it against the workspace, the same way the
    api-loop ``read`` of a relative path resolves.
    """
    spec = _FILESYSTEM_TOOLS.get(tool)
    if spec is not None:
        key, write = spec
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return FilesystemAccess(path=value, write=write)
        return None
    if tool in _DIRECTORY_READ_TOOLS:
        value = tool_input.get("path")
        return FilesystemAccess(
            path=value if isinstance(value, str) and value else ".", write=False
        )
    return None


def tool_target(tool_input: dict[str, Any]) -> str | None:
    """Tier 3 for a generic tool call: the most identifying input it has."""
    for key in ("url", "command", "pattern", "name", "skill", "path", "file_path"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
    return None
