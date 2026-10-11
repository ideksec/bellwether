"""Plane B reads and Plane D′ processes as ARF records, attributed by process tree (§10.2, §10.3).

The fanotify recorder (:mod:`bellwether.capture.fanotify`) reports what the kernel saw: every
``execve`` in the container with its exact argv and parent, and every file opened for reading on
the watched mounts. This module turns that into actions and answers the one question the
analysis cannot answer later — **whose** process each one was.

A harness execs on its own behalf: the agent CLI, the hook that copies a tool event to the
sink, the ``cat`` api-loop's ``read`` tool runs. Those are recorded with ``role: harness`` and
never become the skill's capabilities or scope violations — Plane A already records the tool
call they implement. Everything else is the skill's. The adapter states the shapes of its own
processes (:class:`~bellwether.harness.HarnessProcessRules`) and attribution follows the tree:
a top-level process is one whose parent is outside the container; a process inherits the role
of the subtree it was born into; and a process that re-execs in place becomes what it execs.

Identity is the argv0 the process asked for *and* the file the kernel actually opened. The two
can legitimately differ (``sh`` is ``dash``, ``python3`` is ``python3.11``, every busybox applet
is ``busybox``) and can be made to differ deliberately (``execve("/usr/bin/curl", ["git"])``).
Both are recorded; the analysis requires both to be accounted for unless the executed file is a
known multi-call binary.
"""

from __future__ import annotations

import datetime as dt
import re
import shlex
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Literal

from bellwether.capture.fanotify import ExecEvent, ReadEvent, RecordedActivity
from bellwether.capture.filesystem import PlaneStatus
from bellwether.harness import HarnessProcessRules
from bellwether.sandbox.zones import ZoneMap
from bellwether.trace.models import Action, Correlation

__all__ = [
    "ProcessRole",
    "kernel_plane_actions",
    "kernel_plane_coverage",
    "process_name",
]

ProcessRole = Literal["harness", "skill"]

#: How a process came to hold its role, for the record a reader audits.
_Origin = Literal["own", "tool_shell", "housekeeping", "helper", "subtree", "inherited", "skill"]


@dataclass
class _Process:
    pid: int
    argv0: str
    role: ProcessRole
    origin: _Origin
    #: Whether this pid's current image is the harness's ``own`` (its children are the skill's).
    own_image: bool


def process_name(argv: Sequence[str] | None, exe: str) -> str:
    """The argv0 a process asked for, as a bare name; the executed file's name where argv is
    unread. Never empty."""
    if argv:
        name = PurePosixPath(argv[0]).name
        if name:
            return name
    return PurePosixPath(exe).name or exe


def _is_subtree_script(argv: Sequence[str] | None, rules: HarnessProcessRules) -> bool:
    """``sh -c <script>`` where ``<script>`` is exactly one the harness declared."""
    if not argv or len(argv) < 3 or argv[1] != "-c":
        return False
    return argv[2] in rules.subtrees


def _attribute(
    event: ExecEvent,
    processes: Mapping[int, _Process],
    rules: HarnessProcessRules,
    *,
    tool_shell_is_skills: Callable[[ExecEvent], bool],
) -> _Process:
    argv0 = process_name(event.argv, event.exe)
    existing = processes.get(event.pid)
    if existing is not None:
        # A re-exec in place. Inside a harness subtree it stays the harness's (the write tool's
        # shell exec'ing its own `cat`); an `own` image that execs is running what it was handed,
        # which is the skill's; a skill process stays the skill's.
        if existing.role == "harness" and not existing.own_image:
            return _Process(event.pid, argv0, "harness", "inherited", own_image=False)
        return _Process(event.pid, argv0, "skill", "skill", own_image=False)

    parent = processes.get(event.ppid) if event.ppid is not None else None
    if parent is None:
        # Top level: the parent is outside the container — a `docker exec` the harness made.
        if _is_subtree_script(event.argv, rules):
            return _Process(event.pid, argv0, "harness", "subtree", own_image=False)
        if argv0 in rules.own:
            return _Process(event.pid, argv0, "harness", "own", own_image=True)
        return _Process(event.pid, argv0, "skill", "skill", own_image=False)

    if parent.role == "harness" and not parent.own_image:
        return _Process(event.pid, argv0, "harness", "inherited", own_image=False)
    if parent.role == "harness" and parent.own_image:
        if _is_subtree_script(event.argv, rules):
            return _Process(event.pid, argv0, "harness", "subtree", own_image=False)
        if parent.origin == "own" and argv0 in rules.tool_shells:
            if tool_shell_is_skills(event):
                return _Process(event.pid, argv0, "harness", "tool_shell", own_image=True)
            # A shell the harness started that ran none of the model's commands: its own
            # housekeeping (HarnessProcessRules.shell_tools), and so is all it runs.
            return _Process(event.pid, argv0, "harness", "housekeeping", own_image=False)
        # A helper is the harness's only as the harness's own direct child: `git` under the
        # CLI is its repository probe, `git` under the Bash tool's shell is the skill's command.
        if parent.origin == "own" and argv0 in rules.helpers:
            return _Process(event.pid, argv0, "harness", "helper", own_image=False)
    return _Process(event.pid, argv0, "skill", "skill", own_image=False)


#: What a shell wrapper may add to, or take from, a command it embeds: whitespace (a heredoc's
#: newlines, a wrapper's spacing) and the quoting and escaping characters it re-quotes with.
_UNQUOTED = re.compile(r"[\s'\"\\]+")

#: What may follow an embedded command in a wrapper: the end, or a shell delimiter.
_AFTER_COMMAND = re.compile(r"(?:$|[\s;&|<>)])")


def _bare(text: str) -> str:
    return _UNQUOTED.sub("", text)


def _quoted_forms(command: str) -> tuple[str, ...]:
    """The spellings a wrapper embeds a command in: as written, and the usual single-quotings."""
    return (
        shlex.quote(command),
        "'" + command.replace("'", "'\\''") + "'",
        "'" + command.replace("'", "'\"'\"'") + "'",
        command,
    )


def _mentions(argv: Sequence[str] | None, command: str, prefix: str) -> bool:
    """Whether ``argv`` is the shell that ran ``command``.

    With a ``prefix`` (``HarnessProcessRules.shell_command_prefix``) the command must appear right
    after it, quoted as a shell quotes an argument, and be followed by a delimiter: the CLI runs a
    ``Bash`` call as ``… && eval 'date -u' < /dev/null && …`` (``eval id`` for a bare word),
    observed on PR #102's live run. That run is why the match is anchored. Matched anywhere, the
    one-word command ``id`` was found inside the CLI's own IDE probe
    (``grep -E "…|idea|…"``) and its shell-snapshot script, and both shells — with their ``ps``,
    ``grep``, ``cat`` and ``id -u`` — were put on the skill.

    Without a prefix, the command is looked for anywhere, compared with whitespace, quotes and
    backslashes removed — looser, and only ever in the over-attributing direction.
    """
    if not argv or not command.strip():
        return False
    text = "\0".join(argv)
    if prefix:
        for form in _quoted_forms(command):
            needle = prefix + form
            start = text.find(needle)
            while start != -1:
                if _AFTER_COMMAND.match(text, start + len(needle)):
                    return True
                start = text.find(needle, start + 1)
        return False
    return _bare(command) in _bare("".join(argv))


def _tool_shell_rule(
    activity: RecordedActivity,
    rules: HarnessProcessRules,
    shell_commands: Sequence[str] | None,
) -> Callable[[ExecEvent], bool]:
    """Which of the harness's tool shells are the skill's (see :func:`kernel_plane_actions`)."""
    if shell_commands is None:
        return lambda _event: True
    if not shell_commands:
        return lambda _event: False
    commands = list(shell_commands)
    candidates = [
        event
        for event in activity.execs
        if process_name(event.argv, event.exe) in rules.tool_shells
    ]
    # A blank command (a call whose input could not be read) matches nothing, so it lands here.
    prefix = rules.shell_command_prefix
    if not all(
        any(_mentions(event.argv, command, prefix) for event in candidates) for command in commands
    ):
        return lambda _event: True
    return lambda event: any(_mentions(event.argv, command, prefix) for command in commands)


def kernel_plane_actions(
    activity: RecordedActivity,
    *,
    rules: HarnessProcessRules,
    zones: ZoneMap,
    canary_paths: Mapping[str, str],
    start_seq: int = 0,
    shell_commands: Sequence[str] | None = None,
) -> list[Action]:
    """Every recorded exec and read as an action, in the order the kernel reported them.

    ``shell_commands`` are the commands Plane A recorded the model asking a shell tool
    (``rules.shell_tools``) to run, and decide which of the harness's tool shells are the skill's:

    - ``None`` — not known: every tool shell is the skill's, the direction that attributes more
      to the skill, never less;
    - empty — no shell-tool call: the model never had a command run, so every tool shell is
      the harness's housekeeping;
    - otherwise — a tool shell is the skill's when its argv carries one of the commands (as
      written, or shell-quoted the way a wrapper embeds it). The real CLI also starts shells of
      its own in a run that calls ``Bash`` (CI recorded ``cat``, ``env``, ``grep``, ``id`` and
      ``ps`` beside the model's command), and only the command text tells them apart. If any
      command matches no tool shell, matching is not trusted for the run and every tool shell is
      the skill's again — a wrapper that encodes commands some other way must over-attribute,
      never hide the command it ran.

    ``canary_paths`` maps each planted canary's container path to its canary id: a read of one
    is recorded as ``canary_read`` (§10.4, §11.3) — by reference, never by value — whatever
    process performed it, because a credential read is the evidence whether the harness's
    ``Read`` tool or a skill's subprocess did it.
    """
    tool_shell_is_skills = _tool_shell_rule(activity, rules, shell_commands)
    processes: dict[int, _Process] = {}
    ancestry: dict[int, tuple[str, ...]] = {}
    events: list[tuple[int, dt.datetime, ExecEvent | ReadEvent]] = sorted(
        [(event.order, event.ts, event) for event in activity.execs]
        + [(event.order, event.ts, event) for event in activity.reads],
        key=lambda item: item[0],
    )
    actions: list[Action] = []
    for offset, (_, ts, event) in enumerate(events):
        seq = start_seq + offset
        if isinstance(event, ExecEvent):
            process = _attribute(event, processes, rules, tool_shell_is_skills=tool_shell_is_skills)
            parent = processes.get(event.ppid) if event.ppid is not None else None
            ancestors: tuple[str, ...] = (
                (parent.argv0, *ancestry.get(parent.pid, ())) if parent is not None else ()
            )
            processes[event.pid] = process
            ancestry[event.pid] = ancestors
            payload: dict[str, Any] = {
                "argv0": process.argv0,
                "exe": event.exe,
                "role": process.role,
                "attribution": process.origin,
                "ancestors": list(ancestors),
                "argv_read": event.argv is not None,
            }
            if event.argv is not None:
                payload["argv"] = list(event.argv)
            if event.filename is not None:
                payload["filename"] = event.filename
            if event.interpreters:
                payload["interpreters"] = list(event.interpreters)
            if event.ppid is not None:
                payload["ppid"] = event.ppid
            actions.append(
                Action(
                    seq=seq,
                    ts=ts,
                    plane="process",
                    kind="process_exec",
                    action=payload,
                    correlation=Correlation(pid=event.pid),
                )
            )
            continue

        reader = processes.get(event.pid)
        zoned = zones.classify(event.path)
        read_payload: dict[str, Any] = {
            "path": str(zoned.absolute),
            "zone": zoned.zone,
            "zone_relative": str(zoned.relative),
            # A pid never seen exec is one the recorder cannot place; the conservative reading
            # is the skill's — the marks are on this run's mounts only, so nothing on the host
            # reaches them.
            "role": reader.role if reader is not None else "skill",
        }
        if reader is not None:
            read_payload["process"] = reader.argv0
        canary_id = canary_paths.get(str(zoned.absolute))
        if canary_id is not None:
            read_payload["canary_id"] = canary_id
        actions.append(
            Action(
                seq=seq,
                ts=ts,
                plane="filesystem",
                kind="canary_read" if canary_id is not None else "file_read",
                action=read_payload,
                correlation=Correlation(pid=event.pid),
            )
        )
    return actions


def kernel_plane_coverage(
    activity: RecordedActivity | None, *, reason_if_absent: str
) -> tuple[PlaneStatus, PlaneStatus]:
    """``(filesystem_reads, process)`` coverage for one run (§10.7).

    ``full`` only where the recorder ran and reported no gap. Read capture is scoped — the
    workspace and the planted credentials, never the image's own files — and the reason says
    so, because "full" here means the stated domain was watched in full, not that every read
    on the machine was.
    """
    if activity is None:
        return (
            PlaneStatus(fidelity="unavailable", reason=reason_if_absent),
            PlaneStatus(fidelity="unavailable", reason=reason_if_absent),
        )
    domain = ", ".join(activity.read_mounts) or "nothing"
    gap = "; ".join(activity.gaps)
    reads = PlaneStatus(
        fidelity="partial" if gap else "full",
        reason=(
            f"reads captured host-side (fanotify) on {domain}"
            + (f"; incomplete: {gap}" if gap else "")
        ),
        domain=activity.read_mounts,
    )
    process = PlaneStatus(
        fidelity="partial" if gap else "full",
        reason=(
            f"every execve on the container's {len(activity.exec_mounts)} mounts captured "
            "host-side (fanotify permission events)" + (f"; incomplete: {gap}" if gap else "")
        ),
    )
    return reads, process
