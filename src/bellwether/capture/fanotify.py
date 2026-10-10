"""Plane B reads and Plane D′ process execution, captured host-side with fanotify (§10.2, §10.3).

The spec names two mechanisms: a ``fanotify`` mark for reads (v0.2) and eBPF ``execve`` tracing
for processes (v0.3). Both are built here on the one kernel interface the host already has the
privilege for — the host runs as root to mount the workspace overlay, and the container does not
(§10.0's observer rule). A single fanotify group watches every mount the container can see, from
outside it:

- **Execution.** ``FAN_OPEN_EXEC_PERM`` on every mount in the container's mount namespace (reached
  through ``/proc/<pid>/root``, so a host directory bound into the container is watched only through
  the container's own mount of it, never the host's). A permission event holds the exec'ing task in
  the kernel until it is answered, and while it is held the task is still inside ``execve`` with
  its *old* address space mapped: its parent, its mount namespace and — read through
  ``/proc/<pid>/syscall`` and ``/proc/<pid>/mem`` — the exact ``filename`` and ``argv`` it asked
  the kernel for are all still there. The executed file itself is the event's descriptor, which the
  kernel resolved, so a symlink or a multi-call binary cannot disguise *what* ran. Every exec is
  answered ``FAN_ALLOW``: this plane observes, it never decides (§10.0).
- **Reads.** ``FAN_CLOSE_NOWRITE`` on the workspace mount and on each planted canary's mount — a
  file opened without write access and closed again, which covers ``read(2)`` and ``mmap`` alike
  and fires even when the reader exits without closing. Reads elsewhere in the image (shared
  libraries, ``/etc``) are not watched: they are the platform, and §10.2 scopes read capture to the
  workspace.

The recorder never decides attribution or scope. It records what the kernel reported, in arrival
order, with what it could read about the process at that instant; the trace builder decides what
belongs to the harness and what to the skill, and the analysis decides what was declared.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import datetime as dt
import errno
import os
import platform
import select
import struct
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

__all__ = [
    "FANOTIFY_EVENT_LIMIT",
    "PSEUDO_FILESYSTEMS",
    "ExecEvent",
    "FanotifyRecorder",
    "FanotifyUnavailableError",
    "ReadEvent",
    "RecordedActivity",
    "container_mounts",
    "fanotify_available",
    "parse_mountinfo",
]

# fanotify(7) constants, from <linux/fanotify.h>.
_FAN_CLASS_CONTENT = 0x00000004
_FAN_CLOEXEC = 0x00000001
_FAN_NONBLOCK = 0x00000002
_FAN_MARK_ADD = 0x00000001
_FAN_MARK_MOUNT = 0x00000010
_FAN_CLOSE_NOWRITE = 0x00000010
_FAN_OPEN_EXEC_PERM = 0x00040000
_FAN_Q_OVERFLOW = 0x00004000
_FAN_ALLOW = 0x01
_FAN_NOFD = -1
_FANOTIFY_METADATA_VERSION = 3
#: ``struct fanotify_event_metadata``: event_len, vers, reserved, metadata_len, mask, fd, pid.
_METADATA = struct.Struct("=IBBHQii")
_RESPONSE = struct.Struct("=iI")
_AT_FDCWD = -100

#: Filesystems with nothing on them to execute or read as a skill's input: the kernel's own
#: views and the cgroup/IPC plumbing. Everything else the container can see is marked —
#: overlay roots, bind mounts, tmpfs — so a binary dropped anywhere executable is observed.
#: Normalise, don't enumerate: the list says what *cannot* hold a program, never what can.
PSEUDO_FILESYSTEMS: frozenset[str] = frozenset(
    {"proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "securityfs", "debugfs",
     "tracefs", "bpf", "pstore", "configfs", "fusectl", "binfmt_misc", "autofs", "nsfs"}
)  # fmt: skip

#: The most events one run may record before the recorder stops *recording* (it never stops
#: answering a permission event). A skill that execs in a tight loop must not exhaust host
#: memory; the plane then reads ``partial`` and says why, rather than silently truncating.
FANOTIFY_EVENT_LIMIT = 200_000

#: Bounds on the argv read out of a paused process. The pointers are the evaluated code's own,
#: so every read is capped: a hostile argv cannot make the host read unboundedly.
_MAX_ARGS = 1024
_MAX_ARG_BYTES = 8192
_MAX_ARGV_BYTES = 256 * 1024

#: ``execve``/``execveat`` syscall numbers per architecture, and which argument holds the
#: filename and the argv pointer. An architecture missing here records argv as unread.
_EXEC_SYSCALLS: dict[str, dict[int, tuple[int, int]]] = {
    "x86_64": {59: (0, 1), 322: (1, 2)},
    "aarch64": {221: (0, 1), 281: (1, 2)},
}


#: The start of the one gap recorded for unread argvs, however many there were.
_ARGV_GAP = "the argv of at least one exec could not be read"


class FanotifyUnavailableError(Exception):
    """The kernel refused the group or a mark; the planes are unavailable for this run."""


@dataclass(frozen=True)
class ExecEvent:
    """One ``execve`` the container made, as the kernel reported it at the moment of the call."""

    order: int
    ts: dt.datetime
    pid: int
    #: The parent at exec time, read while the task was held; ``None`` if it could not be read.
    ppid: int | None
    #: The file the kernel opened to execute — resolved by the kernel, so authoritative.
    exe: str
    #: The ``filename`` argument the process passed (may be a symlink or a relative path).
    filename: str | None
    #: The argv the process passed, read from its memory while it was held. ``None`` where it
    #: could not be read; never guessed.
    argv: tuple[str, ...] | None
    #: Further files the same ``execve`` opened for execution: the ELF interpreter, or the
    #: interpreter named on a script's ``#!`` line. Part of this exec, not new processes.
    interpreters: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReadEvent:
    """One file the container opened without write access, read, and closed."""

    order: int
    ts: dt.datetime
    pid: int
    path: str


@dataclass(frozen=True)
class RecordedActivity:
    """Everything one run's recorder saw, in arrival order."""

    execs: tuple[ExecEvent, ...]
    reads: tuple[ReadEvent, ...]
    #: Mount points marked (container paths) and which carried read capture.
    exec_mounts: tuple[str, ...]
    read_mounts: tuple[str, ...]
    #: Why the record is incomplete, if it is: an overflowed kernel queue, the event limit, an
    #: argv that could not be read. Empty when every exec and read was recorded in full.
    gaps: tuple[str, ...] = ()


@dataclass(frozen=True)
class Mount:
    """One line of ``/proc/<pid>/mountinfo``, reduced to what marking needs."""

    mount_point: str
    fstype: str


def parse_mountinfo(text: str) -> list[Mount]:
    """Parse ``mountinfo`` (proc(5)): field 5 is the mount point, the field after ``-`` the type.

    Mount points are octal-escaped by the kernel (``\\040`` for a space); they are decoded so a
    workspace path with a space still matches. Sorted for a deterministic marking order.
    """
    mounts: list[Mount] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 7 or "-" not in fields[6:]:
            continue
        separator = fields.index("-", 6)
        if separator + 1 >= len(fields):
            continue
        mounts.append(Mount(mount_point=_unescape(fields[4]), fstype=fields[separator + 1]))
    return sorted(mounts, key=lambda mount: mount.mount_point)


def _unescape(value: str) -> str:
    out = bytearray()
    raw = value.encode()
    index = 0
    while index < len(raw):
        if (
            raw[index] == ord("\\")
            and index + 4 <= len(raw)
            and raw[index + 1 : index + 4].isdigit()
        ):
            out.append(int(raw[index + 1 : index + 4], 8))
            index += 4
        else:
            out.append(raw[index])
            index += 1
    return out.decode(errors="replace")


def container_mounts(pid: int, proc: Path = Path("/proc")) -> list[Mount]:
    """The mounts in ``pid``'s mount namespace that can hold something to execute or read."""
    text = (proc / str(pid) / "mountinfo").read_text(encoding="utf-8", errors="replace")
    return [mount for mount in parse_mountinfo(text) if mount.fstype not in PSEUDO_FILESYSTEMS]


def _libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c") or "libc.so.6"
    return ctypes.CDLL(name, use_errno=True)


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@dataclass
class _PendingExec:
    order: int
    ts: dt.datetime
    pid: int
    ppid: int | None
    exe: str
    filename: str | None
    argv: tuple[str, ...] | None
    #: The ``/proc/<pid>/syscall`` line at the first event — identical for the interpreter
    #: opens of the same ``execve``, which is how they are folded into it.
    syscall_key: str
    interpreters: list[str] = field(default_factory=list)


def fanotify_available() -> tuple[bool, str]:
    """Whether this host grants the fanotify group a run's recorder needs, and why not if not.

    Opens the same ``FAN_CLASS_CONTENT`` group :meth:`FanotifyRecorder.start` does and closes it
    at once: the question is answered by the kernel, not inferred from the uid.
    """
    try:
        libc = _libc()
    except OSError as error:
        return False, f"libc not loadable: {error}"
    fd = libc.fanotify_init(
        _FAN_CLASS_CONTENT | _FAN_CLOEXEC | _FAN_NONBLOCK, os.O_RDONLY | os.O_LARGEFILE
    )
    if fd < 0:
        code = ctypes.get_errno()
        return False, (
            f"fanotify_init failed ({errno.errorcode.get(code, code)}): read and process capture "
            "need the host's CAP_SYS_ADMIN (run under sudo, as the overlay already requires) and "
            "a kernel with fanotify permission events"
        )
    os.close(fd)
    return True, "a content-class fanotify group can be opened on this host"


class FanotifyRecorder:
    """One run's fanotify group: marks the container's mounts, drains, answers, records.

    Start it after the container exists and before anything runs in it; stop it after the
    container is gone. Draining happens on a dedicated thread from the moment the group exists:
    an undrained notification holds an open file descriptor on the file it names, and a held
    descriptor keeps a mount busy — the recorder must never be the reason a teardown fails.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], dt.datetime] = _utc_now,
        proc: Path = Path("/proc"),
        event_limit: int = FANOTIFY_EVENT_LIMIT,
        machine: str | None = None,
    ) -> None:
        self._clock = clock
        self._proc = proc
        self._event_limit = event_limit
        self._syscalls = _EXEC_SYSCALLS.get(machine or platform.machine(), {})
        self._libc = _libc()
        self._fd = -1
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._order = 0
        self._execs: list[_PendingExec] = []
        self._reads: list[ReadEvent] = []
        self._seen_reads: set[tuple[int, str]] = set()
        self._gaps: set[str] = set()
        self._exec_mounts: list[str] = []
        self._read_mounts: list[str] = []
        self._own_pid = os.getpid()

    # -- lifecycle -----------------------------------------------------------------------

    def start(self) -> None:
        fd = self._libc.fanotify_init(
            _FAN_CLASS_CONTENT | _FAN_CLOEXEC | _FAN_NONBLOCK, os.O_RDONLY | os.O_LARGEFILE
        )
        if fd < 0:
            code = ctypes.get_errno()
            raise FanotifyUnavailableError(
                f"fanotify_init failed ({errno.errorcode.get(code, code)}): read and process "
                "capture need the host's CAP_SYS_ADMIN and a kernel with fanotify permission "
                "events (CONFIG_FANOTIFY_ACCESS_PERMISSIONS)"
            )
        self._fd = fd
        self._thread = threading.Thread(target=self._drain, name="bw-fanotify", daemon=True)
        self._thread.start()

    def watch_container(self, pid: int, *, read_points: Iterable[str]) -> None:
        """Mark every mount ``pid`` can see for exec, and ``read_points``' mounts for reads.

        ``read_points`` are container paths (the workspace root, each canary slot); the mount a
        point lives on is the one whose mount point is its longest prefix, so a canary bound as a
        single file is its own mount and the workspace overlay is another.
        """
        mounts = container_mounts(pid, self._proc)
        if not mounts:
            raise FanotifyUnavailableError(f"no mounts readable for container process {pid}")
        wanted = {self._mount_of(PurePosixPath(point), mounts) for point in read_points}
        for mount in mounts:
            read = mount.mount_point in wanted
            mask = _FAN_OPEN_EXEC_PERM | (_FAN_CLOSE_NOWRITE if read else 0)
            target = self._proc / str(pid) / "root" / mount.mount_point.lstrip("/")
            self._mark(str(target), mask, mount.mount_point)
            self._exec_mounts.append(mount.mount_point)
            if read:
                self._read_mounts.append(mount.mount_point)

    def stop(self) -> RecordedActivity:
        """Stop draining, release the group (which answers anything still held), return the record."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
        if self._fd >= 0:
            # Closing the group removes every mark and lets any task still held proceed: the
            # kernel answers an unanswered permission event with allow when its group goes away.
            os.close(self._fd)
            self._fd = -1
        with self._lock:
            execs = tuple(
                ExecEvent(
                    order=pending.order,
                    ts=pending.ts,
                    pid=pending.pid,
                    ppid=pending.ppid,
                    exe=pending.exe,
                    filename=pending.filename,
                    argv=pending.argv,
                    interpreters=tuple(pending.interpreters),
                )
                for pending in self._execs
            )
            return RecordedActivity(
                execs=execs,
                reads=tuple(self._reads),
                exec_mounts=tuple(sorted(set(self._exec_mounts))),
                read_mounts=tuple(sorted(set(self._read_mounts))),
                gaps=tuple(sorted(self._gaps)),
            )

    def __enter__(self) -> FanotifyRecorder:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fd >= 0:
            self.stop()

    # -- internals -----------------------------------------------------------------------

    @staticmethod
    def _mount_of(point: PurePosixPath, mounts: list[Mount]) -> str:
        best = "/"
        for mount in mounts:
            candidate = PurePosixPath(mount.mount_point)
            if (point == candidate or candidate in point.parents) and len(mount.mount_point) > len(
                best
            ):
                best = mount.mount_point
        return best

    def _mark(self, path: str, mask: int, label: str) -> None:
        result = self._libc.fanotify_mark(
            self._fd,
            _FAN_MARK_ADD | _FAN_MARK_MOUNT,
            ctypes.c_uint64(mask),
            _AT_FDCWD,
            path.encode(),
        )
        if result != 0:
            code = ctypes.get_errno()
            raise FanotifyUnavailableError(
                f"could not mark the container mount {label!r} ({errno.errorcode.get(code, code)})"
            )

    def _drain(self) -> None:
        while not self._stop.is_set() or self._has_pending():
            try:
                ready, _, _ = select.select([self._fd], [], [], 0.02)
            except (OSError, ValueError):
                return
            if not ready:
                if self._stop.is_set():
                    return
                continue
            try:
                buffer = os.read(self._fd, 256 * 1024)
            except BlockingIOError:
                continue
            except OSError:
                return
            self._consume(buffer)

    def _has_pending(self) -> bool:
        if self._fd < 0:
            return False
        try:
            ready, _, _ = select.select([self._fd], [], [], 0)
        except (OSError, ValueError):
            return False
        return bool(ready)

    def _consume(self, buffer: bytes) -> None:
        offset = 0
        while offset + _METADATA.size <= len(buffer):
            event_len, version, _, _, mask, event_fd, pid = _METADATA.unpack_from(buffer, offset)
            if event_len < _METADATA.size:
                break
            offset += event_len
            if version != _FANOTIFY_METADATA_VERSION:
                self._gaps.add(f"unexpected fanotify metadata version {version}")
            if mask & _FAN_Q_OVERFLOW:
                self._gaps.add("the kernel's fanotify queue overflowed; events were dropped")
            if event_fd == _FAN_NOFD:
                continue
            try:
                self._handle(mask, event_fd, pid)
            # A recorder bug must never hold a task: the answer below is always written.
            except Exception as error:
                self._gaps.add(f"an event could not be recorded ({type(error).__name__})")
            finally:
                if mask & _FAN_OPEN_EXEC_PERM:
                    with contextlib.suppress(OSError):
                        os.write(self._fd, _RESPONSE.pack(event_fd, _FAN_ALLOW))
                with contextlib.suppress(OSError):
                    os.close(event_fd)

    def _handle(self, mask: int, event_fd: int, pid: int) -> None:
        if pid == self._own_pid:
            return
        path = _fd_path(event_fd)
        if mask & _FAN_OPEN_EXEC_PERM:
            self._record_exec(pid, path)
        elif mask & _FAN_CLOSE_NOWRITE:
            self._record_read(pid, path)

    def _next_order(self) -> int | None:
        if self._order >= self._event_limit:
            self._gaps.add(
                f"the run exceeded {self._event_limit} file and process events; later ones "
                "were allowed but not recorded"
            )
            return None
        self._order += 1
        return self._order

    def _exec_syscall_line(self, pid: int) -> str | None:
        """The ``/proc`` syscall line of the thread of ``pid`` that is held in ``execve``.

        fanotify names the thread group, not the thread. An exec called from a secondary thread
        (the real claude-code CLI does this) leaves the group leader in some other syscall, so
        its line names a ``futex`` rather than the exec; the thread actually held in the exec is
        found among ``/proc/<pid>/task/*``. Tasks are scanned in sorted order (§24).
        """
        leader = _read_text(self._proc / str(pid) / "syscall")
        if self._is_exec_line(leader):
            return leader
        try:
            tasks = sorted(
                (entry.name for entry in (self._proc / str(pid) / "task").iterdir()),
                key=lambda name: (len(name), name),
            )
        except OSError:
            return leader
        for tid in tasks:
            line = _read_text(self._proc / str(pid) / "task" / tid / "syscall")
            if self._is_exec_line(line):
                return line
        return leader

    def _is_exec_line(self, line: str | None) -> bool:
        if not line:
            return False
        try:
            return int(line.split()[0]) in self._syscalls
        except (ValueError, IndexError):
            return False

    def _record_exec(self, pid: int, exe: str) -> None:
        syscall_line = self._exec_syscall_line(pid)
        with self._lock:
            last = next((e for e in reversed(self._execs) if e.pid == pid), None)
            if last is not None and syscall_line and last.syscall_key == syscall_line:
                # The ELF interpreter or a script's #! interpreter, opened by the same execve.
                last.interpreters.append(exe)
                return
            order = self._next_order()
            if order is None:
                return
        filename, argv = self._read_exec_args(pid, syscall_line)
        if argv is None and not any(gap.startswith(_ARGV_GAP) for gap in self._gaps):
            self._gaps.add(
                f"{_ARGV_GAP} (first: {PurePosixPath(exe).name}, syscall "
                f"{(syscall_line or 'unreadable').split(' ', 1)[0]})"
            )
        pending = _PendingExec(
            order=order,
            ts=self._clock(),
            pid=pid,
            ppid=_parent_of(self._proc, pid),
            exe=exe,
            filename=filename,
            argv=argv,
            syscall_key=syscall_line or f"unread:{order}",
        )
        with self._lock:
            self._execs.append(pending)

    def _record_read(self, pid: int, path: str) -> None:
        key = (pid, path)
        with self._lock:
            if key in self._seen_reads:
                return
            order = self._next_order()
            if order is None:
                return
            self._seen_reads.add(key)
            self._reads.append(ReadEvent(order=order, ts=self._clock(), pid=pid, path=path))

    def _read_exec_args(
        self, pid: int, syscall_line: str | None
    ) -> tuple[str | None, tuple[str, ...] | None]:
        """The ``filename`` and ``argv`` a held ``execve`` was called with, from its memory."""
        if not syscall_line:
            return None, None
        fields = syscall_line.split()
        try:
            number = int(fields[0])
            args = [int(value, 16) for value in fields[1:7]]
        except (ValueError, IndexError):
            return None, None
        positions = self._syscalls.get(number)
        if positions is None:
            return None, None
        filename_at, argv_at = positions
        try:
            with (self._proc / str(pid) / "mem").open("rb", buffering=0) as memory:
                filename = _read_c_string(memory, args[filename_at])
                argv = _read_string_array(memory, args[argv_at])
        except OSError:
            return None, None
        return filename, argv


def _fd_path(event_fd: int) -> str:
    path = Path(f"/proc/self/fd/{event_fd}").readlink()
    return str(path).removesuffix(" (deleted)")


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        return None


def _parent_of(proc: Path, pid: int) -> int | None:
    stat = _read_text(proc / str(pid) / "stat")
    if not stat or ")" not in stat:
        return None
    try:
        return int(stat.rsplit(")", 1)[1].split()[1])
    except (ValueError, IndexError):
        return None


def _read_c_string(memory: BinaryIO, address: int) -> str | None:
    if address == 0:
        return None
    memory.seek(address)
    raw = memory.read(_MAX_ARG_BYTES)
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _read_string_array(memory: BinaryIO, address: int) -> tuple[str, ...] | None:
    if address == 0:
        return ()
    out: list[str] = []
    total = 0
    for index in range(_MAX_ARGS):
        memory.seek(address + 8 * index)
        chunk = memory.read(8)
        if len(chunk) < 8:
            return None
        pointer = struct.unpack("<Q", chunk)[0]
        if pointer == 0:
            return tuple(out)
        value = _read_c_string(memory, pointer)
        if value is None:
            return None
        total += len(value)
        if total > _MAX_ARGV_BYTES:
            return (*out, "<argv truncated>")
        out.append(value)
    return (*out, "<argv truncated>")
