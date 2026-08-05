"""The isolation profile, as data (§9.2, §3.4).

The flags a sandbox backend applies are kept as a structure rather than assembled inline
at launch, for three reasons: they are recorded in the run header so a trace says what
isolation it was collected under; they can be asserted in tests without a daemon; and a
second backend (gVisor, Firecracker) applies the same profile rather than reimplementing
the intent.

**``--cap-drop=ALL`` is genuinely achievable here**, because no capture code runs inside
the container (§10.0). Revision 1 of the specification put ``fanotify`` and eBPF inside,
which would have required ``CAP_SYS_ADMIN`` or ``CAP_BPF`` and silently negated the whole
isolation profile it was meant to observe.

This profile is adequate for *observing* skills of unknown quality. It is **not** adequate
for detonating confirmed malware; that needs a stronger backend, and policy can require
one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["IsolationProfile", "PinnedEnvironment"]


@dataclass(frozen=True)
class PinnedEnvironment:
    """Values pinned so that no tool inside derives a varying identifier (§9.2).

    A deterministic clock is *not* required — Bellwether measures behavioural variance,
    not wall-clock — but timezone, locale and machine-id are pinned, because a tool that
    stamps output with any of them turns an environment difference into what looks like
    skill nondeterminism.
    """

    timezone: str = "UTC"
    locale: str = "C.UTF-8"
    #: Pinned to a fixed value rather than randomised: it is not a concealment signal, and
    #: a varying machine-id leaks into logs from anything using systemd's ID as a seed.
    machine_id: str = "00000000000000000000000000000000"


@dataclass(frozen=True)
class IsolationProfile:
    """The v0.1 Docker baseline of §9.2."""

    #: No capability is needed by anything inside, because nothing that produces evidence
    #: runs inside.
    cap_drop: tuple[str, ...] = ("ALL",)
    cap_add: tuple[str, ...] = ()
    read_only_root: bool = True
    no_new_privileges: bool = True
    seccomp: str = "default"
    #: Numeric, not a name. `--user agent` requires the image to define that account;
    #: a uid always resolves, and it is the uid the workspace has to be owned by.
    uid: int = 1000
    gid: int = 1000
    user_name: str = "agent"
    #: 512 rather than 256: a Node-based harness plus a language server plus git plus
    #: Python approaches 256 in normal operation, and hitting the limit produces a
    #: ``sandbox_error`` that reads as a skill failure.
    pids_limit: int = 512
    memory: str = "2g"
    cpus: float = 2.0
    #: 900 rather than 300: a full agentic session that reads a repository and writes a
    #: report routinely exceeds five minutes, and §12.2's ``exit_reason`` assertion would
    #: turn those into failures that look like skill instability.
    timeout_seconds: int = 900
    #: Never mounted. A Docker socket inside the sandbox is a root shell on the host.
    docker_socket: bool = False
    #: The only writable paths. Everything else is read-only root filesystem.
    writable_paths: tuple[str, ...] = ("/work", "/tmp", "/home/agent/.claude")
    pinned: PinnedEnvironment = field(default_factory=PinnedEnvironment)

    @property
    def owner(self) -> tuple[int, int]:
        """The ``(uid, gid)`` every prepared path must be owned by."""
        return (self.uid, self.gid)

    def violations(self) -> list[str]:
        """Weakenings of the baseline that a report must state plainly.

        A run collected under a relaxed profile is still evidence; it is just evidence
        about a different situation, and saying so is the difference between a caveat and
        a misrepresentation.
        """
        problems: list[str] = []
        if "ALL" not in self.cap_drop:
            problems.append("capabilities were not fully dropped")
        if self.cap_add:
            problems.append(f"capabilities were added back: {', '.join(sorted(self.cap_add))}")
        if not self.read_only_root:
            problems.append("the root filesystem was writable")
        if not self.no_new_privileges:
            problems.append("no-new-privileges was not set")
        if self.docker_socket:
            problems.append(
                "the Docker socket was mounted, which is equivalent to root on the host"
            )
        if self.uid == 0:
            problems.append("the container ran as root")
        return problems

    def docker_flags(self) -> list[str]:
        """Render the profile as Docker CLI flags.

        Kept here rather than in the backend so the flags are testable without a daemon —
        a profile that reads correctly and renders wrongly is the failure mode that would
        otherwise reach production unobserved.
        """
        flags: list[str] = []
        for capability in self.cap_drop:
            flags += ["--cap-drop", capability]
        for capability in self.cap_add:
            flags += ["--cap-add", capability]
        if self.read_only_root:
            flags.append("--read-only")
        if self.no_new_privileges:
            flags += ["--security-opt", "no-new-privileges"]
        # Docker applies its default profile without being asked; a custom one silently
        # doing nothing would be a weakening nobody could see.
        if self.seccomp != "default":
            flags += ["--security-opt", f"seccomp={self.seccomp}"]
        flags += ["--user", f"{self.uid}:{self.gid}"]
        flags += ["--pids-limit", str(self.pids_limit)]
        flags += ["--memory", self.memory]
        flags += ["--cpus", str(self.cpus)]
        return flags
