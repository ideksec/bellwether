"""The Docker sandbox backend (§9.1, §9.2).

Drives the container half of the lifecycle: mount the overlay, start a container under
the isolation profile, wait for it, read the diff from the host-side upper directory,
tear down.

Deliberately shells out to the ``docker`` CLI rather than using the SDK. The flags *are*
the security boundary, and rendering them from :class:`~bellwether.sandbox.IsolationProfile`
means the exact command is recordable in the trace, reproducible by a human at a terminal,
and testable without a daemon. An SDK call that maps arguments to an API body is one more
translation between the profile and what actually ran.

Nothing in this module runs inside the container. That is what keeps ``--cap-drop=ALL``
achievable (§10.0).
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from bellwether.errors import BellwetherError
from bellwether.sandbox.overlay import OverlayMount, PathChange, mount_overlay, read_overlay_diff
from bellwether.sandbox.session import PreparedSandbox

__all__ = ["ContainerResult", "DockerBackend"]


@dataclass(frozen=True)
class ContainerResult:
    """What happened when the container ran."""

    exit_code: int
    stdout: str
    stderr: str
    #: True where the wall-clock timeout of §9.2 fired. A timeout is a *failure* rather
    #: than an infrastructure error — it is something the skill did (§12.7).
    timed_out: bool = False

    @property
    def exit_reason(self) -> str:
        if self.timed_out:
            return "timeout"
        if self.exit_code == 0:
            return "completed"
        # 137 is SIGKILL, which for a memory-limited container is almost always the OOM
        # killer. It must not be retried, and it counts against the skill (§13.2).
        if self.exit_code == 137:
            return "oom"
        return "harness_error"


@dataclass
class DockerBackend:
    """A sandbox backend driving the local Docker daemon."""

    name: str = "docker"
    binary: str = "docker"
    #: Set for the container integration tests. Production runs pin the sandbox image by
    #: digest in ``config.yaml``; a moving tag makes two evaluations non-comparable.
    image: str = ""
    _mounts: dict[str, OverlayMount] = field(default_factory=dict, repr=False)

    def available(self) -> tuple[bool, str]:
        """Whether a daemon is reachable, and why not where it is not.

        The reason reaches ``bellwether doctor`` and the coverage block: a missing daemon
        must read as "this plane is unavailable because X", never as a clean run (§10.7).
        """
        try:
            result = subprocess.run(
                [self.binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except FileNotFoundError:
            return False, f"{self.binary} is not installed"
        except subprocess.TimeoutExpired:
            return False, "the Docker daemon did not respond within 20s"

        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            return False, detail[-1] if detail else "the Docker daemon is not reachable"
        return True, f"docker {result.stdout.strip()}"

    def mount(self, prepared: PreparedSandbox) -> OverlayMount:
        """Mount the workspace overlay, with the upper directory on the host."""
        overlay = mount_overlay(
            lower=prepared.workspace.root,
            upper=prepared.upper_dir,
            work=prepared.work_dir,
            merged=prepared.upper_dir.parent / "merged",
        )
        self._mounts[str(prepared.upper_dir)] = overlay
        return overlay

    def unmount(self, prepared: PreparedSandbox) -> None:
        overlay = self._mounts.pop(str(prepared.upper_dir), None)
        if overlay is not None:
            overlay.unmount()

    def run(
        self,
        prepared: PreparedSandbox,
        command: list[str],
        *,
        image: str | None = None,
        network: str = "none",
    ) -> ContainerResult:
        """Run one command in a container under the isolation profile.

        ``network`` defaults to ``none``. The recording proxy and controlled resolver of
        WP-13 and WP-15 replace it with an internal bridge whose only routes out are those
        two; until they exist, no network at all is the honest configuration, because a
        container with unmediated egress would produce traces that under-report it.
        """
        argv = self.build_argv(prepared, command, image=image, network=network)

        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=prepared.isolation.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as expired:
            self._force_remove(prepared.identifiers.container_name)
            return ContainerResult(
                exit_code=124,
                stdout=_text(expired.stdout),
                stderr=_text(expired.stderr),
                timed_out=True,
            )

        return ContainerResult(
            exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr
        )

    def build_argv(
        self,
        prepared: PreparedSandbox,
        command: list[str],
        *,
        image: str | None = None,
        network: str = "none",
    ) -> list[str]:
        """Render the full docker command line.

        The single place an argv is built, so that what is recorded, what is shown to a
        human, and what actually ran cannot drift apart.
        """
        chosen = image or self.image
        if not chosen:
            raise BellwetherError(
                "no sandbox image configured; set sandbox.image in .bellwether/config.yaml, "
                "pinned by digest so two evaluations stay comparable"
            )

        overlay = self._mounts.get(str(prepared.upper_dir))
        workspace_source = overlay.merged if overlay else prepared.workspace.root
        workspace_target = PurePosixPath(prepared.identifiers.workspace_root)

        argv = [self.binary, "run", "--rm", *prepared.isolation.docker_flags()]
        argv += ["--network", network]
        argv += ["--hostname", prepared.identifiers.hostname]
        argv += ["--name", prepared.identifiers.container_name]

        # Every declared writable path gets a writable mount. Under `--read-only` a path
        # with no mount is simply read-only, however loudly the profile declares it — so
        # `/home/agent/.claude` was unwritable, and the harness state zone is exactly where
        # a harness stores session state. Every write would have failed with EROFS, and a
        # run where the agent could not write anything reads as a skill that did nothing:
        # the same shape as the ownership bug, arrived at a different way.
        for writable in prepared.isolation.writable_paths:
            target = PurePosixPath(writable)
            if target == workspace_target or workspace_target.is_relative_to(target):
                continue  # the workspace has its own bind mount, below
            argv += ["--tmpfs", str(target)]

        argv += ["-v", f"{workspace_source}:{workspace_target}:rw"]
        # After the writable mounts, so the read-only payload sits on top of, rather than
        # underneath, a writable parent.
        argv += ["-v", f"{prepared.payload.root}:{prepared.payload.install_path}:ro"]

        for key, value in sorted(prepared.environment().items()):
            argv += ["-e", f"{key}={value}"]
        argv += ["-w", str(workspace_target)]
        argv.append(chosen)
        return argv + command

    def changed_paths(self, prepared: PreparedSandbox) -> list[PathChange]:
        """The changed-path set, read from the host-side upper directory."""
        return read_overlay_diff(prepared.upper_dir, prepared.workspace.root)

    def command_line(self, prepared: PreparedSandbox, command: list[str], **kwargs: str) -> str:
        """The exact command, for the trace and for a human to re-run at a terminal.

        Built from :meth:`build_argv`, so the claim in that sentence is true. An earlier
        version rendered a shortened form while describing itself as exact — harmless
        while unused, and a false fidelity claim the moment it reached a trace.
        """
        return shlex.join(self.build_argv(prepared, command, **kwargs))

    def _force_remove(self, container_name: str) -> None:
        subprocess.run(
            [self.binary, "rm", "-f", container_name],
            capture_output=True,
            text=True,
            check=False,
        )


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def workspace_is_clean(prepared: PreparedSandbox) -> bool:
    """True where nothing was written. Used by ``workspace_unchanged`` (§12.2)."""
    return not any(Path(prepared.upper_dir).iterdir())
