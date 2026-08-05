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
from bellwether.sandbox.zones import Zone

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
    #: Upper directories whose overlay was mounted at any point, surviving unmount.
    #: A zone in this set with an empty upper dir was *observed to be untouched*; a zone
    #: never in it was *unobserved*. The two must not read the same (§10.7).
    _observed: set[str] = field(default_factory=set, repr=False)

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
        """Mount the overlays: the workspace, then each captured zone (§10.2).

        All three zones get the same treatment — an upper directory on the host — because
        a zone mounted as tmpfs dies with the container and its writes are unobservable.
        If a later mount fails, the earlier ones are unmounted rather than leaked.
        """
        mounted: list[tuple[str, OverlayMount]] = []
        try:
            overlay = mount_overlay(
                lower=prepared.workspace.root,
                upper=prepared.upper_dir,
                work=prepared.work_dir,
                merged=prepared.upper_dir.parent / "merged",
            )
            mounted.append((str(prepared.upper_dir), overlay))
            for zone in prepared.captured_zones:
                zone_mount = mount_overlay(
                    lower=zone.lower, upper=zone.upper, work=zone.work, merged=zone.merged
                )
                mounted.append((str(zone.upper), zone_mount))
        except BellwetherError:
            for _, undo in reversed(mounted):
                undo.unmount()
            raise
        self._mounts.update(mounted)
        self._observed.update(key for key, _ in mounted)
        return overlay

    def unmount(self, prepared: PreparedSandbox) -> None:
        keys = [str(prepared.upper_dir)] + [str(zone.upper) for zone in prepared.captured_zones]
        for key in keys:
            overlay = self._mounts.pop(key, None)
            if overlay is not None:
                overlay.unmount()

    def run(
        self,
        prepared: PreparedSandbox,
        command: list[str],
        *,
        image: str | None = None,
        network: str = "none",
        sink_bind: tuple[Path, PurePosixPath] | None = None,
    ) -> ContainerResult:
        """Run one command in a container under the isolation profile.

        ``network`` defaults to ``none``. The recording proxy and controlled resolver of
        WP-13 and WP-15 replace it with an internal bridge whose only routes out are those
        two; until they exist, no network at all is the honest configuration, because a
        container with unmediated egress would produce traces that under-report it.

        ``sink_bind`` mounts a host-owned event sink FIFO (§10.1) as a single file at the
        given container path. It is passed as plain paths, not as a capture object,
        because the layering runs ``sandbox -> capture`` and the backend must not know
        what consumes the FIFO — only that the file is the harness's event channel.
        """
        argv = self.build_argv(prepared, command, image=image, network=network, sink_bind=sink_bind)

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
        sink_bind: tuple[Path, PurePosixPath] | None = None,
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
        #
        # A path that is a captured zone gets its overlay's merged directory — writes land
        # in a host-side upper dir and survive the container, which is what makes the zone
        # observable at all. Only where the zone's overlay is not mounted does the path
        # fall back to tmpfs: still writable, but its writes vanish with the container,
        # and the filesystem plane's coverage for that zone must say so (§10.7).
        zone_binds = {
            PurePosixPath(zone.container_path): zone
            for zone in prepared.captured_zones
            if str(zone.upper) in self._mounts
        }
        for writable in prepared.isolation.writable_paths:
            target = PurePosixPath(writable)
            if target == workspace_target or workspace_target.is_relative_to(target):
                continue  # the workspace has its own bind mount, below
            zone = zone_binds.get(target)
            if zone is not None:
                argv += ["-v", f"{zone.merged}:{target}:rw"]
            else:
                argv += ["--tmpfs", str(target)]

        argv += ["-v", f"{workspace_source}:{workspace_target}:rw"]
        # After the writable mounts, so the read-only payload sits on top of, rather than
        # underneath, a writable parent.
        argv += ["-v", f"{prepared.payload.root}:{prepared.payload.install_path}:ro"]

        if sink_bind is not None:
            host_fifo, container_fifo = sink_bind
            # The mount is rw because writing to a FIFO requires it; reading is refused
            # by the node's own write-only permissions, which the host set before any
            # container existed. Mounted after the zone mounts for the same reason as
            # the payload: the file must sit on top of any writable parent.
            argv += ["-v", f"{host_fifo}:{container_fifo}:rw"]

        for key, value in sorted(prepared.environment().items()):
            argv += ["-e", f"{key}={value}"]
        argv += ["-w", str(workspace_target)]
        argv.append(chosen)
        return argv + command

    def changed_paths(self, prepared: PreparedSandbox) -> list[PathChange]:
        """The workspace changed-path set, read from the host-side upper directory."""
        return read_overlay_diff(prepared.upper_dir, prepared.workspace.root)

    def zone_changes(self, prepared: PreparedSandbox) -> dict[Zone, list[PathChange]]:
        """The changed-path set of every captured zone, keyed by zone (§10.2).

        The workspace diffs against its fixture lower directory; the other zones start
        empty, so everything observed there is a creation. A zone that was never mounted
        is *absent* from the result rather than present-and-empty — absent means
        unobserved, empty means observed to be untouched, and conflating them is how a
        capture failure reads as a clean run.
        """
        changes: dict[Zone, list[PathChange]] = {
            "workspace": read_overlay_diff(prepared.upper_dir, prepared.workspace.root)
        }
        for zone in prepared.captured_zones:
            if str(zone.upper) in self._observed:
                changes[zone.zone] = read_overlay_diff(zone.upper, zone.lower)
        return changes

    def command_line(
        self,
        prepared: PreparedSandbox,
        command: list[str],
        *,
        image: str | None = None,
        network: str = "none",
        sink_bind: tuple[Path, PurePosixPath] | None = None,
    ) -> str:
        """The exact command, for the trace and for a human to re-run at a terminal.

        Built from :meth:`build_argv`, so the claim in that sentence is true. An earlier
        version rendered a shortened form while describing itself as exact — harmless
        while unused, and a false fidelity claim the moment it reached a trace.
        """
        return shlex.join(
            self.build_argv(prepared, command, image=image, network=network, sink_bind=sink_bind)
        )

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
