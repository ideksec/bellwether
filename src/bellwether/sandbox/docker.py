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
import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO

from bellwether.errors import BellwetherError
from bellwether.sandbox.overlay import OverlayMount, PathChange, mount_overlay, read_overlay_diff
from bellwether.sandbox.session import PreparedSandbox
from bellwether.sandbox.zones import Zone

__all__ = ["ContainerResult", "DockerBackend", "ExecEnd", "StreamedExec"]

#: Size cap on every fallback ``--tmpfs`` mount. An uncapped tmpfs is a host-DoS: it draws
#: from host memory and a skill filling ``/tmp`` could exhaust it (§9.2 bounds the sandbox's
#: resources for the same reason ``--memory`` does). A captured zone gets a host-side overlay
#: instead; tmpfs is only the fallback for a declared-writable path with no zone overlay, so a
#: fixed, sensible ceiling is enough — it need not track the memory limit.
_TMPFS_SIZE = "256m"

#: Where the pinned machine-id file is bound. Read-only, because pinning it is the whole point
#: (§9.2): a container that could rewrite ``/etc/machine-id`` mid-run would reintroduce exactly
#: the varying identifier the pin removes.
_MACHINE_ID_TARGET = PurePosixPath("/etc/machine-id")


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


@dataclass(frozen=True)
class ExecEnd:
    """How a streamed exec ended."""

    exit_code: int
    timed_out: bool
    stderr_tail: str


@dataclass
class StreamedExec:
    """A running ``docker exec`` whose stdout is consumed line by line (see ``exec_stream``)."""

    process: subprocess.Popen[str]
    timeout: float
    stderr_path: Path
    _stderr_file: IO[str] = field(repr=False)
    timed_out: bool = False

    def lines(self) -> Iterator[str]:
        """Stdout lines as they arrive; the wall clock kills the client at ``timeout``."""
        timer = threading.Timer(self.timeout, self._kill)
        timer.daemon = True
        timer.start()
        try:
            assert self.process.stdout is not None
            yield from self.process.stdout
        finally:
            timer.cancel()

    def _kill(self) -> None:
        self.timed_out = True
        self.process.kill()

    def wait(self) -> ExecEnd:
        code = self.process.wait()
        if self.process.stdout is not None:
            self.process.stdout.close()
        self._stderr_file.close()
        tail = self.stderr_path.read_text(encoding="utf-8") if self.stderr_path.exists() else ""
        return ExecEnd(exit_code=code, timed_out=self.timed_out, stderr_tail=tail[-2000:])


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

    def create_network(self, name: str, *, internal: bool = True) -> str:
        """Create the bridge the sandbox attaches to, isolated from the host by default.

        §3.3 invariant 3 — *no unmediated route out on any protocol* — is enforced here,
        at the Docker network layer, not by hoping the skill respects ``--network none``.
        ``--internal`` builds a bridge with no gateway to the outside: a container on it
        can reach only its peers, so the sole routes out are the recording proxy and the
        controlled resolver, which are those peers. A container that tries to open a socket
        to a public address gets "network is unreachable" from the kernel, before any
        userspace egress code runs — the isolation is a routing fact, not a policy the
        container could talk its way past.

        Idempotent creation is deliberately *not* offered: a name collision means a leaked
        network from a previous run, and silently reusing it would attach this run's
        sandbox to a bridge whose peers we did not place. The caller removes and retries.
        """
        argv = [self.binary, "network", "create", "--driver", "bridge"]
        if internal:
            argv.append("--internal")
        argv.append(name)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            raise BellwetherError(
                f"could not create sandbox network {name!r}: "
                f"{result.stderr.strip() or result.returncode}"
            )
        return name

    def remove_network(self, name: str) -> None:
        """Tear the bridge down. Best-effort, like container removal: a network that never
        existed and one already gone are the same clean end state."""
        subprocess.run(
            [self.binary, "network", "rm", name],
            capture_output=True,
            text=True,
            check=False,
        )

    def connect_network(self, network: str, container: str) -> None:
        """Attach an already-running container to a second network — how the recording
        proxy is dual-homed (§3.3, §10.5).

        The proxy sidecar starts on the internal bridge, the sandbox's only home, so the
        sandbox can reach it but has no route past it. To forward the allowlisted egress
        the proxy also needs a way *out*, which the internal bridge deliberately denies —
        so it is attached, second, to an ordinary (non-``--internal``) bridge with a
        gateway to the host network. The two homes keep the invariant intact: the sandbox
        sees only the internal side, and the sole crossing between the sandbox's world and
        the internet is the proxy process itself, which records every flow. The sandbox is
        never connected here; connecting it would be the unmediated route out §3.3 forbids.
        """
        result = subprocess.run(
            [self.binary, "network", "connect", network, container],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise BellwetherError(
                f"could not connect {container!r} to network {network!r}: "
                f"{result.stderr.strip() or result.returncode}"
            )

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
        extra_env: Mapping[str, str] | None = None,
        extra_ro_binds: Sequence[tuple[Path, PurePosixPath]] | None = None,
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

        ``extra_ro_binds`` mounts host-owned files read-only at container paths — how the
        recording proxy's CA certificate reaches the sandbox so TLS is intercepted (§9.2).
        """
        argv = self.build_argv(
            prepared,
            command,
            image=image,
            network=network,
            sink_bind=sink_bind,
            extra_env=extra_env,
            extra_ro_binds=extra_ro_binds,
        )

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
        dns: str | None = None,
        sink_bind: tuple[Path, PurePosixPath] | None = None,
        extra_env: Mapping[str, str] | None = None,
        extra_ro_binds: Sequence[tuple[Path, PurePosixPath]] | None = None,
    ) -> list[str]:
        """Render the full docker command line.

        The single place an argv is built, so that what is recorded, what is shown to a
        human, and what actually ran cannot drift apart.

        ``extra_env`` is merged over the sandbox's own environment, last-wins. It is how the
        recording proxy is wired in — ``HTTPS_PROXY`` and the CA-trust vars point the container
        at the sidecar (§10.5) — and the values are ordinary env, never a secret: the real key
        never enters the container, only the scoped token (§3.3).

        ``extra_ro_binds`` are host files mounted read-only at container paths, placed after
        the payload so they sit on top of any writable parent — how the proxy CA reaches the
        sandbox's trust store path (§9.2). Read-only because the container never writes them.
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
        if dns is not None:
            # Point the container's resolver at the controlled resolver, by IP (§9.2, §10.6): a
            # single nameserver, so there is no secondary to fall back to, and the internal bridge
            # (no route out) is what makes that the *only* resolver reachable — §3.3 invariant 3.
            # `--dns-opt single-request` keeps glibc from splitting A/AAAA across sockets, so every
            # lookup is one query to one place, the resolver sees them all, and the covert channel
            # cannot leak on a path the log misses.
            #
            # `--dns-search .` clears the search list so it is *empty*, not inherited. A cloud CI
            # runner's host resolv.conf carries a search domain (a GitHub-hosted runner is an Azure
            # VM: `search …dx.internal.cloudapp.net`), and Docker copies the host search list into
            # the container unless told otherwise. glibc/Node then append that suffix to every
            # unqualified lookup, so an allowlisted `api.anthropic.com` also produces a
            # `api.anthropic.com.<search>` query — a name the controlled resolver rightly NXDOMAINs
            # (default-deny, §10.6). That search-list artefact is the runner's environment, not the
            # skill choosing a new destination, but it lands as a `dns_blocked` event and warns the
            # DNS gate. Only the claude-code harness hits it — its model call resolves the endpoint
            # from *inside* the sandbox; the api-loop model runs host-side. Clearing the search list
            # leaves the embedded resolver (127.0.0.11) untouched, so the short proxy alias still
            # resolves; only the phantom suffixed queries disappear.
            argv += ["--dns", dns, "--dns-search", ".", "--dns-option", "single-request"]
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
                # Bounded: an uncapped tmpfs draws unboundedly from host memory (§9.2).
                argv += ["--tmpfs", f"{target}:size={_TMPFS_SIZE}"]

        argv += ["-v", f"{workspace_source}:{workspace_target}:rw"]
        # After the writable mounts, so the read-only payload sits on top of, rather than
        # underneath, a writable parent.
        argv += ["-v", f"{prepared.payload.root}:{prepared.payload.install_path}:ro"]

        # The pinned machine-id (§9.2), bound read-only over /etc/machine-id. Emitted here
        # rather than left to the caller's `extra_ro_binds` so it is applied to every path —
        # one-shot `run`, persistent session, and the recorded `command_line` alike — and so
        # the trace shows the pin that was actually in force. Absent only for a hand-built
        # PreparedSandbox; prepare_sandbox always sets it.
        if prepared.machine_id_file is not None:
            argv += ["-v", f"{prepared.machine_id_file}:{_MACHINE_ID_TARGET}:ro"]

        if sink_bind is not None:
            host_fifo, container_fifo = sink_bind
            # The mount is rw because writing to a FIFO requires it; reading is refused
            # by the node's own write-only permissions, which the host set before any
            # container existed. Mounted after the zone mounts for the same reason as
            # the payload: the file must sit on top of any writable parent.
            argv += ["-v", f"{host_fifo}:{container_fifo}:rw"]

        for host_file, container_file in extra_ro_binds or ():
            # After the payload, so a CA mounted under a writable parent stays read-only —
            # the same ordering discipline the payload mount relies on.
            argv += ["-v", f"{host_file}:{container_file}:ro"]

        merged_env = {**prepared.environment(), **(extra_env or {})}
        for key, value in sorted(merged_env.items()):
            argv += ["-e", f"{key}={value}"]
        argv += ["-w", str(workspace_target)]
        argv.append(chosen)
        return argv + command

    def start_persistent(
        self,
        prepared: PreparedSandbox,
        *,
        image: str | None = None,
        network: str = "none",
        dns: str | None = None,
        sink_bind: tuple[Path, PurePosixPath] | None = None,
        extra_env: Mapping[str, str] | None = None,
        extra_ro_binds: Sequence[tuple[Path, PurePosixPath]] | None = None,
    ) -> str:
        """Start a long-lived container for an agent loop to exec into.

        Same flags, same profile, same mounts as :meth:`run` — :meth:`build_argv` is
        still the single place an argv is built — with the one-shot command replaced by
        an init process that sleeps until :meth:`stop_persistent`. Tool calls then run
        against it via :meth:`exec_in`, so a multi-call agent session shares one
        filesystem, one process namespace, and one identity, the way a real session
        does.
        """
        argv = self.build_argv(
            prepared,
            [],
            image=image,
            network=network,
            dns=dns,
            sink_bind=sink_bind,
            extra_env=extra_env,
            extra_ro_binds=extra_ro_binds,
        )
        # build_argv always renders [binary, "run", ...]; the detach flag goes right
        # after. A numeric sleep rather than `infinity`, because busybox sleep — which
        # the alpine CI image provides — does not accept the GNU spelling.
        argv.insert(2, "-d")
        argv += ["sleep", "2147483647"]

        result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode != 0:
            raise BellwetherError(
                f"could not start a persistent container: {result.stderr.strip() or result.returncode}"
            )
        return prepared.identifiers.container_name

    def exec_in(
        self,
        prepared: PreparedSandbox,
        argv: list[str],
        *,
        stdin: str | None = None,
        timeout: float = 120.0,
    ) -> ContainerResult:
        """Run one command in the persistent container.

        The working directory is the workspace root, matching :meth:`run`'s ``-w``.
        A timeout kills the exec'd process, not the container — one hung tool call must
        surface as a failed call the model can react to, not end the session.
        """
        command = [
            self.binary,
            "exec",
            "--interactive",
            "--workdir",
            str(prepared.identifiers.workspace_root),
            prepared.identifiers.container_name,
            *argv,
        ]
        try:
            result = subprocess.run(
                command,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as expired:
            return ContainerResult(
                exit_code=124,
                stdout=_text(expired.stdout),
                stderr=_text(expired.stderr),
                timed_out=True,
            )
        return ContainerResult(
            exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr
        )

    def exec_stream(
        self,
        prepared: PreparedSandbox,
        argv: list[str],
        *,
        timeout: float,
        stderr_path: Path,
    ) -> StreamedExec:
        """Start one command in the persistent container and stream its stdout.

        The agent-CLI harness (§9.4 adapter 1) is a long-lived process whose structured
        output must be consumed as it is produced — a run killed at the wall clock must leave
        every line up to that point (§11.1). Its stderr goes to a host file, never a pipe:
        an undrained pipe while stdout is being read is a deadlock waiting for a chatty
        harness. The wall clock kills the ``docker exec`` client; the container itself is
        removed by :meth:`stop_persistent` regardless, so nothing outlives the run.
        """
        command = [
            self.binary,
            "exec",
            "--workdir",
            str(prepared.identifiers.workspace_root),
            prepared.identifiers.container_name,
            *argv,
        ]
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_file = stderr_path.open("w", encoding="utf-8")
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            text=True,
        )
        return StreamedExec(
            process=process, timeout=timeout, stderr_path=stderr_path, _stderr_file=stderr_file
        )

    def stop_persistent(self, prepared: PreparedSandbox) -> None:
        self._force_remove(prepared.identifiers.container_name)

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
