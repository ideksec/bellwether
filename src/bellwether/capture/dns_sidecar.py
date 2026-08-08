"""The host side of the controlled-resolver sidecar — start it, read its queries, stop it (§10.6).

:class:`DnsResolverSidecar` is the :class:`ControlledResolver` the analysis path talks to. It runs
the resolver container built from ``sidecar/resolver`` on the run's internal bridge, hands it the
non-secret config on a shared volume, and reads back the query log the resolver writes. The
inside-the-container half — the dnslib server that decides and records — is
:mod:`bellwether.capture.resolver_entry`; this is only the lifecycle around it. It is the DNS
analog of :class:`~bellwether.capture.sidecar.MitmproxySidecar`, minus the credential machinery a
resolver has no use for (it injects nothing).

Two host-side properties live here and are what the offline tests pin:

- **Readiness is the query log appearing, not a guess.** The entry writes an empty query log the
  instant it loads (:mod:`resolver_entry` §10.6), so the log's appearance is proof the resolver
  came up — and its *absence* after a run is proof it never ran, which :meth:`queries` turns into a
  loud failure rather than a clean-looking zero-query trace.
- **The sandbox reaches the resolver by IP, not name.** Docker ``--dns`` takes an address, so the
  launcher needs the resolver's bridge IP; :meth:`resolver_ip` reads it off the running container.
  (The recording proxy is reached by container name via ``HTTPS_PROXY``; DNS cannot be, because
  ``--dns`` is resolved before any name resolution exists.)

The ``runner`` and ``sleep`` seams let the whole lifecycle be tested without a daemon, the same way
:class:`MitmproxySidecar` is; the live standup against a real resolver container is the
docker-marked test, on CI.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from bellwether.capture.dns import ControlledResolver, DnsAllowlist, DnsQuery, read_query_records
from bellwether.capture.resolver_entry import (
    DEFAULT_UPSTREAM,
    RESOLVER_CONFIG_ENV_VAR,
    ResolverConfig,
)
from bellwether.errors import BellwetherError

__all__ = ["DnsResolverSidecar", "ResolverHandle"]

#: Where the host's shared directory is mounted inside the resolver. Config and query log live
#: here, written by the host and by the resolver respectively — the shared volume of §10.6.
RESOLVER_SHARED_MOUNT = PurePosixPath("/bw")

#: The entry the resolver image runs (placed there by ``sidecar/resolver/Dockerfile``). A fixed
#: path rather than the installed package location, so the argv does not depend on a site-packages
#: layout — the same treatment the proxy's entry gets.
RESOLVER_ENTRY_PATH = "/opt/bw/resolver_entry.py"

#: Filenames on the shared volume.
_CONFIG_NAME = "resolver-config.json"
_QUERY_LOG_NAME = "queries.jsonl"


@dataclass(frozen=True)
class ResolverHandle:
    """The resolved identifiers and host paths of one running resolver, so argv, config, and query
    reads all agree on where things are."""

    run_id: str
    container_name: str
    config_host_path: Path
    query_log_host_path: Path


@dataclass
class DnsResolverSidecar(ControlledResolver):
    """A :class:`ControlledResolver` backed by a resolver sidecar container (§10.6).

    Constructed per evaluation with the run's image and topology; :meth:`start` is called per run
    with that run's allowlist (the :class:`ControlledResolver` contract). The sandbox is pointed at
    :meth:`resolver_ip` via ``docker --dns``.
    """

    image: str
    network: str
    shared_dir: Path
    binary: str = "docker"
    listen_port: int = 53
    upstream: str = DEFAULT_UPSTREAM
    ready_timeout: float = 30.0
    #: Seams. ``runner`` runs a command (default: real subprocess); ``sleep`` paces the readiness
    #: poll. Both are injected in tests so the lifecycle runs without a daemon or real waiting.
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
    sleep: Callable[[float], None] = time.sleep
    _handle: ResolverHandle | None = field(default=None, repr=False)

    def resolver_argv(self, container_name: str, config_container_path: PurePosixPath) -> list[str]:
        """The full ``docker run`` command for the resolver.

        No ``-e KEY`` credential channel: the resolver holds no keys. The image's entry is a small
        script that loads the config from ``RESOLVER_CONFIG_ENV_VAR`` and runs the dnslib UDP server.
        """
        argv = [self.binary, "run", "--rm", "-d", "--name", container_name]
        argv += ["--network", self.network]
        argv += ["-v", f"{self.shared_dir}:{RESOLVER_SHARED_MOUNT}:rw"]
        argv += ["-e", f"{RESOLVER_CONFIG_ENV_VAR}={config_container_path}"]
        argv += [self.image, "python", RESOLVER_ENTRY_PATH]
        return argv

    def build_config(self, *, allowlist: DnsAllowlist) -> ResolverConfig:
        """The non-secret config the resolver reads, assembled from the run's allowlist. Sorted so
        two identical runs write the same config bytes (§24)."""
        return ResolverConfig(
            allowed=tuple(sorted(allowlist.allowed)),
            query_log_path=str(RESOLVER_SHARED_MOUNT / _QUERY_LOG_NAME),
            upstream=self.upstream,
            listen_port=self.listen_port,
        )

    def start(self, run_id: str, *, allowlist: DnsAllowlist) -> None:
        container_name = f"bw-resolver-{run_id}"
        config_host = self.shared_dir / _CONFIG_NAME
        query_log_host = self.shared_dir / _QUERY_LOG_NAME
        config_container = RESOLVER_SHARED_MOUNT / _CONFIG_NAME

        self.shared_dir.mkdir(parents=True, exist_ok=True)
        # A stale query log from a crashed prior run would make readiness trivially true and hand
        # this run someone else's queries; remove it before the resolver recreates it.
        query_log_host.unlink(missing_ok=True)
        config_host.write_text(self.build_config(allowlist=allowlist).to_json(), encoding="utf-8")

        result = self.runner(
            self.resolver_argv(container_name, config_container),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            raise BellwetherError(
                f"could not start the controlled-resolver sidecar: "
                f"{result.stderr.strip() or result.returncode}"
            )

        self._handle = ResolverHandle(
            run_id=run_id,
            container_name=container_name,
            config_host_path=config_host,
            query_log_host_path=query_log_host,
        )
        self._await_ready(query_log_host, container_name)

    def _await_ready(self, query_log_host: Path, container_name: str) -> None:
        """Wait for the resolver to write its empty query log — proof the server came up.

        A timeout is a hard failure: a resolver that never came up must not be treated as one that
        saw no queries. The reason names the container so its logs can be inspected.
        """
        deadline = self.ready_timeout
        waited = 0.0
        step = 0.1
        while waited <= deadline:
            if query_log_host.exists():
                return
            self.sleep(step)
            waited += step
        raise BellwetherError(
            f"controlled-resolver sidecar {container_name} did not become ready within "
            f"{self.ready_timeout:g}s (no query log written); check its container logs"
        )

    def container_name(self) -> str:
        """The running resolver's container name."""
        return self._require_handle().container_name

    def resolver_ip(self) -> str:
        """The resolver's IP on the internal bridge, for the sandbox's ``docker --dns`` (§9.2).

        Read off the running container with ``docker inspect``; the network name is looked up via
        ``index`` because it contains hyphens (``bw-int-<run_id>``), which a bare Go-template field
        access cannot express. An empty or missing address is a hard failure — a sandbox pointed at
        no resolver would fall through to whatever ``resolv.conf`` it inherited, reopening the
        uncontrolled DNS channel §10.6 exists to close.
        """
        handle = self._require_handle()
        template = f'{{{{ (index .NetworkSettings.Networks "{self.network}").IPAddress }}}}'
        result = self.runner(
            [self.binary, "inspect", "-f", template, handle.container_name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        ip = result.stdout.strip() if result.returncode == 0 else ""
        if not ip:
            raise BellwetherError(
                f"could not read the controlled-resolver {handle.container_name}'s IP on "
                f"{self.network!r}: {result.stderr.strip() or 'no address'}; the sandbox cannot be "
                "pointed at it and DNS would be uncontrolled (§10.6)"
            )
        return ip

    def queries(self) -> list[DnsQuery]:
        """The recorded queries. A missing log raises (via :func:`read_query_records`) — the
        resolver always writes it, so absence means it never ran, never that the run was clean."""
        return read_query_records(self._require_handle().query_log_host_path)

    def stop(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self.runner(
            [self.binary, "rm", "-f", handle.container_name],
            capture_output=True,
            text=True,
            check=False,
        )

    def _require_handle(self) -> ResolverHandle:
        if self._handle is None:
            raise BellwetherError("the controlled-resolver sidecar has not been started")
        return self._handle
