"""The host side of the recording-proxy sidecar — start it, read its flows, stop it (§10.5).

:class:`MitmproxySidecar` is the :class:`RecordingProxy` the analysis path talks to. It runs the
``mitmdump`` container built from ``sidecar/proxy`` on the run's internal bridge, hands it the
non-secret config on a shared volume, and reads back the flow log the sidecar writes. The
inside-the-container half — the addon that decides and records — is :mod:`bellwether.capture.sidecar_entry`;
this is only the lifecycle around it.

Two host-side security properties live here and are what the offline tests pin:

- **The real key never reaches the command line.** The sidecar needs the real credential, but a
  ``-e KEY=value`` flag would put it in the process table and in any recorded command. Instead the
  launcher passes ``-e KEY`` (name only) and runs ``docker`` with the key in its *own* environment,
  so docker forwards the value and it appears in no argv, no trace, no artifact (§3.3).
- **Readiness is the flow log appearing, not a guess.** The entry writes an empty flow log the
  instant it loads (``sidecar_entry`` §10.5), so the log's appearance is proof mitmdump came up and
  registered the addon — and its *absence* after a run is proof the proxy never ran, which
  :meth:`flows` turns into a loud failure rather than a clean-looking zero-egress trace (§14).

The ``runner`` and ``sleep`` seams let the whole lifecycle be tested without a daemon, the same way
:meth:`DockerBackend.build_argv` is; the live standup against a real ``mitmproxy`` container is the
docker-marked test, on CI.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from bellwether.capture.credential import CredentialBroker
from bellwether.capture.egress import CapLedger, EgressAllowlist, EgressFlow, RecordingProxy
from bellwether.capture.proxy_addon import read_flow_records
from bellwether.capture.sidecar_entry import CONFIG_ENV_VAR, SidecarConfig
from bellwether.errors import BellwetherError

__all__ = ["MitmproxySidecar", "SidecarHandle"]

#: Where the host's shared directory is mounted inside the sidecar. Config and flow log live here,
#: written by the host and by the sidecar respectively — the shared volume of §10.5.
SIDECAR_SHARED_MOUNT = PurePosixPath("/bw")

#: The mitmdump entry the image runs (placed there by ``sidecar/proxy/Dockerfile``). A fixed path
#: rather than the installed package location, so the argv does not depend on a site-packages layout.
SIDECAR_ENTRY_PATH = "/opt/bw/proxy_entry.py"

#: Filenames on the shared volume.
_CONFIG_NAME = "config.json"
_FLOW_LOG_NAME = "flows.jsonl"

#: The mitmproxy confdir, on the shared volume so the host can read the CA the proxy generates.
#: mitmproxy writes its CA files here on first start; the sandbox trusts one of them (§9.2).
_CONFDIR_NAME = "mitmproxy"
#: The PEM-encoded CA certificate mitmproxy writes into its confdir. This is the client-trust
#: form the sandbox's CA-bundle env vars point at; the ``.crt`` copy for a system store is a
#: build-time concern the read-only, non-root sandbox cannot run ``update-ca-certificates`` for.
_CA_CERT_NAME = "mitmproxy-ca-cert.pem"


@dataclass(frozen=True)
class SidecarHandle:
    """The resolved identifiers and host paths of one running sidecar, so argv, config, and flow
    reads all agree on where things are."""

    run_id: str
    container_name: str
    proxy_url: str
    config_host_path: Path
    flow_log_host_path: Path
    ca_cert_host_path: Path


@dataclass
class MitmproxySidecar(RecordingProxy):
    """A :class:`RecordingProxy` backed by a ``mitmdump`` sidecar container (§10.5).

    Constructed per evaluation with the run's broker and topology; :meth:`start` is called per run
    with that run's allowlist and caps (the :class:`RecordingProxy` contract). The sandbox is
    pointed at :attr:`SidecarHandle.proxy_url`, which is the sidecar reachable by container name on
    the internal bridge.
    """

    image: str
    network: str
    broker: CredentialBroker
    provider_of_host: Mapping[str, str]
    shared_dir: Path
    binary: str = "docker"
    listen_port: int = 8080
    ready_timeout: float = 30.0
    #: Seams. ``runner`` runs a command (default: real subprocess); ``sleep`` paces the readiness
    #: poll. Both are injected in tests so the lifecycle runs without a daemon or real waiting.
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
    sleep: Callable[[float], None] = time.sleep
    _handle: SidecarHandle | None = field(default=None, repr=False)

    def sidecar_argv(self, container_name: str, config_container_path: PurePosixPath) -> list[str]:
        """The full ``docker run`` command for the sidecar.

        The real keys are named with ``-e KEY`` and *not* valued: docker forwards them from the
        launcher's own environment, so the credential never appears in this argv.
        """
        argv = [self.binary, "run", "--rm", "-d", "--name", container_name]
        argv += ["--network", self.network]
        argv += ["-v", f"{self.shared_dir}:{SIDECAR_SHARED_MOUNT}:rw"]
        for env_name in sorted(self.broker.sidecar_real_key_env()):
            argv += ["-e", env_name]  # name only — value forwarded from the launcher's env
        argv += ["-e", f"{CONFIG_ENV_VAR}={config_container_path}"]
        argv += [
            self.image,
            "mitmdump",
            "--listen-host",
            "0.0.0.0",
            "--listen-port",
            str(self.listen_port),
            "-s",
            SIDECAR_ENTRY_PATH,
            # A proxy on an internal bridge legitimately forwards to non-public peers; without
            # this mitmproxy refuses "global" destinations and the fake-provider tests cannot run.
            "--set",
            "block_global=false",
            # Put the CA in the shared volume, so the host can mount it into the sandbox and TLS
            # is actually intercepted rather than silently failing to a zero-egress trace (§9.2).
            "--set",
            f"confdir={SIDECAR_SHARED_MOUNT / _CONFDIR_NAME}",
        ]
        return argv

    def build_config(self, *, allowlist: EgressAllowlist, caps: CapLedger) -> SidecarConfig:
        """The non-secret config the sidecar reads, assembled from the run's allowlist and caps and
        this proxy's broker export and host map. No real key is here — only the scoped tokens."""
        return SidecarConfig(
            provider_endpoints=tuple(sorted(allowlist.provider_endpoints)),
            infrastructure_endpoints=tuple(sorted(allowlist.infrastructure_endpoints)),
            allowlist_extra=tuple(sorted(allowlist.extra)),
            provider_of_host=dict(self.provider_of_host),
            credential_export=self.broker.sidecar_export(),
            max_requests=caps.max_requests,
            max_request_bytes=caps.max_request_bytes,
            flow_log_path=str(SIDECAR_SHARED_MOUNT / _FLOW_LOG_NAME),
            listen_port=self.listen_port,
        )

    def start(self, run_id: str, *, allowlist: EgressAllowlist, caps: CapLedger) -> None:
        container_name = f"bw-proxy-{run_id}"
        config_host = self.shared_dir / _CONFIG_NAME
        flow_log_host = self.shared_dir / _FLOW_LOG_NAME
        ca_cert_host = self.shared_dir / _CONFDIR_NAME / _CA_CERT_NAME
        config_container = SIDECAR_SHARED_MOUNT / _CONFIG_NAME

        self.shared_dir.mkdir(parents=True, exist_ok=True)
        # A stale flow log from a crashed prior run would make readiness trivially true and hand
        # this run someone else's flows; remove it before the sidecar recreates it.
        flow_log_host.unlink(missing_ok=True)
        config_host.write_text(
            self.build_config(allowlist=allowlist, caps=caps).to_json(), encoding="utf-8"
        )

        result = self.runner(
            self.sidecar_argv(container_name, config_container),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            raise BellwetherError(
                f"could not start the recording-proxy sidecar: "
                f"{result.stderr.strip() or result.returncode}"
            )

        self._handle = SidecarHandle(
            run_id=run_id,
            container_name=container_name,
            proxy_url=f"http://{container_name}:{self.listen_port}",
            config_host_path=config_host,
            flow_log_host_path=flow_log_host,
            ca_cert_host_path=ca_cert_host,
        )
        self._await_ready(flow_log_host, container_name)

    def _await_ready(self, flow_log_host: Path, container_name: str) -> None:
        """Wait for the sidecar to write its empty flow log — proof mitmdump loaded the addon.

        A timeout is a hard failure: a proxy that never came up must not be treated as one that
        saw no egress. The reason names the container so its logs can be inspected.
        """
        deadline = self.ready_timeout
        waited = 0.0
        step = 0.1
        while waited <= deadline:
            if flow_log_host.exists():
                return
            self.sleep(step)
            waited += step
        raise BellwetherError(
            f"recording-proxy sidecar {container_name} did not become ready within "
            f"{self.ready_timeout:g}s (no flow log written); check its container logs"
        )

    def proxy_url(self) -> str:
        """The URL the sandbox uses as its ``HTTPS_PROXY`` — the sidecar on the bridge."""
        return self._require_handle().proxy_url

    def container_name(self) -> str:
        """The running sidecar's container name, so the launcher can attach it to a second
        network for dual-homing (§3.3): internal bridge in, egress bridge out."""
        return self._require_handle().container_name

    def ca_cert_path(self) -> Path:
        """The host path of the proxy's CA certificate, once the sidecar has written it (§9.2).

        mitmproxy generates its CA into the confdir on the shared volume when its proxy server
        first starts, which can lag the addon's flow-log readiness signal — so this waits for
        the file rather than assuming it. A CA that never appears is a hard failure, not a quiet
        fall-through to an untrusted proxy, which would produce the zero-egress trace §9.2 warns
        of: the sandbox would trust no CA, every HTTPS connect would fail, and the run would read
        as a clean skill that simply made no requests.
        """
        handle = self._require_handle()
        deadline = self.ready_timeout
        waited = 0.0
        step = 0.1
        while waited <= deadline:
            if handle.ca_cert_host_path.exists():
                return handle.ca_cert_host_path
            self.sleep(step)
            waited += step
        raise BellwetherError(
            f"recording-proxy sidecar {handle.container_name} wrote no CA certificate at "
            f"{handle.ca_cert_host_path} within {self.ready_timeout:g}s; the sandbox would trust "
            "no proxy CA and every HTTPS request would fail invisibly (§9.2)"
        )

    def flows(self) -> list[EgressFlow]:
        """The recorded flows. A missing log raises (via :func:`read_flow_records`) — the sidecar
        always writes it, so absence means it never ran, never that the run was clean."""
        return read_flow_records(self._require_handle().flow_log_host_path)

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

    def _require_handle(self) -> SidecarHandle:
        if self._handle is None:
            raise BellwetherError("the recording-proxy sidecar has not been started")
        return self._handle
