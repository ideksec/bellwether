"""WP-14's live half: confirm TLS interception with a real request (§9.2, §20).

``bellwether doctor`` reported that the recording proxy was configured. It did not establish
that the sandbox *trusts* the proxy's certificate, and those are not the same claim: a container
that rejects the CA makes no observable egress at all, so the run produces a zero-egress trace
that reads as a skill which never touched the network. That is the single most dangerous state
in the tool, and until now nothing executed to rule it out.

This module stands the real sidecar up, runs a client **inside a container on the sandbox's own
internal bridge** with the §9.2 trust environment, has it issue a genuine HTTPS request, and
reads the proxy's recorded flows. The decision the flows feed is
:func:`~bellwether.capture.ca.interpret_interception_probe`, which is pure and tested offline;
what lives here is the standup, which needs a daemon.

**The probe needs no reachable destination — but only because it asks for that explicitly.**
The addon records a flow when the request *arrives*, before any forwarding decision, so a
recorded probe host establishes that the client completed the handshake
against the proxy's certificate whatever the upstream then did. A client that does not trust the
CA fails during that handshake and no flow is ever recorded — which is precisely the distinction
being drawn.

That is not free. mitmproxy's default connection strategy is *eager*: it dials the upstream
**before** the client handshake, so the generated certificate can copy the real one. Under eager
an unresolvable host fails at connect and the request hook never fires. The first cut of this
probe assumed otherwise, and CI said so. The probe's own sidecar therefore runs with
``connection_strategy=lazy``, which completes the client handshake first and defers the upstream
entirely. Runs are untouched: the setting is passed by this module alone, because a proxy that
behaved differently would change what a trace means.

With that, the probe host is an unresolvable name in a reserved TLD and the allowlist denies it:
nothing leaves the machine, no peer server is stood up, and the client still gets a real answer
over TLS it had to trust.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory

from bellwether.capture import EgressAllowlist, InterceptionProbe, interpret_interception_probe
from bellwether.capture.ca import DEFAULT_CA_CONTAINER_PATH
from bellwether.cli.proxy_run import SidecarProxyProvider
from bellwether.errors import BellwetherError

__all__ = [
    "PROBE_CLIENT_SOURCE",
    "PROBE_HOST",
    "PROBE_SIDECAR_SETTINGS",
    "ProbeRunner",
    "probe_argv",
    "run_interception_probe",
]

#: An unresolvable name in the reserved ``.invalid`` TLD (RFC 2606). The probe must never leave
#: the machine, and it does not need to: the flow is recorded on arrival, so reaching the proxy
#: is the whole of what is being established.
PROBE_HOST = "bellwether-interception-probe.invalid"

#: The client, run inside the container. ``urllib`` honours ``SSL_CERT_FILE``, one of the §9.2
#: mechanisms, so a handshake here exercises the real trust path rather than a bespoke one.
#:
#: An HTTP error *is* a success for this purpose — a 403 from the default-deny allowlist means
#: the proxy received the request over TLS the client accepted — so the exception text is
#: printed for the interpreter to read. The exit code is still made non-zero on any exception:
#: it is not what decides the outcome (the recorded flow is), but a client that always exits 0
#: makes the inconclusive message read "client exit 0" whether it ran or not, which is exactly
#: the kind of uninformative signal this project is supposed to refuse.
PROBE_CLIENT_SOURCE = """
import os, sys, urllib.request
url = "https://" + os.environ["BW_PROBE_HOST"] + "/bellwether-probe"
try:
    with urllib.request.urlopen(url, timeout=20) as response:
        print("status", response.status)
except Exception as exc:  # noqa: BLE001 - every outcome is data for the interpreter
    print(type(exc).__name__, exc, file=sys.stderr)
    sys.exit(1)
"""

#: mitmdump settings the probe's sidecar needs, and nothing a run uses. ``lazy`` completes the
#: client handshake before any upstream connection, which is what lets the probe establish CA
#: trust without a reachable destination (see the module docstring).
PROBE_SIDECAR_SETTINGS: dict[str, str] = {"connection_strategy": "lazy"}


@dataclass(frozen=True)
class ProbeRunner:
    """How the probe client is executed. Injected so the standup is testable without a daemon."""

    binary: str = "docker"
    timeout_seconds: float = 120.0

    def run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=self.timeout_seconds, check=False
        )


def probe_argv(
    *,
    image: str,
    network: str,
    environment: dict[str, str],
    ca_host_path: Path,
    binary: str = "docker",
) -> list[str]:
    """The exact command that runs the probe client, built so a human can re-run it.

    The client joins the sandbox's **internal** bridge — the one with no route out — so the
    only way its request can reach anything is through the proxy, exactly as a real run's
    sandbox is placed. The CA is mounted read-only at the same container path the executor
    uses, and the trust environment is the run's own, so this exercises the chain a run would
    get rather than a chain assembled for the test.
    """
    argv = [binary, "run", "--rm", "--network", network]
    for name in sorted(environment):
        argv += ["-e", f"{name}={environment[name]}"]
    argv += ["-e", f"BW_PROBE_HOST={PROBE_HOST}"]
    argv += ["-v", f"{ca_host_path.resolve()}:{DEFAULT_CA_CONTAINER_PATH}:ro"]
    argv += [image, "python3", "-c", PROBE_CLIENT_SOURCE]
    return argv


def run_interception_probe(
    provider: SidecarProxyProvider,
    *,
    client_image: str,
    runner: ProbeRunner | None = None,
    probe_host: str = PROBE_HOST,
) -> InterceptionProbe:
    """Stand the proxy up, issue one real HTTPS request from a container, and decide (§9.2).

    ``client_image`` runs the probe. The sidecar image is the sound default: it is the one
    image guaranteed to carry a Python interpreter, and using it keeps the probe from
    depending on what a particular sandbox image happens to ship.

    The proxy is always torn down, including on failure, so a probe never leaks a bridge or a
    container. A standup that cannot complete raises rather than returning a negative result:
    "the proxy would not start" is not evidence about the CA.
    """
    runner = runner or ProbeRunner()
    # The probe's own proxy, carrying the one setting that makes a destination unnecessary.
    # Applied here rather than asked of the caller, so a probe cannot be stood up without it and
    # then report "inconclusive" for a reason that is really about mitmproxy's defaults.
    provider = replace(
        provider, extra_settings={**provider.extra_settings, **PROBE_SIDECAR_SETTINGS}
    )
    with TemporaryDirectory(prefix="bellwether-probe-") as shared:
        try:
            proxy = provider.open("interception-probe", shared_dir=Path(shared))
        except BellwetherError as error:
            raise BellwetherError(
                f"the interception probe could not stand the recording proxy up: {error}"
            ) from error
        try:
            completed = runner.run(
                probe_argv(
                    image=client_image,
                    network=proxy.sandbox_network(),
                    environment=proxy.sandbox_env(),
                    ca_host_path=proxy.ca_host_path,
                )
            )
            recorded = [flow.host for flow in proxy.flows()]
        finally:
            proxy.close()
    return interpret_interception_probe(
        probe_host,
        recorded,
        exit_code=completed.returncode,
        stderr=completed.stderr,
    )


def probe_allowlist() -> EgressAllowlist:
    """The allowlist the probe's proxy runs with: default-deny, naming nothing.

    The probe host is deliberately *not* allowed. A denied request is still recorded — the
    block is a decision the proxy makes after receiving it — so interception is established either
    way, and refusing to allowlist keeps the probe from widening the egress policy of a run it
    is only meant to check.
    """
    return EgressAllowlist(provider_endpoints=frozenset(), infrastructure_endpoints=frozenset())
