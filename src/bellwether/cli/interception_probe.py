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

from bellwether.capture import (
    CredentialBroker,
    EgressAllowlist,
    InterceptionProbe,
    interpret_interception_probe,
)
from bellwether.capture.ca import DEFAULT_CA_CONTAINER_PATH
from bellwether.cli.proxy_run import SidecarProxyProvider
from bellwether.determinism import SeededRng
from bellwether.errors import BellwetherError

__all__ = [
    "PROBE_CLIENT_NODE",
    "PROBE_CLIENT_PYTHON",
    "PROBE_HOST",
    "PROBE_SIDECAR_SETTINGS",
    "ProbeRunner",
    "probe_allowlist",
    "probe_argv",
    "probe_client_command",
    "run_interception_probe",
]

#: An unresolvable name in the reserved ``.invalid`` TLD (RFC 2606). The probe must never leave
#: the machine, and it does not need to: the flow is recorded on arrival, so reaching the proxy
#: is the whole of what is being established.
PROBE_HOST = "bellwether-interception-probe.invalid"

#: The probe client, as a ``sh`` dispatcher over the interpreters an image might carry.
#:
#: The first cut hard-coded ``python3``, which the shipped ``claude-code`` sandbox image does
#: not have — it carries ``node`` and ``sh`` and nothing else — so the probe could only ever
#: return *inconclusive* on the one image that matters, while the CI proof passed by
#: substituting the sidecar. Node is not a fallback here, it is the point: Node ignores the
#: system trust store and reads ``NODE_EXTRA_CA_CERTS``, which §9.2 singles out as the
#: mechanism that is **not optional**, so probing with it exercises the trust path most likely
#: to be the one that silently fails.
#:
#: Node's core ``https`` does not honour ``HTTPS_PROXY``, so the tunnel is made explicitly:
#: ``CONNECT`` to the proxy, then TLS over that socket. That is exactly the sequence being
#: established — the proxy is reached, and the certificate it presents has to be trusted.
PROBE_CLIENT_NODE = """
const net = require('net'), tls = require('tls');
const proxy = new URL(process.env.HTTPS_PROXY || process.env.https_proxy);
const host = process.env.BW_PROBE_HOST;
const fail = (m) => { console.error(m); process.exit(1); };
const sock = net.connect(Number(proxy.port || 80), proxy.hostname, () => {
  sock.write('CONNECT ' + host + ':443 HTTP/1.1\\r\\nHost: ' + host + ':443\\r\\n\\r\\n');
});
let head = '';
sock.on('error', (e) => fail((e.code || '') + ' ' + e.message));
sock.on('data', (chunk) => {
  head += chunk.toString('latin1');
  if (head.indexOf('\\r\\n\\r\\n') === -1) return;
  sock.removeAllListeners('data');
  if (head.split(' ')[1] !== '200') fail('CONNECT refused: ' + head.split('\\r\\n')[0]);
  const wrapped = tls.connect({ socket: sock, servername: host }, () => {
    wrapped.write('GET /bellwether-probe HTTP/1.1\\r\\nHost: ' + host +
                 '\\r\\nConnection: close\\r\\n\\r\\n');
  });
  wrapped.on('error', (e) => fail((e.code || '') + ' ' + e.message));
  wrapped.on('data', (d) => console.log(d.toString('latin1').split('\\r\\n')[0]));
  wrapped.on('end', () => process.exit(0));
});
"""

#: The same request for an image that carries Python instead. ``urllib`` honours
#: ``SSL_CERT_FILE`` and ``HTTPS_PROXY`` without help, so this one is short.
PROBE_CLIENT_PYTHON = """
import os, sys, urllib.request
url = 'https://' + os.environ['BW_PROBE_HOST'] + '/bellwether-probe'
try:
    with urllib.request.urlopen(url, timeout=20) as response:
        print('status', response.status)
except Exception as exc:
    print(type(exc).__name__, exc, file=sys.stderr)
    sys.exit(1)
"""


def probe_client_command(
    node_source: str = PROBE_CLIENT_NODE, python_source: str = PROBE_CLIENT_PYTHON
) -> str:
    """A ``sh`` command that runs the probe with whatever interpreter the image has.

    An HTTP error *is* a success for this purpose — a 403 from the default-deny allowlist means
    the proxy received the request over TLS the client accepted — so the client prints and the
    recorded flow decides. Exit 127 with no interpreter at all, which the interpreter reads as
    *inconclusive*: an image that cannot make a request tells us nothing about its trust store,
    and saying so is the honest answer.
    """
    return (
        "if command -v node >/dev/null 2>&1; then exec node -e "
        + _sh_quote(node_source)
        + "; elif command -v python3 >/dev/null 2>&1; then exec python3 -c "
        + _sh_quote(python_source)
        + "; else echo 'no node or python3 in this image' >&2; exit 127; fi"
    )


def _sh_quote(source: str) -> str:
    """Single-quote ``source`` for ``sh -c``, closing and reopening around any quote."""
    return "'" + source.replace("'", "'\\''") + "'"


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
    argv += [image, "sh", "-c", probe_client_command()]
    return argv


def run_interception_probe(
    provider: SidecarProxyProvider,
    *,
    client_image: str,
    runner: ProbeRunner | None = None,
    probe_host: str = PROBE_HOST,
) -> InterceptionProbe:
    """Stand the proxy up, issue one real HTTPS request from a container, and decide (§9.2).

    ``client_image`` is the **sandbox** image, and that is not interchangeable with the
    sidecar: the container a run places on the internal bridge is the sandbox, so it is the
    sandbox's trust store the question is about. Probing the sidecar renders an ``ok`` about a
    container no evaluation uses, and cannot fail for the one state this exists to catch.

    The proxy is always torn down, including on failure, so a probe never leaks a bridge or a
    container. A standup that cannot complete raises rather than returning a negative result:
    "the proxy would not start" is not evidence about the CA.
    """
    runner = runner or ProbeRunner()
    # The probe's own proxy, carrying the one setting that makes a destination unnecessary.
    # Applied here rather than asked of the caller, so a probe cannot be stood up without it and
    # then report "inconclusive" for a reason that is really about mitmproxy's defaults.
    provider = replace(
        provider,
        # Default-deny, naming nothing: the probe must not widen the egress policy of the run
        # it is only checking, and a denied request is recorded anyway — the block is a
        # decision the addon makes *after* receiving it, which is all this establishes.
        allowlist=probe_allowlist(),
        # No credential either. The probe sends no model traffic, so brokering a key into its
        # sidecar would put the real key on a container that has no use for it.
        broker=CredentialBroker.for_run({}, {}, rng=SeededRng(0, "interception-probe")),
        provider_of_host={},
        extra_settings={**provider.extra_settings, **PROBE_SIDECAR_SETTINGS},
    )
    with TemporaryDirectory(prefix="bellwether-probe-", ignore_cleanup_errors=True) as shared:
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
        # Decided *inside* the temporary directory's scope. The sidecar runs as root and leaves
        # a root-owned confdir behind, so cleanup can raise for a non-root operator — and a
        # PermissionError raised after a successful probe would be caught upstream as "not
        # probed", silently downgrading the one critical outcome this feature exists to report.
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
