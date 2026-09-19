"""The proxy CA trust chain — install it everywhere, then confirm interception (§9.2).

The entire egress design depends on the container trusting the recording proxy's CA, and
several common runtimes ignore the system trust store. **A silent interception failure
produces traces with zero egress — which reads as a clean skill, and is the single most
dangerous failure mode in the tool.** So the CA is installed into *every* mechanism in the
§9.2 table, not just the system store, and ``bellwether doctor`` proves interception end to
end by issuing a real request from inside the container and asserting the proxy recorded it
(§20) — never by assuming.

This module is the host-side core of that: the mechanism table, the environment variables
and system-store commands that install the CA, and :func:`interception_confirmed` — the
predicate doctor applies to the proxy's recorded flows. The command that actually issues the
probe from inside a live container is the sidecar's job (WP-13 pt 2b-ii), validated on CI;
the *decision* it feeds — "did the probe reach the proxy?" — is here and tested.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

__all__ = [
    "CA_MECHANISMS",
    "DEFAULT_CA_CONTAINER_PATH",
    "CaMechanism",
    "InterceptionProbe",
    "ca_trust_environment",
    "interception_confirmed",
    "interpret_interception_probe",
    "system_store_install_commands",
]

#: Where the CA is placed inside the container's system store. ``update-ca-certificates``
#: reads ``/usr/local/share/ca-certificates/*.crt``.
DEFAULT_CA_CONTAINER_PATH = "/usr/local/share/ca-certificates/bellwether-proxy.crt"


@dataclass(frozen=True)
class CaMechanism:
    """One trust mechanism the CA must reach (§9.2), and what it covers.

    ``kind`` is ``"store"`` (a filesystem CA store activated by a command) or ``"env"`` (an
    environment variable naming a bundle a runtime reads instead of the system store).
    """

    kind: Literal["store", "env"]
    name: str
    covers: str


#: The complete §9.2 table. Node ignores the system store and reads a *bundled* CA list, so
#: ``NODE_EXTRA_CA_CERTS`` is not optional; Python's ``requests``/``httpx`` follow ``certifi``
#: via ``REQUESTS_CA_BUNDLE``/``SSL_CERT_FILE``; some curl builds read ``CURL_CA_BUNDLE``; and
#: git over HTTPS reads ``GIT_SSL_CAINFO`` rather than the system store when it is set.
CA_MECHANISMS: tuple[CaMechanism, ...] = (
    CaMechanism("store", "system store", "Go, curl (system build), most C clients"),
    CaMechanism("env", "NODE_EXTRA_CA_CERTS", "Node runtimes (bundled CA list, ignore the store)"),
    CaMechanism("env", "REQUESTS_CA_BUNDLE", "Python requests / httpx via certifi"),
    CaMechanism("env", "SSL_CERT_FILE", "Python ssl / certifi and others"),
    CaMechanism("env", "CURL_CA_BUNDLE", "curl builds that read it"),
    CaMechanism("env", "GIT_SSL_CAINFO", "git over HTTPS"),
)


def ca_trust_environment(ca_path: str = DEFAULT_CA_CONTAINER_PATH) -> dict[str, str]:
    """The env-var half of the §9.2 install: every variable pointing at the CA bundle.

    Handed to the container so the runtimes that ignore the system store still trust the
    proxy. This is the complete set — the subset in :func:`proxy_environment` is convenience;
    the run wiring uses this.
    """
    return {mech.name: ca_path for mech in CA_MECHANISMS if mech.kind == "env"}


def system_store_install_commands(
    ca_source: str, *, container_path: str = DEFAULT_CA_CONTAINER_PATH
) -> list[list[str]]:
    """The commands the sandbox image runs to install the CA into the system store (§9.2).

    ``ca_source`` is where the CA lands in the image; the copy into the store directory plus
    ``update-ca-certificates`` is what activates it for Go and system curl. Returned as argv
    lists so the caller runs them without a shell.
    """
    return [
        ["cp", ca_source, container_path],
        ["update-ca-certificates"],
    ]


def interception_confirmed(recorded_hosts: Iterable[str], probe_host: str) -> bool:
    """Whether a probe request to ``probe_host`` reached the proxy (§9.2, §20).

    Doctor issues a real HTTPS request to ``probe_host`` from inside the container and then
    calls this on the hosts the proxy actually recorded. If the probe host is absent, TLS
    interception silently failed — the CA is not trusted, egress is invisible, and a run
    would produce zero-egress traces that read as a clean skill. Doctor MUST fail loudly on a
    ``False`` here rather than proceed.

    Both sides are put through the same host normalisation (strip, lowercase, drop a trailing
    dot) before comparison, so a probe reported as ``Example.Test`` still matches a recorded
    ``example.test`` — a casing or FQDN-dot mismatch must never read as a failed interception.
    """

    def _normalise(host: str) -> str:
        return host.strip().lower().rstrip(".")

    return _normalise(probe_host) in {_normalise(host) for host in recorded_hosts}


#: Substrings that mean the client rejected the proxy's certificate. Matched case-insensitively
#: against the probe client's stderr. These are the wordings OpenSSL, Python's ``ssl`` and curl
#: produce for an untrusted issuer; the list is deliberately about *trust*, not about any TLS
#: error, so a handshake that failed for another reason stays "inconclusive" rather than being
#: reported as an untrusted CA.
_CA_REJECTION_MARKERS: tuple[str, ...] = (
    "certificate_verify_failed",
    "certificate verify failed",
    "unable to get local issuer certificate",
    "self-signed certificate",
    "self signed certificate",
    "ssl: certificate",
    "unable to verify the first certificate",
)


@dataclass(frozen=True)
class InterceptionProbe:
    """What one CA-in-the-loop probe established (§9.2, §20).

    Three outcomes, kept apart on purpose. ``confirmed`` means the proxy recorded the probe
    host, which can only happen if the client completed a TLS handshake against the proxy's
    own certificate — the trust chain is proven, end to end. ``ca_rejected`` means the client
    refused that certificate: the single most dangerous state in the tool, because a run in
    this condition produces traces with **zero egress that read as a clean skill**.

    Neither confirmed nor rejected is *inconclusive*: the probe never reached the proxy at all
    (no route, the client image lacks the interpreter, the request died before TLS). That is
    reported as its own state rather than folded into either, because "we could not tell" and
    "the CA is not trusted" call for different actions, and neither may be read as a pass.
    """

    confirmed: bool
    ca_rejected: bool
    probe_host: str
    recorded_hosts: tuple[str, ...]
    exit_code: int
    reason: str

    @property
    def inconclusive(self) -> bool:
        return not self.confirmed and not self.ca_rejected


def interpret_interception_probe(
    probe_host: str,
    recorded_hosts: Sequence[str],
    *,
    exit_code: int,
    stderr: str = "",
) -> InterceptionProbe:
    """Decide what a probe run established, from the proxy's flows and the client's output.

    The load-bearing asymmetry: the proxy records a flow when it **receives** the request, so a
    recorded probe host proves the client accepted the proxy's certificate even where the
    upstream was unreachable and the client ultimately got an error. The probe therefore needs
    no reachable destination and no peer server — only a client that trusts the CA. A client
    that does not trust it fails during the handshake, before any flow exists, which is exactly
    the state this probe is for.
    """
    confirmed = interception_confirmed(recorded_hosts, probe_host)
    recorded = tuple(recorded_hosts)
    if confirmed:
        return InterceptionProbe(
            confirmed=True,
            ca_rejected=False,
            probe_host=probe_host,
            recorded_hosts=recorded,
            exit_code=exit_code,
            reason=(
                f"the proxy recorded a request to {probe_host}, so the client completed TLS "
                "against the proxy's own certificate: the CA is trusted and egress is observed"
            ),
        )
    lowered = stderr.lower()
    if any(marker in lowered for marker in _CA_REJECTION_MARKERS):
        return InterceptionProbe(
            confirmed=False,
            ca_rejected=True,
            probe_host=probe_host,
            recorded_hosts=recorded,
            exit_code=exit_code,
            reason=(
                f"the client rejected the proxy's certificate for {probe_host}, so TLS was not "
                "intercepted: a run in this state records no egress at all, which reads as a "
                "skill that made no network calls (§9.2)"
            ),
        )
    return InterceptionProbe(
        confirmed=False,
        ca_rejected=False,
        probe_host=probe_host,
        recorded_hosts=recorded,
        exit_code=exit_code,
        reason=(
            f"the probe did not reach the proxy (client exit {exit_code}) and did not fail on "
            "the certificate, so nothing was established either way — this is not a pass"
        ),
    )
