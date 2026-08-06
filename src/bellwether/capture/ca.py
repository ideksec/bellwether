"""The proxy CA trust chain — install it everywhere, then prove interception (§9.2).

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

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

__all__ = [
    "CA_MECHANISMS",
    "DEFAULT_CA_CONTAINER_PATH",
    "CaMechanism",
    "ca_trust_environment",
    "interception_confirmed",
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
#: via ``REQUESTS_CA_BUNDLE``/``SSL_CERT_FILE``; some curl builds read ``CURL_CA_BUNDLE``.
CA_MECHANISMS: tuple[CaMechanism, ...] = (
    CaMechanism("store", "system store", "Go, curl (system build), most C clients"),
    CaMechanism("env", "NODE_EXTRA_CA_CERTS", "Node runtimes (bundled CA list, ignore the store)"),
    CaMechanism("env", "REQUESTS_CA_BUNDLE", "Python requests / httpx via certifi"),
    CaMechanism("env", "SSL_CERT_FILE", "Python ssl / certifi and others"),
    CaMechanism("env", "CURL_CA_BUNDLE", "curl builds that read it"),
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
    """
    return probe_host in {host.strip().lower().rstrip(".") for host in recorded_hosts}
