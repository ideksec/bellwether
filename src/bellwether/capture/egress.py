"""Plane D — network egress semantics, host-side (§10.5).

All container TCP traffic routes through a recording proxy running as a sidecar (§10.5,
§22). This module is the *host-side* half of that plane: the deterministic semantics the
proxy applies and the analysis consumes — classification, the default-deny allowlist,
per-run caps, header redaction, and the egress-induced-failure correlation. The sidecar
itself (mitmproxy, the bridge, credential injection) is the container half and plugs in
behind :class:`RecordingProxy`, exactly as the sandbox backend plugs in behind ``Sandbox``.

Two rules here carry the plane's whole point:

- **Classify before assertions see it (§10.5.0).** Agent CLIs emit telemetry and check for
  updates; without separating that from skill-attributed traffic, ``no_egress`` never
  passes for any skill on any real harness. Each flow is labelled ``model_api`` /
  ``harness_infrastructure`` / ``skill_attributed`` at capture, and only the last counts.
- **A blocked attempt is evidence, not an error (§10.5.0).** Default-deny; every blocked
  request is recorded as ``egress_blocked`` and must never fail the run for infrastructure
  reasons. When a run has *both* assertion failures and blocked egress, the failure may be
  infrastructure-shaped, so it is flagged ``possible_egress_induced_failure``, excluded
  from quality metrics, and kept in full for security metrics.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from bellwether.determinism import stable_hash

__all__ = [
    "DEFAULT_HEADER_ALLOWLIST",
    "CapLedger",
    "EgressAllowlist",
    "EgressClass",
    "EgressFlow",
    "RecordingProxy",
    "classify_egress",
    "correlate_egress_induced_failure",
    "make_flow",
    "provider_hosts",
    "redact_headers",
]

#: The three egress classes (§10.5.0). Only ``skill_attributed`` counts toward ``no_egress``.
EgressClass = Literal["model_api", "harness_infrastructure", "skill_attributed"]

#: Request header names recorded verbatim; everything else is redacted to a placeholder.
#: An allowlist, not a denylist, because the failure mode to avoid is a *new* auth header
#: (``x-goog-api-key``, ``anthropic-key``) leaking a real credential into an artifact — a
#: denylist that has to enumerate every such header is one forgotten name from a leak.
DEFAULT_HEADER_ALLOWLIST: frozenset[str] = frozenset(
    {
        "accept",
        "accept-encoding",
        "content-type",
        "content-length",
        "user-agent",
        "host",
        "anthropic-version",
        "x-stainless-lang",
    }
)

_REDACTED = "<redacted>"


def _norm_host(host: str) -> str:
    """A host to compare on: lowercased, port and trailing dot stripped."""
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:  # bracketed IPv6 literal
        return host[1 : host.index("]")]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _host_matches(host: str, endpoint: str) -> bool:
    """True if ``host`` is ``endpoint`` or a subdomain of it.

    ``api.anthropic.com`` matches ``api.anthropic.com`` and ``eu.api.anthropic.com`` but
    never ``notanthropic.com`` — suffix matching on a label boundary, so a lookalike domain
    cannot smuggle itself in as infrastructure.
    """
    host = _norm_host(host)
    endpoint = _norm_host(endpoint)
    if not host or not endpoint:
        return False
    return host == endpoint or host.endswith("." + endpoint)


def provider_hosts(base_urls: Iterable[str]) -> frozenset[str]:
    """The hosts of the configured provider ``base_url`` values (§9.4).

    A request to one of these is ``model_api`` — the one endpoint that is authenticated and
    allowlisted by construction (§10.5.2).
    """
    hosts: set[str] = set()
    for url in base_urls:
        parsed = urlsplit(url if "://" in url else f"//{url}", scheme="https")
        if parsed.hostname:
            hosts.add(_norm_host(parsed.hostname))
    return frozenset(hosts)


def classify_egress(
    host: str,
    *,
    provider_endpoints: Iterable[str],
    infrastructure_endpoints: Iterable[str],
) -> EgressClass:
    """Classify one request's host (§10.5.0), model API first, then harness infrastructure.

    Order matters: the model API is checked before infrastructure so a provider host is
    never mistaken for telemetry. Everything unmatched is ``skill_attributed`` — the class
    that counts toward ``no_egress`` — which is the conservative default: an unknown host is
    attributed to the skill until proven infrastructure.
    """
    if any(_host_matches(host, endpoint) for endpoint in provider_endpoints):
        return "model_api"
    if any(_host_matches(host, endpoint) for endpoint in infrastructure_endpoints):
        return "harness_infrastructure"
    return "skill_attributed"


@dataclass(frozen=True)
class EgressAllowlist:
    """The default-deny egress allowlist (§10.5.0 enforcement).

    A host is permitted only if it is a configured provider endpoint, a declared harness
    infrastructure endpoint, or an explicit allowlist entry. Nothing else — the proxy
    blocks it and records ``egress_blocked``. Provider and infrastructure endpoints are
    always permitted, because blocking the model API or the harness's own telemetry would
    fail runs for infrastructure reasons, which §10.5.0 forbids.
    """

    provider_endpoints: frozenset[str]
    infrastructure_endpoints: frozenset[str]
    extra: frozenset[str] = frozenset()

    def permits(self, host: str) -> bool:
        return any(
            _host_matches(host, endpoint)
            for endpoint in (*self.provider_endpoints, *self.infrastructure_endpoints, *self.extra)
        )

    def block_reason(self, host: str) -> str:
        return (
            ""
            if self.permits(host)
            else f"{_norm_host(host)} is not in the egress allowlist (default-deny, §10.5.0)"
        )


@dataclass
class CapLedger:
    """Per-run request and byte caps on the sandbox-scoped token (§10.5.1).

    Bounds volume exfiltration through the residual model-API channel (§3.3). The proxy
    consults this before forwarding; a request that would cross a cap is refused and the run
    records ``exit_reason: budget_exceeded`` (§10.5.1) — an operator limit, not a skill
    failure, so it is ``not_evaluable`` rather than a fail (§12.7).
    """

    max_requests: int
    max_request_bytes: int
    requests: int = 0
    request_bytes: int = 0

    def would_exceed(self, next_body_bytes: int) -> str | None:
        """The cap ``next_body_bytes`` would cross, or ``None`` if it fits."""
        if self.requests + 1 > self.max_requests:
            return "max_requests"
        if self.request_bytes + next_body_bytes > self.max_request_bytes:
            return "max_request_bytes"
        return None

    def record(self, body_bytes: int) -> None:
        self.requests += 1
        self.request_bytes += body_bytes


def redact_headers(
    headers: Mapping[str, str], *, allowlist: frozenset[str] = DEFAULT_HEADER_ALLOWLIST
) -> dict[str, str]:
    """Keep allowlisted headers verbatim; redact every other value (§10.5).

    The header *names* are kept so the shape of the request is still legible — a redacted
    ``authorization`` is visible as present without its value reaching an artifact.
    """
    return {
        name: (value if name.lower() in allowlist else _REDACTED)
        for name, value in sorted(headers.items())
    }


@dataclass(frozen=True)
class EgressFlow:
    """One captured request/response, classified and allowlist-checked (§10.5).

    The request body is never carried here — only its length and digest — because a body
    may hold a credential or a canary and this record ends up in an artifact. Canary
    *scanning* of bodies happens in the proxy before this record exists (§10.5.2, WP-16);
    what survives to the trace is the digest and the byte count.
    """

    ts: str
    method: str
    scheme: str
    host: str
    port: int
    path: str
    egress_class: EgressClass
    blocked: bool
    request_headers: Mapping[str, str] = field(default_factory=dict)
    request_body_bytes: int = 0
    request_body_sha256: str = ""
    response_status: int | None = None
    response_size: int | None = None
    sni: str = ""
    block_reason: str = ""

    @property
    def counts_as_egress(self) -> bool:
        """Whether this flow counts toward ``no_egress`` (§10.5.0): only skill-attributed,
        and only if it was actually permitted — a blocked attempt is a separate record."""
        return self.egress_class == "skill_attributed" and not self.blocked


def make_flow(
    *,
    ts: str,
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    provider_endpoints: Iterable[str],
    infrastructure_endpoints: Iterable[str],
    allowlist: EgressAllowlist,
    request_headers: Mapping[str, str] | None = None,
    request_body: bytes = b"",
    response_status: int | None = None,
    response_size: int | None = None,
    sni: str = "",
) -> EgressFlow:
    """Build a classified, allowlist-checked, redacted :class:`EgressFlow` from a request.

    This is the one place a raw request becomes a record fit for an artifact: it classifies
    (§10.5.0), applies the default-deny allowlist, redacts headers, and reduces the body to a
    digest and a length so no credential or canary value survives. The proxy sidecar calls it
    per flow.
    """
    egress_class = classify_egress(
        host,
        provider_endpoints=provider_endpoints,
        infrastructure_endpoints=infrastructure_endpoints,
    )
    permitted = allowlist.permits(host)
    return EgressFlow(
        ts=ts,
        method=method,
        scheme=scheme,
        host=_norm_host(host),
        port=port,
        path=path,
        egress_class=egress_class,
        blocked=not permitted,
        request_headers=redact_headers(request_headers or {}),
        request_body_bytes=len(request_body),
        request_body_sha256=stable_hash(request_body) if request_body else "",
        response_status=response_status,
        response_size=response_size,
        sni=sni,
        block_reason=allowlist.block_reason(host),
    )


def correlate_egress_induced_failure(*, assertion_failed: bool, blocked_flows: int) -> bool:
    """§10.5.0: a run with both assertion failures and blocked egress may have failed for an
    infrastructure reason, not a skill one. Flag it so it can be excluded from quality
    metrics and retained for security metrics — the caller does that split."""
    return assertion_failed and blocked_flows > 0


class RecordingProxy:
    """The recording-proxy seam (§10.5, §22).

    A ``Protocol`` in spirit: the mitmproxy sidecar implements it (the container half,
    landing next), and the analysis path depends only on this surface — start a run,
    read its flows, stop — so the proxy can be swapped without touching capture code, the
    same treatment the sandbox backend gets. Kept a base class with a ``NotImplementedError``
    body rather than a bare ``Protocol`` so a partial implementation fails loudly instead of
    silently observing nothing (a zero-egress trace reads as a clean skill — §14/WP-14).
    """

    def start(self, run_id: str, *, allowlist: EgressAllowlist, caps: CapLedger) -> None:
        raise NotImplementedError

    def flows(self) -> list[EgressFlow]:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError
