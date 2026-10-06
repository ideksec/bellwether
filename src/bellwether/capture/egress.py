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

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from bellwether.capture.canary import Canary, scan_for_canaries
from bellwether.determinism import stable_hash
from bellwether.errors import ConfigurationError, UserFacingProblem

__all__ = [
    "DEFAULT_EGRESS_PORTS",
    "DEFAULT_HEADER_ALLOWLIST",
    "CapLedger",
    "EgressAllowlist",
    "EgressCanaryHit",
    "EgressClass",
    "EgressFlow",
    "RecordingProxy",
    "classify_egress",
    "correlate_egress_induced_failure",
    "identity_mismatch",
    "make_flow",
    "provider_authorities",
    "provider_hosts",
    "redact_headers",
]

#: The three egress classes (§10.5.0). Only ``skill_attributed`` counts toward ``no_egress``.
EgressClass = Literal["model_api", "harness_infrastructure", "skill_attributed"]

#: Request header names recorded verbatim; everything else is redacted to a placeholder.
#: An allowlist, not a denylist, because the failure mode to avoid is a *new* auth header
#: (``x-goog-api-key``, ``anthropic-key``) leaking a real credential into an artifact — a
#: denylist that has to enumerate every such header is one forgotten name from a leak.
#: Only *structural* headers are kept: values that describe the request's shape, not
#: attacker-controlled free text. ``user-agent`` and ``accept`` are skill/client free text —
#: a skill can write a secret into either — so they are redacted like any other value.
DEFAULT_HEADER_ALLOWLIST: frozenset[str] = frozenset(
    {
        "accept-encoding",
        "content-type",
        "content-length",
        "host",
        "anthropic-version",
        "x-stainless-lang",
    }
)

_REDACTED = "<redacted>"


def _norm_host(host: str) -> str:
    """The host a real client routes to, normalised for comparison.

    Parsed with :func:`urllib.parse.urlsplit` exactly as :func:`provider_hosts` parses a
    ``base_url``, so an RFC-3986 authority is read the way a client reads it: a ``userinfo@``
    prefix and the port are dropped, the hostname is lowercased, the trailing dot is stripped,
    and a bracketed literal is unwrapped only when it is a valid IP. ``api.anthropic.com:443@evil.com``
    is therefore ``evil.com`` — the host after the userinfo — never ``api.anthropic.com``, the
    authority a naive ``rsplit(":")`` port-strip would have mistaken it for.

    Returns ``""`` for anything a client could not route to a single host — an empty host, a
    leading-dot (empty) first label, a non-numeric port, or a bracketed non-IP literal — so it
    matches nothing in the allowlist rather than being coerced into a lookalike.
    """
    host = host.strip()
    if not host:
        return ""
    # A bare IPv6 literal (e.g. re-normalising a hostname :func:`provider_hosts` already
    # extracted) carries no brackets and would misparse as host:port; bracket it so urlsplit
    # reads it as one host. A single-colon host:port and a userinfo authority are left alone.
    if "[" not in host and "@" not in host and host.count(":") >= 2:
        host = f"[{host}]"
    try:
        parsed = urlsplit(f"//{host}")
        _ = parsed.port  # property access validates the port segment is numeric (else ValueError)
        hostname = parsed.hostname
    except ValueError:
        return ""
    if not hostname:
        return ""
    hostname = hostname.rstrip(".")
    if not hostname or hostname.startswith("."):
        return ""
    return hostname


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


#: The ports an allowlist entry with no ``:port`` permits: HTTPS and plain HTTP. An entry names a
#: host *and* where on it the sandbox may connect; a bare host meaning "any port" let a CONNECT
#: reach every service an allowlisted address runs (§10.5.0). Anything else is spelled
#: ``host:port`` and permits that port alone.
DEFAULT_EGRESS_PORTS: frozenset[int] = frozenset({80, 443})


def _endpoint_port(endpoint: str) -> int | None:
    """The explicit port of an allowlist entry, or ``None`` for a bare host.

    Parsed the way :func:`_norm_host` parses the host, so the two halves of an entry are read
    from one authority: ``[::1]:8443`` is port 8443 and a bare ``::1`` has none. A port that is
    not a number in range makes :func:`_norm_host` return ``""``, so such an entry matches
    nothing — and :class:`EgressAllowlist` refuses it before it can.
    """
    endpoint = endpoint.strip()
    if "[" not in endpoint and "@" not in endpoint and endpoint.count(":") >= 2:
        return None  # a bare IPv6 literal: every colon is the address's own
    try:
        return urlsplit(f"//{endpoint}").port
    except ValueError:
        return None


def _port_permitted(endpoint: str, port: int) -> bool:
    explicit = _endpoint_port(endpoint)
    return port in DEFAULT_EGRESS_PORTS if explicit is None else port == explicit


def _authority_problem(entry: str) -> str:
    """Why an allowlist entry names no single host and port, or ``""`` when it does."""
    if not _norm_host(entry):
        return f"{entry!r} names no host a client could route to"
    if "/" in entry or "@" in entry:
        return f"{entry!r} is not a bare host or host:port"
    if _endpoint_port(entry) == 0:
        return f"{entry!r} names port 0"
    return ""


def provider_authorities(base_urls: Iterable[str]) -> frozenset[str]:
    """The egress allowlist entries the configured provider ``base_url`` values imply (§9.4).

    A ``base_url`` that names its port (``http://10.0.0.5:8080``) permits that port and no
    other; one that does not (``https://api.anthropic.com``) is a bare host, permitted on
    :data:`DEFAULT_EGRESS_PORTS`. Use this, not :func:`provider_hosts`, wherever an
    :class:`EgressAllowlist` is built: the hosts alone would refuse a provider on its own port.
    """
    authorities: set[str] = set()
    for url in base_urls:
        parsed = urlsplit(url if "://" in url else f"//{url}", scheme="https")
        if not parsed.hostname:
            continue
        host = _norm_host(parsed.hostname)
        if not host:
            continue
        if ":" in host:
            host = f"[{host}]"
        authorities.add(host if parsed.port is None else f"{host}:{parsed.port}")
    return frozenset(authorities)


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

    A destination is permitted only if its host is a configured provider endpoint, a declared
    harness infrastructure endpoint, or an explicit allowlist entry — **and** its port is one that
    entry permits: the entry's own ``:port`` where it names one, else
    :data:`DEFAULT_EGRESS_PORTS`. Nothing else — the proxy blocks it and records
    ``egress_blocked``. Provider and infrastructure endpoints are always permitted, because
    blocking the model API or the harness's own telemetry would fail runs for infrastructure
    reasons, which §10.5.0 forbids.

    Construction refuses an entry that names no single host and port: such an entry would match
    nothing, a control the configuration accepted and then silently did not apply.
    """

    provider_endpoints: frozenset[str]
    infrastructure_endpoints: frozenset[str]
    extra: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        problems = [
            UserFacingProblem(f"egress.allowlist[{entry!r}]", problem, _ALLOWLIST_ENTRY_HINT)
            for entry in sorted(self._entries())
            if (problem := _authority_problem(entry))
        ]
        if problems:
            raise ConfigurationError("the egress allowlist", problems)

    def _entries(self) -> tuple[str, ...]:
        return (*self.provider_endpoints, *self.infrastructure_endpoints, *self.extra)

    def permits(self, host: str, port: int) -> bool:
        return any(
            _host_matches(host, endpoint) and _port_permitted(endpoint, port)
            for endpoint in self._entries()
        )

    def block_reason(self, host: str, port: int) -> str:
        if self.permits(host, port):
            return ""
        if any(_host_matches(host, endpoint) for endpoint in self._entries()):
            return (
                f"{_norm_host(host)} is in the egress allowlist, but not on port {port} "
                f"(an entry without a port permits {_DEFAULT_PORTS_TEXT}; name another port as "
                f"host:port) (default-deny, §10.5.0)"
            )
        return f"{_norm_host(host)} is not in the egress allowlist (default-deny, §10.5.0)"


_DEFAULT_PORTS_TEXT = " and ".join(str(port) for port in sorted(DEFAULT_EGRESS_PORTS))
_ALLOWLIST_ENTRY_HINT = (
    f"write a host (permitted on ports {_DEFAULT_PORTS_TEXT}) or host:port, "
    f"e.g. api.example.com or api.example.com:8443"
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
class EgressCanaryHit:
    """A canary marker found in a request body, recorded by reference (§10.4.3, §10.5.2).

    The body itself never reaches the trace — only its digest and byte count — so the scan runs in
    the proxy, where the body exists, and this is what survives: *which* canary, *where* in the body,
    and *how* it was encoded. Never the value. ``destination`` is the §10.4.1 destination the host
    grades severity from; a body to a non-model host is ``other_host``.
    """

    canary_id: str
    destination: str
    offset: int
    length: int
    via: str
    #: Where in the request the marker sat: ``body``, or ``header:<name>``. A header is as good
    #: an exfiltration channel as a body, and the two are told apart here rather than merged.
    channel: str = "body"


@dataclass(frozen=True)
class EgressFlow:
    """One captured request/response, classified and allowlist-checked (§10.5).

    The request body is never carried here — only its length and digest — because a body
    may hold a credential or a canary and this record ends up in an artifact. Canary
    *scanning* of bodies happens in the proxy before this record exists (§10.5.2, WP-16):
    ``canary_hits`` records any marker found, by reference, so the host can raise the Plane C
    finding without the body — the digest and the byte count are all else that survives.
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
    canary_hits: tuple[EgressCanaryHit, ...] = ()
    #: The authority the *client* asserted — the ``Host``/``:authority`` header — when it names
    #: a different host from the one the proxy actually connects to (``host``). Empty when the
    #: two agree, which is the ordinary case, so the record only carries the discrepancy.
    #: §10.5.0: the allowlist and credential injection are decided on ``host``, never on this.
    claimed_host: str = ""
    #: The per-run cap (``max_requests`` / ``max_request_bytes``) this request would have crossed,
    #: when that is why the proxy refused it (§10.5.1); empty otherwise. Recorded so the host can
    #: tell its own budget refusal from a provider's rate limit — the proxy answers both with a
    #: 429, and a run that hit a cap is ``budget_exceeded``, not an infrastructure failure.
    cap_exceeded: str = ""

    @property
    def counts_as_egress(self) -> bool:
        """Whether this flow counts toward ``no_egress`` (§10.5.0): only skill-attributed,
        and only if it was actually permitted — a blocked attempt is a separate record."""
        return self.egress_class == "skill_attributed" and not self.blocked


def _hits_from(text: str, canaries: Sequence[Canary], *, channel: str) -> list[EgressCanaryHit]:
    """The canary findings in one corpus string, as flow-level hits by reference.

    ``channel`` names *where in the request* the corpus came from — the body, or the header
    that carried it — and rides on the hit so a reader can tell a body leak from a header one
    without the value. ``via`` stays what it has always been: the encoding the marker was
    found under.
    """
    return [
        EgressCanaryHit(
            canary_id=finding.canary_id,
            destination=finding.destination,
            offset=finding.offset,
            length=finding.length,
            via=finding.via,
            channel=channel,
        )
        for finding in scan_for_canaries(text, canaries, destination="other_host")
    ]


def _scan_request_for_canaries(
    headers: Mapping[str, str], body: bytes, egress_class: EgressClass, canaries: Sequence[Canary]
) -> tuple[EgressCanaryHit, ...]:
    """Scan a request's headers *and* body for planted markers, by reference (§10.5.2, §10.4.1).

    The headers are scanned **before** :func:`redact_headers` replaces their values: redaction is
    what makes the record fit for an artifact, and scanning the redacted set would look at
    ``<redacted>``. A header is as good an exfiltration channel as a body — ``X-Export: <marker>``
    to an allowlisted host leaves no body hit at all — so both corpora feed the same scan and only
    the reference (id, offset, length, encoding) survives, never the value. Header *names* are
    scanned too: a marker can be spelled as a name with an empty value.

    Only *non-model* requests are scanned here: a marker on its way to an arbitrary host is
    exfiltration, a critical ``other_host`` leak needing no read state. A model-API request is
    skipped — that is the ``canary_in_context`` vs ``canary_without_read`` grading, which needs
    the per-request read state the host holds, and is the model-channel scanner's job. The scan is
    bounded inside ``scan_for_canaries``; the body is decoded leniently so binary payloads do not
    abort it.
    """
    if egress_class == "model_api" or not canaries:
        return ()
    hits: list[EgressCanaryHit] = []
    # One corpus per header, so an offset points inside the header that carried the marker
    # rather than into a synthetic join whose coordinates mean nothing to a reader.
    for name, value in sorted(headers.items()):
        hits.extend(_hits_from(f"{name}: {value}", canaries, channel=f"header:{name.lower()}"))
    if body:
        hits.extend(_hits_from(body.decode("utf-8", "replace"), canaries, channel="body"))
    return tuple(hits)


def identity_mismatch(host: str, *, claimed_host: str = "", sni: str = "") -> str:
    """The reason this request's asserted identity disagrees with where it is going, or ``""``.

    ``host`` is the destination the proxy will actually dial — the request-line authority, or
    the ``CONNECT`` authority for a tunnelled request. ``claimed_host`` is the authority the
    *client* asserted in its ``Host``/``:authority`` header, and ``sni`` the name it offered in
    the TLS handshake. Any of the three can differ, and only the first is where the bytes go.

    A disagreement is refused rather than resolved: authorising one identity while connecting to
    another is how a default-deny allowlist is talked out of its own decision, and how a brokered
    credential minted for a provider is handed to a host that merely claimed the provider's name
    (§10.5.0, §10.5.1). There is no legitimate reason for a client behind this proxy to address
    one host and name another, so the request is blocked and recorded — evidence, not an error.
    """
    destination = _norm_host(host)
    for label, asserted in (("Host header", claimed_host), ("TLS SNI", sni)):
        if not asserted:
            continue
        named = _norm_host(asserted)
        if named and named != destination:
            return (
                f"{label} names {named}, but the connection goes to "
                f"{destination or '(unroutable)'} — a request may not authorise one host and "
                "connect to another (§10.5.0)"
            )
    return ""


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
    claimed_host: str = "",
    canaries: Sequence[Canary] = (),
) -> EgressFlow:
    """Build a classified, allowlist-checked, redacted :class:`EgressFlow` from a request.

    This is the one place a raw request becomes a record fit for an artifact: it classifies
    (§10.5.0), applies the default-deny allowlist, redacts headers, scans the headers and body for
    planted canaries (§10.5.2), and reduces the body to a digest and a length so no credential or
    canary value survives. The proxy sidecar calls it per flow, passing the run's ``canaries`` so a
    marker in a header or body is recorded by reference before the values are dropped.

    ``host`` is the **actual destination**, never an asserted one. ``claimed_host`` and ``sni``
    are what the client said it was talking to; where either disagrees with ``host`` the flow is
    blocked by :func:`identity_mismatch` before the allowlist is consulted, and the discrepancy is
    recorded on the flow so the attempt is legible.
    """
    egress_class = classify_egress(
        host,
        provider_endpoints=provider_endpoints,
        infrastructure_endpoints=infrastructure_endpoints,
    )
    mismatch = identity_mismatch(host, claimed_host=claimed_host, sni=sni)
    permitted = not mismatch and allowlist.permits(host, port)
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
        block_reason=mismatch or allowlist.block_reason(host, port),
        canary_hits=_scan_request_for_canaries(
            request_headers or {}, request_body, egress_class, canaries
        ),
        claimed_host=(_norm_host(claimed_host) if mismatch and _norm_host(claimed_host) else ""),
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

    def start(
        self,
        run_id: str,
        *,
        allowlist: EgressAllowlist,
        caps: CapLedger,
        canaries: Sequence[Canary] = (),
    ) -> None:
        raise NotImplementedError

    def flows(self) -> list[EgressFlow]:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError


def budget_refusal(flows: Iterable[EgressFlow]) -> str:
    """The first per-run cap the proxy refused a request on, or ``""`` if none (§10.5.1)."""
    return next((flow.cap_exceeded for flow in flows if flow.cap_exceeded), "")
