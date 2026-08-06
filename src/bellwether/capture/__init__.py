"""The capture planes: host-side collection of ground truth (§10).

Responsibility
    Plane A (harness events via a host-owned sink), Plane B (filesystem, overlay diff,
    partitioned into the three zones of §10.2), Plane C (canaries), Plane D (network
    egress via the recording proxy), Plane D′ (process execution), Plane E (DNS).
    Produce raw plane events and the coverage block of §10.7.

MUST NOT
    Interpret semantics. A plane records that a path was read; deciding whether that
    read exceeded declared scope belongs to :mod:`bellwether.assertions`.

MUST NOT, more importantly
    Run inside the sandbox. §10.0: no component that produces evidence may execute
    inside the container it observes. Revision 1 violated this and the violation
    invalidated the ground-truth claim.

WP-5 built Plane A's host-owned sink and Plane B's zone-partitioned overlay capture.
WP-13 built Plane D's host-side logic: increment 1 the egress semantics (``egress`` —
classification, the default-deny allowlist, per-run caps, redaction), 2a the credential
isolation core (``credential`` — the sandbox-scoped token, proxy-side injection, leak guard),
and 2b-i the per-request decision (``proxy_core.decide_request`` — the fixed
allowlist→caps→inject→record order the addon runs). Its mitmproxy sidecar (2b-ii) and
WP-15/16/18 bring the rest of the proxy, DNS, canaries and process planes.
``mypy --strict`` from the first commit.
"""

from __future__ import annotations

from bellwether.capture.credential import (
    SANDBOX_TOKEN_PREFIX,
    CredentialBroker,
    mint_sandbox_token,
    proxy_environment,
    strip_and_inject,
)
from bellwether.capture.egress import (
    DEFAULT_HEADER_ALLOWLIST,
    CapLedger,
    EgressAllowlist,
    EgressClass,
    EgressFlow,
    RecordingProxy,
    classify_egress,
    correlate_egress_induced_failure,
    make_flow,
    provider_hosts,
    redact_headers,
)
from bellwether.capture.filesystem import (
    FilesystemEvent,
    PlaneStatus,
    collect_filesystem_events,
    filesystem_writes_status,
)
from bellwether.capture.proxy_core import ProxyDecision, decide_request
from bellwether.capture.sink import HostEventSink, SinkEvent, SinkStats

__all__ = [
    "DEFAULT_HEADER_ALLOWLIST",
    "SANDBOX_TOKEN_PREFIX",
    "CapLedger",
    "CredentialBroker",
    "EgressAllowlist",
    "EgressClass",
    "EgressFlow",
    "FilesystemEvent",
    "HostEventSink",
    "PlaneStatus",
    "ProxyDecision",
    "RecordingProxy",
    "SinkEvent",
    "SinkStats",
    "classify_egress",
    "collect_filesystem_events",
    "correlate_egress_induced_failure",
    "decide_request",
    "filesystem_writes_status",
    "make_flow",
    "mint_sandbox_token",
    "provider_hosts",
    "proxy_environment",
    "redact_headers",
    "strip_and_inject",
]
