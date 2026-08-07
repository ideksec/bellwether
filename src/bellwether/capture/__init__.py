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
allowlist→caps→inject→record order the addon runs). WP-16 built Plane C (``canary`` — mint,
decode-then-match, destination classification, capture-time redaction) and WP-14 the CA
trust chain (``ca`` — the §9.2 mechanism table, install env/commands, and the
interception-confirmation predicate). The mitmproxy sidecar (WP-13 pt 2b-ii), DNS (WP-15) and
process (WP-18) planes are what remain — the container halves, validated on CI.
``mypy --strict`` from the first commit.
"""

from __future__ import annotations

from bellwether.capture.ca import (
    CA_MECHANISMS,
    DEFAULT_CA_CONTAINER_PATH,
    CaMechanism,
    ca_trust_environment,
    interception_confirmed,
    system_store_install_commands,
)
from bellwether.capture.canary import (
    DEFAULT_CANARY_POOL,
    Canary,
    CanaryFinding,
    CanaryPlacement,
    canary_markers,
    classify_canary_hit,
    decoded_forms,
    mint_canaries,
    redact_canaries,
    scan_for_canaries,
    strip_dns_labels,
)
from bellwether.capture.credential import (
    SANDBOX_TOKEN_PREFIX,
    CredentialBroker,
    mint_sandbox_token,
    proxy_environment,
    strip_and_inject,
)
from bellwether.capture.dns import (
    DNS_DESTINATION,
    DnsAllowlist,
    DnsQuery,
    decide_query,
    scan_query_for_canaries,
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
from bellwether.capture.proxy_addon import (
    BlockResponse,
    ProxyAddon,
    RequestLike,
    flow_record_line,
    parse_flow_record,
    read_flow_records,
    write_flow_records,
)
from bellwether.capture.proxy_core import ProxyDecision, decide_request
from bellwether.capture.sidecar import MitmproxySidecar, SidecarHandle
from bellwether.capture.sidecar_entry import (
    SidecarConfig,
    block_response_args,
    build_addon,
)
from bellwether.capture.sink import HostEventSink, SinkEvent, SinkStats

__all__ = [
    "CA_MECHANISMS",
    "DEFAULT_CANARY_POOL",
    "DEFAULT_CA_CONTAINER_PATH",
    "DEFAULT_HEADER_ALLOWLIST",
    "DNS_DESTINATION",
    "SANDBOX_TOKEN_PREFIX",
    "BlockResponse",
    "CaMechanism",
    "Canary",
    "CanaryFinding",
    "CanaryPlacement",
    "CapLedger",
    "CredentialBroker",
    "DnsAllowlist",
    "DnsQuery",
    "EgressAllowlist",
    "EgressClass",
    "EgressFlow",
    "FilesystemEvent",
    "HostEventSink",
    "MitmproxySidecar",
    "PlaneStatus",
    "ProxyAddon",
    "ProxyDecision",
    "RecordingProxy",
    "RequestLike",
    "SidecarConfig",
    "SidecarHandle",
    "SinkEvent",
    "SinkStats",
    "block_response_args",
    "build_addon",
    "ca_trust_environment",
    "canary_markers",
    "classify_canary_hit",
    "classify_egress",
    "collect_filesystem_events",
    "correlate_egress_induced_failure",
    "decide_query",
    "decide_request",
    "decoded_forms",
    "filesystem_writes_status",
    "flow_record_line",
    "interception_confirmed",
    "make_flow",
    "mint_canaries",
    "mint_sandbox_token",
    "parse_flow_record",
    "provider_hosts",
    "proxy_environment",
    "read_flow_records",
    "redact_canaries",
    "redact_headers",
    "scan_for_canaries",
    "scan_query_for_canaries",
    "strip_and_inject",
    "strip_dns_labels",
    "system_store_install_commands",
    "write_flow_records",
]
