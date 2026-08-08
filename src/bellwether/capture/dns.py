"""Plane E — the controlled DNS resolver's decision core (§10.6).

An HTTP proxy does not see UDP/53, so without a controlled resolver DNS is a covert channel that
routes entirely around Plane D: a skill encodes a secret into query *labels* and exfiltrates it while
the recording proxy records nothing at all. The resolver answers allowlisted names only and returns
NXDOMAIN for everything else, logs every query, and — because a query name joins the canary corpus
(§10.4.2) — turns a canary smuggled into query labels into a ``critical`` leak on the same footing as
any other non-model destination.

This module is the host-side core: the allowlist decision, the query record, and the canary scan over
a query name. It is deliberately pure and offline-tested, the same as the recording proxy's
``decide_request``. The resolver *sidecar* — ``dnslib``/``coredns`` in a container, the UDP lockdown
of §3.3 invariant 3 that makes it unavoidable rather than merely available, and the ``dns_query`` /
``dns_blocked`` trace actions — is the container half, validated on CI.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bellwether.capture.canary import (
    Canary,
    CanaryDestination,
    CanaryFinding,
    scan_for_canaries,
)
from bellwether.determinism import canonical_json

__all__ = [
    "DNS_DESTINATION",
    "ControlledResolver",
    "DnsAllowlist",
    "DnsQuery",
    "decide_query",
    "parse_query_record",
    "query_record_line",
    "read_query_records",
    "scan_query_for_canaries",
    "write_query_records",
]

#: A DNS query is a non-model destination, so a canary in one is ``critical`` (§10.4.1).
DNS_DESTINATION: CanaryDestination = "dns"


def _norm_qname(name: str) -> str:
    """A query name to compare on: lowercased, with the root's trailing dot removed."""
    return name.strip().lower().rstrip(".")


def _has_empty_label(name: str) -> bool:
    """True where a normalised name holds an empty label (a leading dot or ``a..b``).

    A valid hostname has no empty labels. ``.api.anthropic.com`` is *not* a subdomain of
    ``api.anthropic.com`` — but a naive ``endswith("." + allowed)`` reads the empty label
    before the leading dot as the subdomain and lets it in. This is the DNS-plane mirror of
    the egress ``_norm_host`` leading-dot fix (BW-40); rejecting the empty label here keeps
    the two planes' allowlist parsers from disagreeing on the same input.
    """
    return name == "" or any(label == "" for label in name.split("."))


def _qname_matches(name: str, allowed: str) -> bool:
    """True if ``name`` is ``allowed`` or a subdomain of it, on a label boundary.

    ``api.anthropic.com`` matches ``api.anthropic.com`` and ``eu.api.anthropic.com`` but never
    ``notanthropic.com`` or ``.api.anthropic.com`` — the same label-boundary rule the egress
    allowlist uses, so a lookalike or empty-label name cannot smuggle itself in.
    """
    name = _norm_qname(name)
    allowed = _norm_qname(allowed)
    if not name or not allowed or _has_empty_label(name) or _has_empty_label(allowed):
        return False
    return name == allowed or name.endswith("." + allowed)


@dataclass(frozen=True)
class DnsAllowlist:
    """The controlled resolver's allowlist (§10.6). Default-deny: a name not on it gets NXDOMAIN."""

    allowed: frozenset[str]

    def permits(self, name: str) -> bool:
        return any(_qname_matches(name, entry) for entry in self.allowed)

    def nxdomain_reason(self, name: str) -> str:
        return (
            ""
            if self.permits(name)
            else f"{_norm_qname(name)} is not in the DNS allowlist (default-deny, §10.6); NXDOMAIN"
        )


@dataclass(frozen=True)
class DnsQuery:
    """One recorded query and what the resolver did with it.

    ``resolved`` is whether the name was allowlisted (and so would be answered); its negation is a
    blocked query, recorded as ``dns_blocked`` — evidence, not an error, exactly like a blocked HTTP
    request. Canary scanning is orthogonal: an allowlisted name can still carry a canary, and a
    blocked name that carries one is both NXDOMAIN and a critical leak.
    """

    ts: str
    name: str
    resolved: bool
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return not self.resolved


def decide_query(name: str, *, allowlist: DnsAllowlist, ts: str) -> DnsQuery:
    """Decide one DNS query against the allowlist and record it (§10.6).

    Every query is logged whether or not it resolves — the log is the plane's ground truth, and a
    query that was refused is exactly the evidence the resolver exists to capture.
    """
    normalised = _norm_qname(name)
    permitted = allowlist.permits(normalised)
    return DnsQuery(
        ts=ts,
        name=normalised,
        resolved=permitted,
        reason="" if permitted else allowlist.nxdomain_reason(normalised),
    )


def scan_query_for_canaries(name: str, canaries: Iterable[Canary]) -> list[CanaryFinding]:
    """Scan a query name for canary markers, label-separator-aware (§10.4.2).

    A dotted split (``sec.ret.value`` for ``secretvalue``) is seen as contiguous, so a canary
    chunked across labels is still found. A hit is a ``critical`` leak — DNS is a non-model
    destination, and this is the covert channel the resolver exists to close.
    """
    return scan_for_canaries(name, canaries, destination=DNS_DESTINATION, is_dns=True)


# ---------------------------------------------------------------------------
# The resolver ↔ host query-record contract (§10.6)
#
# The mirror of the proxy's flow-record contract (:mod:`bellwether.capture.proxy_addon`):
# the resolver sidecar appends one canonical JSONL line per query to a log on the shared
# volume, and the host reads it back into :class:`DnsQuery` objects to build Plane E of the
# trace. Canonical form keeps the shared file byte-stable, so two identical runs produce
# identical query logs.
# ---------------------------------------------------------------------------


def _query_to_dict(query: DnsQuery) -> dict[str, Any]:
    """A :class:`DnsQuery` as a plain JSON-able dict. Explicit rather than ``asdict`` so a new
    field on the dataclass fails the round-trip test loudly instead of silently dropping."""
    return {
        "ts": query.ts,
        "name": query.name,
        "resolved": query.resolved,
        "reason": query.reason,
    }


def _query_from_dict(payload: Mapping[str, Any]) -> DnsQuery:
    return DnsQuery(
        ts=payload["ts"],
        name=payload["name"],
        resolved=payload["resolved"],
        reason=payload.get("reason", ""),
    )


def query_record_line(query: DnsQuery) -> str:
    """One canonical JSONL line for a query — sorted keys, no trailing newline."""
    return canonical_json(_query_to_dict(query))


def parse_query_record(line: str) -> DnsQuery:
    """Reconstruct a :class:`DnsQuery` from one JSONL line written by the resolver."""
    return _query_from_dict(json.loads(line))


def write_query_records(path: Path, queries: list[DnsQuery]) -> None:
    """Write queries as JSONL — the resolver's side of the shared-volume contract."""
    path.write_text("".join(f"{query_record_line(query)}\n" for query in queries), encoding="utf-8")


def read_query_records(path: Path) -> list[DnsQuery]:
    """Read the resolver's query log into :class:`DnsQuery` objects — the host's side.

    A missing file is an *error state*, not an empty run: the resolver always writes the log
    (an empty one at t=0), so its absence means the resolver never ran, and a zero-query trace
    that reads as a clean skill is exactly the failure this plane exists to prevent. Absence
    raises rather than returning ``[]``; blank lines are skipped so a trailing newline is
    harmless. Mirrors :func:`bellwether.capture.proxy_addon.read_flow_records`.
    """
    text = path.read_text(encoding="utf-8")
    return [parse_query_record(line) for line in text.splitlines() if line.strip()]


class ControlledResolver:
    """The controlled-resolver seam (§10.6, §22) — the DNS analog of :class:`RecordingProxy`.

    A ``Protocol`` in spirit: the resolver sidecar implements it (the container half), and the
    analysis path depends only on this surface — start a run, read its queries, stop — so the
    resolver can be swapped without touching capture code, the same treatment the sandbox
    backend and the recording proxy get. Kept a base class with a ``NotImplementedError`` body
    rather than a bare ``Protocol`` so a partial implementation fails loudly instead of silently
    resolving nothing (a zero-query trace reads as a clean skill — the covert channel §10.6
    exists to police would go unrecorded).
    """

    def start(self, run_id: str, *, allowlist: DnsAllowlist) -> None:
        raise NotImplementedError

    def queries(self) -> list[DnsQuery]:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError
