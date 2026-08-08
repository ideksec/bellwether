"""The recording-proxy addon — mitmproxy-shaped glue over the decision core (§10.5).

The sidecar (WP-13 pt 2b-ii) runs ``mitmdump`` with a tiny entry script that imports mitmproxy
and, for every request, hands ``flow.request`` to a :class:`ProxyAddon` and applies the result.
Everything security-relevant already lives in :func:`~bellwether.capture.proxy_core.decide_request`
— allowlist, caps, injection, redaction, in a fixed order. This module adds only the edges that
touch mitmproxy: reading the fields off a request, mutating its headers for credential injection,
turning a block into a synthetic response, and the flow-record file the sidecar writes and the
host reads back.

Those edges are kept here, structural and mitmproxy-free, for the same reason the decision is:
so they are unit-tested with a plain fake request and mypy-checked without mitmproxy installed,
and the entry script in the image stays too thin to hide a bug. :class:`RequestLike` is the exact
subset of ``mitmproxy.http.Request`` the addon reads and writes; the real object satisfies it
structurally.

The flow-record contract (:func:`flow_record_line` / :func:`read_flow_records`) is how the
sidecar and host communicate across the shared volume of §10.5: the sidecar appends one canonical
JSON line per flow, the host reads them into :class:`~bellwether.capture.egress.EgressFlow` objects
and feeds them to ``trace.egress_actions``. Canonical lines make the file byte-stable and diffable.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from bellwether.capture.canary import Canary
from bellwether.capture.credential import CredentialBroker
from bellwether.capture.egress import (
    CapLedger,
    EgressAllowlist,
    EgressCanaryHit,
    EgressClass,
    EgressFlow,
)
from bellwether.capture.proxy_core import decide_request
from bellwether.determinism import canonical_json

__all__ = [
    "BlockResponse",
    "ProxyAddon",
    "RequestLike",
    "flow_record_line",
    "parse_flow_record",
    "read_flow_records",
    "write_flow_records",
]

#: HTTP status the sidecar returns for an allowlist denial. The container sees a real 403,
#: which is the honest signal — the host it asked for is not permitted — rather than a hang.
BLOCK_STATUS_DENIED = 403
#: And for a per-run cap. 429 (Too Many Requests) is distinguishable from a plain denial,
#: because an exhausted budget and a forbidden host are different conditions and a skill
#: reacting to them should be able to tell them apart.
BLOCK_STATUS_BUDGET = 429


class RequestLike(Protocol):
    """The subset of a mitmproxy request the addon reads and mutates.

    ``mitmproxy.http.Request`` satisfies this structurally, so the addon is tested with a plain
    fake and needs no mitmproxy import. ``headers`` is mutated in place for credential injection;
    the case-insensitive multidict mitmproxy provides behaves as a ``MutableMapping[str, str]``
    for the single-valued auth headers the injection touches. ``pretty_host`` is mitmproxy's
    resolved host (from the Host header or SNI), which is what must be classified and allowlisted.
    """

    method: str
    scheme: str
    pretty_host: str
    port: int
    path: str
    headers: MutableMapping[str, str]
    content: bytes | None


@dataclass(frozen=True)
class BlockResponse:
    """Instruction to short-circuit a request with a synthetic response instead of forwarding.

    The entry script turns this into ``flow.response`` so the request never leaves the proxy.
    ``cap_exceeded`` names the per-run cap when the block was a budget refusal, which the run
    surfaces as ``budget_exceeded`` (§10.5.1); it is ``None`` for an allowlist denial.
    """

    status: int
    reason: str
    cap_exceeded: str | None = None


@dataclass
class ProxyAddon:
    """The per-request brain the sidecar runs, holding the run's mutable egress state (§10.5).

    Thin glue over :func:`decide_request`: translate the request, decide, apply. It owns the
    ``CapLedger`` (mutated as forwarded requests are counted), accumulates the flow records the
    host will read, and either mutates the outgoing request's headers for credential injection or
    returns a :class:`BlockResponse` the entry script renders as a synthetic response. It adds no
    security logic of its own — the order and the decisions are all in ``decide_request``.

    ``clock`` supplies the capture timestamp per request (real wall-clock in the sidecar, a fixed
    value in tests); the egress plane's timestamps are anchored to epochs later (§11.5), so a real
    clock here is correct, not a determinism hole.
    """

    allowlist: EgressAllowlist
    provider_endpoints: frozenset[str]
    infrastructure_endpoints: frozenset[str]
    broker: CredentialBroker
    provider_of_host: Mapping[str, str]
    caps: CapLedger
    clock: Callable[[], str]
    #: The run's planted canaries. ``decide_request`` scans each request body for their markers and
    #: records any hit on the flow by reference (§10.5.2); empty when planting is off.
    canaries: tuple[Canary, ...] = ()
    _flows: list[EgressFlow] = field(default_factory=list, repr=False)

    def on_request(self, request: RequestLike) -> BlockResponse | None:
        """Decide one request, record its flow, and either inject or block.

        Returns ``None`` when the request is forwarded — its headers have been mutated in place
        with the upstream set (the real key swapped in for a permitted model-API call) — or a
        :class:`BlockResponse` when it must be short-circuited. Either way the flow is recorded
        first, so a block is never a silent drop.
        """
        decision = decide_request(
            ts=self.clock(),
            method=request.method,
            scheme=request.scheme,
            host=request.pretty_host,
            port=request.port,
            path=request.path,
            headers=dict(request.headers),
            body=request.content or b"",
            allowlist=self.allowlist,
            provider_endpoints=self.provider_endpoints,
            infrastructure_endpoints=self.infrastructure_endpoints,
            broker=self.broker,
            provider_of_host=self.provider_of_host,
            caps=self.caps,
            canaries=self.canaries,
        )
        self._flows.append(decision.flow)

        if decision.action == "block":
            if decision.cap_exceeded is not None:
                return BlockResponse(
                    status=BLOCK_STATUS_BUDGET,
                    reason=f"egress budget exceeded: {decision.cap_exceeded}",
                    cap_exceeded=decision.cap_exceeded,
                )
            return BlockResponse(
                status=BLOCK_STATUS_DENIED,
                reason=decision.flow.block_reason or "egress blocked by default-deny allowlist",
            )

        # Forward: write the upstream headers onto the real request. For an injected model-API
        # call this replaces the scoped token with the real key; otherwise it is the request's
        # own headers, so the assignment is a no-op. The real key reaches the wire here and is
        # never in the recorded flow, which carries the redacted header set.
        for name, value in decision.upstream_headers.items():
            request.headers[name] = value
        return None

    def flows(self) -> list[EgressFlow]:
        """The flows recorded so far, in request order — what the host reads for the trace."""
        return list(self._flows)


# ---------------------------------------------------------------------------
# The sidecar ↔ host flow-record contract (§10.5)
# ---------------------------------------------------------------------------


def _flow_to_dict(flow: EgressFlow) -> dict[str, Any]:
    """An EgressFlow as a plain JSON-able dict. Explicit rather than ``asdict`` so a new field
    on the dataclass fails the round-trip test loudly instead of silently dropping from the wire.
    """
    return {
        "ts": flow.ts,
        "method": flow.method,
        "scheme": flow.scheme,
        "host": flow.host,
        "port": flow.port,
        "path": flow.path,
        "egress_class": flow.egress_class,
        "blocked": flow.blocked,
        "request_headers": dict(flow.request_headers),
        "request_body_bytes": flow.request_body_bytes,
        "request_body_sha256": flow.request_body_sha256,
        "response_status": flow.response_status,
        "response_size": flow.response_size,
        "sni": flow.sni,
        "block_reason": flow.block_reason,
        "canary_hits": [
            {
                "canary_id": hit.canary_id,
                "destination": hit.destination,
                "offset": hit.offset,
                "length": hit.length,
                "via": hit.via,
            }
            for hit in flow.canary_hits
        ],
    }


def _flow_from_dict(payload: Mapping[str, Any]) -> EgressFlow:
    egress_class: EgressClass = payload["egress_class"]
    return EgressFlow(
        ts=payload["ts"],
        method=payload["method"],
        scheme=payload["scheme"],
        host=payload["host"],
        port=payload["port"],
        path=payload["path"],
        egress_class=egress_class,
        blocked=payload["blocked"],
        request_headers=dict(payload["request_headers"]),
        request_body_bytes=payload["request_body_bytes"],
        request_body_sha256=payload["request_body_sha256"],
        response_status=payload["response_status"],
        response_size=payload["response_size"],
        sni=payload["sni"],
        canary_hits=tuple(
            EgressCanaryHit(
                canary_id=hit["canary_id"],
                destination=hit["destination"],
                offset=hit["offset"],
                length=hit["length"],
                via=hit["via"],
            )
            for hit in payload.get("canary_hits", ())
        ),
        block_reason=payload["block_reason"],
    )


def flow_record_line(flow: EgressFlow) -> str:
    """One canonical JSONL line for a flow — sorted keys, no trailing newline.

    The redaction that makes a flow fit for an artifact already happened in ``make_flow``; this
    only serialises. Canonical form keeps the shared file byte-stable, so two identical runs
    produce identical flow logs.
    """
    return canonical_json(_flow_to_dict(flow))


def parse_flow_record(line: str) -> EgressFlow:
    """Reconstruct an :class:`EgressFlow` from one JSONL line written by the sidecar."""
    import json

    return _flow_from_dict(json.loads(line))


def write_flow_records(path: Path, flows: list[EgressFlow]) -> None:
    """Write flows as JSONL to ``path`` — the sidecar's side of the shared-volume contract."""
    path.write_text("".join(f"{flow_record_line(flow)}\n" for flow in flows), encoding="utf-8")


def read_flow_records(path: Path) -> list[EgressFlow]:
    """Read the sidecar's flow log into :class:`EgressFlow` objects — the host's side.

    A missing file is an *error state*, not an empty run: the sidecar always writes the log, so
    its absence means the proxy never ran, and a zero-egress trace that reads as a clean skill is
    exactly the failure this plane exists to prevent. The caller (the ``RecordingProxy`` sidecar
    wrapper) turns a missing log into a loud failure; here, absence raises rather than returning
    ``[]``. Blank lines are skipped so a trailing newline is harmless.
    """
    text = path.read_text(encoding="utf-8")
    return [parse_flow_record(line) for line in text.splitlines() if line.strip()]
