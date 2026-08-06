"""The recording proxy's per-request decision — the security brain, kept pure (§10.5).

The mitmproxy sidecar (the container half, WP-13 pt 2b-ii) is thin glue: for every request
it hands the request's fields to :func:`decide_request` and applies the result. Keeping the
decision here — pure, dependency-free, unit-tested — means the security logic that matters
(what is blocked, what is injected, what is recorded, when a cap trips) is verifiable without
standing up mitmproxy or a container, and the addon that runs it in the sidecar cannot quietly
diverge from what the tests check.

The order of operations is itself a security property, so it is fixed here rather than left
to the addon:

1. **Classify and allowlist-check** (§10.5.0). A request to a denied host is blocked and
   recorded as ``egress_blocked`` — a blocked attempt is evidence, not an error, and is kept
   in full for security metrics.
2. **Cap-check** the permitted request (§10.5.1). If forwarding it would cross a per-run
   request or byte cap on the sandbox-scoped token, it is refused and the run records
   ``budget_exceeded`` — the bound on residual-channel exfiltration.
3. **Inject the real credential** (§10.5.1) only for a permitted ``model_api`` request whose
   provider the broker holds a key for. The container's scoped token becomes the real key on
   the wire and nowhere else.
4. **Record the flow** either way, with the body reduced to a digest and the auth header
   redacted (§10.5) — so the record proves what happened without ever holding a credential.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from bellwether.capture.credential import CredentialBroker
from bellwether.capture.egress import CapLedger, EgressAllowlist, EgressFlow, make_flow

__all__ = ["ProxyDecision", "decide_request"]


@dataclass(frozen=True)
class ProxyDecision:
    """What the sidecar does with one request, and the record it writes.

    ``forward`` sends ``upstream_headers`` on to the destination; ``block`` drops the request
    and the sandbox never reaches it. ``flow`` is written to the shared flow log either way —
    a block is recorded, not silently dropped. ``cap_exceeded`` names the per-run cap that
    forced a block, which the run surfaces as ``budget_exceeded`` (§10.5.1).
    """

    action: Literal["forward", "block"]
    flow: EgressFlow
    upstream_headers: Mapping[str, str] = field(default_factory=dict)
    cap_exceeded: str | None = None
    injected: bool = False


def decide_request(
    *,
    ts: str,
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    headers: Mapping[str, str],
    body: bytes,
    allowlist: EgressAllowlist,
    provider_endpoints: frozenset[str],
    infrastructure_endpoints: frozenset[str],
    broker: CredentialBroker,
    provider_of_host: Mapping[str, str],
    caps: CapLedger,
) -> ProxyDecision:
    """Decide one request (§10.5). See the module docstring for the fixed order.

    ``provider_of_host`` maps a model-API host to the provider name the broker keys on, so a
    permitted ``model_api`` request gets its scoped token swapped for that provider's real
    key. ``caps`` is mutated (a forwarded request is counted); a blocked one is not.
    """
    # (1) Classify, allowlist-check, redact, reduce the body — make_flow does all four and
    # produces the record that is written regardless of the outcome.
    flow = make_flow(
        ts=ts,
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        provider_endpoints=provider_endpoints,
        infrastructure_endpoints=infrastructure_endpoints,
        allowlist=allowlist,
        request_headers=headers,
        request_body=body,
    )
    if flow.blocked:
        return ProxyDecision(action="block", flow=flow)

    # (2) Cap-check the permitted request. A request that would cross a cap is refused before
    # it leaves — the residual-channel bound only holds if it is enforced *before* forwarding.
    cap = caps.would_exceed(len(body))
    if cap is not None:
        return ProxyDecision(action="block", flow=flow, cap_exceeded=cap)
    caps.record(len(body))

    # (3) Inject the real credential for a permitted model-API request whose provider we hold
    # a key for. Non-model traffic (permitted infrastructure) forwards its own headers.
    upstream = dict(headers)
    injected = False
    provider = provider_of_host.get(flow.host)
    if (
        flow.egress_class == "model_api"
        and provider is not None
        and provider in broker.ready_providers()
    ):
        upstream = broker.inject(provider, headers)
        injected = True

    return ProxyDecision(action="forward", flow=flow, upstream_headers=upstream, injected=injected)
