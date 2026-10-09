"""`unexpected_provider_endpoint` — produced at the proxy, carried to the trace, scored (§10.5.2).

The model API is the one authenticated channel out of the sandbox and the proxy puts the real key
on requests to it. Until this control existed, "requests to it" meant "requests to its host": any
method, any path, any model got the key swapped in, and the finding §10.5.2 defines for exactly
that — a ``high`` ``unexpected_provider_endpoint`` — had no producer anywhere in the pipeline.
spec-notes named it as the next inert disposition worth closing.

These tests sit at every wiring hop, because the project's defect pattern is a correct helper that
no caller asks the question of: the pure rule; ``decide_request`` refusing before injection and
before the cap; the addon's 403; the sidecar-to-host wire; the trace finding anchored to the
refusal; the evidence index reading it (and *not* reading it as an allowlist denial); the gate's
decision table; the composed verdict; the §16.4 preflight clause; and the config-to-sidecar
wiring that gives every provider host a shape. The expected shape itself is observed, not
assumed: the pinned CLI, run headless against a scripted API, sends exactly
``POST /v1/messages?beta=true`` with the configured model — that request is the pass case here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from bellwether.assertions import EvidenceIndex, evaluate
from bellwether.capture import (
    CapLedger,
    EgressAllowlist,
    ProviderRequestShape,
    ProxyAddon,
    SidecarConfig,
    decide_request,
    expected_request_paths,
    request_shape,
    shape_violation,
)
from bellwether.capture.proxy_addon import (
    BLOCK_STATUS_DENIED,
    flow_record_line,
    parse_flow_record,
)
from bellwether.cli.orchestrator import SetReading, TargetInfo, _provider_endpoint_result
from bellwether.cli.run import build_proxy_provider
from bellwether.config import template_path
from bellwether.config.models.config import Config, EgressConfig, SandboxConfig
from bellwether.config.models.policy import ProfileSpec
from bellwether.config.models.provider import ProviderConfig
from bellwether.config.models.scenarios import AssertionSpec
from bellwether.config.policy_loader import parse_policy
from bellwether.trace import Trace, egress_actions, provider_endpoint_actions
from bellwether.trace.canonical import NormalizationContext, canonicalize
from bellwether.trace.models import Coverage, PlaneCoverage
from bellwether.verdict.precondition import TargetDeclaration, check_preconditions
from tests.factories import make_footer, make_header
from tests.test_proxy_addon import _REAL_KEY, _broker, _FakeRequest

_PROVIDERS = frozenset({"api.anthropic.com"})
_INFRA = frozenset({"telemetry.example-harness.com"})
_PROVIDER_OF_HOST = {"api.anthropic.com": "anthropic"}
_TS = "2026-08-06T00:00:00+00:00"
_SHAPE = request_shape("anthropic", "https://api.anthropic.com", ["claude-haiku-4-5-20251001"])
_SHAPES = {"api.anthropic.com": _SHAPE}
#: The request the pinned CLI was observed to send, byte-shape for byte-shape (two headless
#: sessions, both permission postures): the path carries ``?beta=true``, the body names the
#: configured model.
_OBSERVED_PATH = "/v1/messages?beta=true"
_MODEL_BODY = b'{"model": "claude-haiku-4-5-20251001", "max_tokens": 1024, "messages": []}'


# ---------------------------------------------------------------------------
# The rule, pure
# ---------------------------------------------------------------------------


def _violation(method: str = "POST", path: str = _OBSERVED_PATH, body: bytes = _MODEL_BODY) -> str:
    return shape_violation(method=method, path=path, body=body, shape=_SHAPE)


def test_the_request_the_cli_was_observed_to_send_is_a_model_call() -> None:
    assert _violation() == ""


def test_count_tokens_is_the_same_api_family_and_is_expected() -> None:
    assert _violation(path="/v1/messages/count_tokens?beta=true") == ""


def test_an_upload_to_the_provider_is_not_a_model_call() -> None:
    """The headline hole: ``/v1/files`` on the provider's own domain, with the real key swapped
    in, is an exfiltration destination the canary body scan skips because it is the model host."""
    reason = _violation(path="/v1/files?beta=true")
    assert "not an expected provider endpoint" in reason
    assert "/v1/messages" in reason


@pytest.mark.parametrize("path", ["/v1/messages/batches", "/v1/complete", "/v1/organizations/me"])
def test_other_provider_endpoints_are_refused(path: str) -> None:
    assert _violation(path=path)


def test_a_get_to_the_provider_is_not_a_model_call_whatever_its_path() -> None:
    assert "GET" in _violation(method="GET", path="/v1/messages", body=b"")


def test_a_model_outside_the_configured_set_is_refused() -> None:
    reason = _violation(body=b'{"model": "claude-opus-4-1-20250805", "messages": []}')
    assert "not in the configured set" in reason
    assert "claude-opus-4-1-20250805" in reason


@pytest.mark.parametrize(
    "body", [b"", b"not json", b"[1, 2]", b'{"messages": []}', b'{"model": 7}']
)
def test_a_body_that_names_no_model_is_refused(body: bytes) -> None:
    assert "does not name a model" in _violation(body=body)


@pytest.mark.parametrize(
    "path",
    [
        "/v1/messages/../files",
        "/v1/./messages",
        "//v1/messages",
        "/v1//messages",
        "/v1/%6Dessages",
        "/v1/messages/",
        "/v1/messages/.",
        "v1/messages",
        "",
    ],
)
def test_a_path_spelling_the_proxy_cannot_reduce_is_refused_not_resolved(path: str) -> None:
    """Normalise rather than enumerate — and where a spelling cannot be reduced to something
    this side knows the meaning of (a dot segment the provider's server may or may not
    resolve, an escape it may or may not decode), refuse it. The grammar is the allowlist;
    every spelling outside it is refused without being named."""
    assert _violation(path=path)


def test_the_query_string_is_not_part_of_the_path() -> None:
    assert _violation(path="/v1/messages?beta=true&x=1") == ""
    assert _violation(path="/v1/messages#frag") == ""


def test_a_gateway_prefix_is_kept_exactly_as_the_clients_join_it() -> None:
    """A provider behind a path prefix expects the prefix: the host-side clients append the
    suffix to ``base_url`` verbatim, and so does this."""
    assert expected_request_paths("anthropic", "https://gw.example/anthropic/") == (
        "/anthropic/v1/messages",
        "/anthropic/v1/messages/count_tokens",
    )
    assert expected_request_paths("openai_compatible", "https://api.openai.com/v1") == (
        "/v1/chat/completions",
    )


def test_an_unknown_provider_type_has_no_shape_and_says_so() -> None:
    """A type whose expected requests are unknown must not be wired as one whose every
    request is expected."""
    with pytest.raises(ValueError, match="no expected request shape"):
        expected_request_paths("bedrock", "https://example")


# ---------------------------------------------------------------------------
# decide_request: refused before the cap and before the key
# ---------------------------------------------------------------------------


def _decide(
    *,
    host: str = "api.anthropic.com",
    method: str = "POST",
    path: str = _OBSERVED_PATH,
    body: bytes = _MODEL_BODY,
    caps: CapLedger | None = None,
    shapes: dict[str, ProviderRequestShape] | None = None,
):  # type: ignore[no-untyped-def]
    broker = _broker()
    return decide_request(
        ts=_TS,
        method=method,
        scheme="https",
        host=host,
        port=443,
        path=path,
        headers={"Authorization": f"Bearer {broker.sandbox_token('anthropic')}"},
        body=body,
        allowlist=EgressAllowlist(
            provider_endpoints=_PROVIDERS,
            infrastructure_endpoints=_INFRA,
            extra=frozenset({"files.example"}),
        ),
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        broker=broker,
        provider_of_host=_PROVIDER_OF_HOST,
        caps=caps or CapLedger(max_requests=100, max_request_bytes=1_000_000),
        provider_shapes=_SHAPES if shapes is None else shapes,
    )


def test_a_conforming_model_call_is_forwarded_with_the_real_key() -> None:
    decision = _decide()
    assert decision.action == "forward"
    assert decision.injected
    assert decision.upstream_headers["Authorization"] == f"Bearer {_REAL_KEY}"
    assert not decision.flow.blocked and not decision.flow.shape_violation


def test_an_unexpected_endpoint_is_blocked_and_never_sees_the_key() -> None:
    decision = _decide(path="/v1/files?beta=true")
    assert decision.action == "block"
    assert not decision.injected
    assert decision.upstream_headers == {}
    assert decision.flow.blocked
    assert decision.flow.shape_violation
    assert decision.flow.block_reason == decision.flow.shape_violation
    # The host *was* permitted: the record must say the request was refused for its shape,
    # not that the host was outside the allowlist.
    assert "allowlist" not in decision.flow.block_reason
    assert decision.flow.egress_class == "model_api"


def test_a_refused_request_is_not_charged_to_the_caps() -> None:
    caps = CapLedger(max_requests=100, max_request_bytes=1_000_000)
    _decide(path="/v1/files", caps=caps)
    assert (caps.requests, caps.request_bytes) == (0, 0)


def test_a_provider_subdomain_is_held_to_its_providers_shape() -> None:
    """The same label-boundary match the broker uses: ``eu.api.anthropic.com`` classifies as the
    provider, gets the provider's key, and is held to the provider's shape — an exact lookup
    would have let the subdomain through unchecked."""
    assert _decide(host="eu.api.anthropic.com", path="/v1/files").action == "block"
    assert _decide(host="eu.api.anthropic.com").action == "forward"


def test_a_non_provider_host_is_not_shape_checked() -> None:
    """The rule is about the model channel; an allowlisted skill host carries whatever its
    operator permitted, scanned for canaries and charged to the caps as before."""
    decision = _decide(host="files.example", method="PUT", path="/upload", body=b"blob")
    assert decision.action == "forward" and not decision.flow.shape_violation


def test_a_websocket_frame_to_the_provider_is_not_a_model_call() -> None:
    """Frames are decided as requests (§10.5.0); a frame to the provider host has the wrong
    method by construction, so no socket to the model host carries anything past this rule."""
    addon = _addon()
    block = addon.on_websocket_message(
        "api.anthropic.com", 443, scheme="https", path="/v1/messages", content=_MODEL_BODY
    )
    assert block is not None and block.status == BLOCK_STATUS_DENIED
    assert addon.flows()[-1].shape_violation


# ---------------------------------------------------------------------------
# The addon, the wire, the trace
# ---------------------------------------------------------------------------


def _addon() -> ProxyAddon:
    return ProxyAddon(
        allowlist=EgressAllowlist(provider_endpoints=_PROVIDERS, infrastructure_endpoints=_INFRA),
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        broker=_broker(),
        provider_of_host=_PROVIDER_OF_HOST,
        caps=CapLedger(max_requests=100, max_request_bytes=1_000_000),
        clock=lambda: _TS,
        provider_shapes=_SHAPES,
    )


def _refused_and_forwarded() -> ProxyAddon:
    addon = _addon()
    assert addon.on_request(_FakeRequest(path=_OBSERVED_PATH, content=_MODEL_BODY)) is None
    block = addon.on_request(_FakeRequest(path="/v1/files?beta=true", content=b"blob"))
    assert block is not None and block.status == BLOCK_STATUS_DENIED
    assert "not an expected provider endpoint" in block.reason
    return addon


def test_the_addon_refuses_with_a_denial_and_records_the_rule() -> None:
    forwarded, refused = _refused_and_forwarded().flows()
    assert not forwarded.blocked and not forwarded.shape_violation
    assert refused.blocked and refused.shape_violation


def test_the_violation_survives_the_sidecar_to_host_wire() -> None:
    refused = _refused_and_forwarded().flows()[-1]
    assert parse_flow_record(flow_record_line(refused)).shape_violation == refused.shape_violation


def _plane_d() -> list:  # type: ignore[type-arg]
    plane_d = egress_actions(_refused_and_forwarded().flows(), start_seq=10)
    return plane_d + provider_endpoint_actions(plane_d, start_seq=10 + len(plane_d))


def test_the_trace_carries_the_finding_anchored_to_the_refusal() -> None:
    sent, refused, finding = _plane_d()
    assert sent.kind == "egress_request"
    assert refused.kind == "egress_blocked" and refused.action["shape_violation"]
    assert finding.kind == "unexpected_provider_endpoint" and finding.plane == "egress"
    assert finding.action["severity"] == "high"
    assert finding.action["path"] == "/v1/files?beta=true"
    assert finding.correlation is not None and finding.correlation.anchor_seq == refused.seq
    assert finding.seq == 12


def test_no_finding_is_derived_from_an_allowlist_denial_or_a_cap() -> None:
    """The producer reads only shape refusals: a default-deny block and a budget refusal are
    different findings with different gates, and must not be relabelled as this one."""
    addon = _addon()
    addon.on_request(_FakeRequest(host="evil.example"))
    capped = ProxyAddon(
        allowlist=addon.allowlist,
        provider_endpoints=_PROVIDERS,
        infrastructure_endpoints=_INFRA,
        broker=_broker(),
        provider_of_host=_PROVIDER_OF_HOST,
        caps=CapLedger(max_requests=0, max_request_bytes=1),
        clock=lambda: _TS,
        provider_shapes=_SHAPES,
    )
    capped.on_request(_FakeRequest(path=_OBSERVED_PATH, content=_MODEL_BODY))
    plane_d = egress_actions(addon.flows() + capped.flows())
    assert [a.kind for a in plane_d] == ["egress_blocked", "egress_blocked"]
    assert provider_endpoint_actions(plane_d) == []


def test_the_finding_is_a_reading_of_the_refusal_not_a_second_step() -> None:
    """One refused request is one trajectory step: the finding anchors to it and adds none."""
    context = NormalizationContext(workspace_root="/work/x")
    plane_d = _plane_d()
    with_finding = canonicalize(plane_d, context).step_sequence
    without = canonicalize(plane_d[:2], context).step_sequence
    assert with_finding == without
    assert len(with_finding) == 2


# ---------------------------------------------------------------------------
# The evidence index: a shape refusal is this finding and nothing else
# ---------------------------------------------------------------------------


def _trace(plane_d: list) -> Trace:  # type: ignore[type-arg]
    header = make_header(
        coverage=Coverage(
            harness_events=PlaneCoverage(fidelity="full"),
            egress=PlaneCoverage(fidelity="full"),
        )
    )
    return Trace(header=header, actions=tuple(plane_d), footer=make_footer())


def test_the_index_reads_the_finding_and_not_an_allowlist_denial() -> None:
    index = EvidenceIndex.from_trace(_trace(_plane_d()), NormalizationContext("/work/x"))
    assert index.unexpected_provider_endpoint_present
    # The host was permitted. Reading the refusal as "egress outside the allowlist" would fire
    # the egress gate with a reason that is false, and count a model-host request as the
    # skill's own egress for `no_egress` and the network scope rows.
    assert not index.egress_blocked_present
    assert index.egress_blocked_flows == ()
    assert evaluate(AssertionSpec.model_validate({"no_egress": True}), index).status == "pass"


def test_a_clean_observed_trace_reads_absent() -> None:
    plane_d = _plane_d()[:1]
    index = EvidenceIndex.from_trace(_trace(plane_d), NormalizationContext("/work/x"))
    assert not index.unexpected_provider_endpoint_present


# ---------------------------------------------------------------------------
# The gate's decision table
# ---------------------------------------------------------------------------

_TARGET = TargetInfo(harness="claude-code", provider="anthropic", model_alias="haiku")


def _profile(disposition: str) -> ProfileSpec:
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    base = policy.profile("low")
    security = base.gates.security_runtime.model_copy(
        update={"unexpected_provider_endpoint": disposition}
    )
    return base.model_copy(
        update={"gates": base.gates.model_copy(update={"security_runtime": security})}
    )


def _reading(*, observed: bool, unexpected: bool) -> SetReading:
    return SetReading(
        scenario_id="s",
        target=_TARGET,
        n_completed=6,
        n_evaluable=6,
        pass_rate=1.0,
        lower_bound=0.6,
        functional_threshold=0.5,
        look=6,
        look_outcome="pass",
        bci=100.0,
        consistently_failing=False,
        jaccard_weighted=1.0,
        jaccard_plain=1.0,
        modal_trajectory_share=1.0,
        mean_pairwise_distance=0.0,
        rare_capability_risk="none",
        rare_capability_blocking=False,
        tier1_agreement=True,
        scope_exceeded=(),
        egress_observed=observed,
        egress_blocked=False,
        weights_digest="sha256:0",
        runs=(),
        provider_requests_observed=observed,
        unexpected_provider_endpoint=unexpected,
    )


def test_observed_and_clean_passes() -> None:
    result = _provider_endpoint_result(_reading(observed=True, unexpected=False), _profile("block"))
    assert result.status == "pass"
    assert "expected model call" in result.observed


def test_an_observed_refusal_under_a_blocking_profile_blocks() -> None:
    result = _provider_endpoint_result(_reading(observed=True, unexpected=True), _profile("block"))
    assert result.status == "block"
    assert "not a model call" in result.observed


def test_an_observed_refusal_under_a_warn_profile_only_warns() -> None:
    result = _provider_endpoint_result(_reading(observed=True, unexpected=True), _profile("warn"))
    assert result.status == "warn"


def test_unobserved_defers_rather_than_passing() -> None:
    result = _provider_endpoint_result(
        _reading(observed=False, unexpected=False), _profile("block")
    )
    assert result.status == "not_evaluable"
    assert "not observed" in result.reason


def test_a_refusal_in_an_otherwise_unobserved_set_still_surfaces() -> None:
    """Presence survives a degraded set; only the pass is an absence claim."""
    result = _provider_endpoint_result(_reading(observed=False, unexpected=True), _profile("block"))
    assert result.status == "block"


# ---------------------------------------------------------------------------
# §16.4: a blocking gate with no proxy is refused before spending
# ---------------------------------------------------------------------------


def _target(*, egress: bool) -> TargetDeclaration:
    return TargetDeclaration(
        label="claude-code/anthropic/haiku",
        provider="anthropic",
        capabilities={
            "structured_tool_events": True,
            "egress_observable": egress,
            "dns_observable": True,
            "controls_skill_presentation": True,
        },
    )


def test_a_blocking_provider_endpoint_gate_with_no_proxy_is_refused_up_front() -> None:
    planes = frozenset({"harness_events", "filesystem_writes", "credentials", "egress", "dns"})
    failures = check_preconditions(
        _profile("block"), [_target(egress=False)], available_planes=planes
    )
    ours = [f for f in failures if f.gate == "security_runtime.unexpected_provider_endpoint"]
    assert ours and "egress.image" in ours[0].remedy
    clean = check_preconditions(_profile("block"), [_target(egress=True)], available_planes=planes)
    assert not any(f.gate == "security_runtime.unexpected_provider_endpoint" for f in clean)
    softened = check_preconditions(
        _profile("warn"), [_target(egress=False)], available_planes=planes
    )
    assert not any(f.gate == "security_runtime.unexpected_provider_endpoint" for f in softened)


# ---------------------------------------------------------------------------
# config → provider → sidecar config: every provider host gets its shape
# ---------------------------------------------------------------------------

_IMG = "img@sha256:" + "d" * 64
_PROXY_IMG = "bw-proxy@sha256:" + "e" * 64


def _config(**providers: ProviderConfig) -> Config:
    return Config(
        apiVersion="bellwether/v1",
        kind="Config",
        providers=providers,
        sandbox=SandboxConfig(image=_IMG),
        egress=EgressConfig(image=_PROXY_IMG),
    )


def test_build_proxy_provider_gives_every_provider_host_a_shape_from_its_config() -> None:
    """At the wiring, not the helper: the shapes the sidecar is handed come from the configured
    providers — type, base_url and model set — for brokered and unbrokered providers alike."""
    provider = build_proxy_provider(
        _config(
            anthropic=ProviderConfig(
                type="anthropic",
                api_key_env="ANTHROPIC_API_KEY",
                models={"haiku": "claude-haiku-4-5-20251001", "mid": "claude-sonnet-4-5"},
            ),
            gateway=ProviderConfig(
                type="openai_compatible",
                base_url="https://gw.example/v1",
                api_key_env="GW_KEY",
                models={"small": "gpt-x"},
            ),
        )
    )
    assert provider is not None
    assert set(provider.provider_shapes) == set(provider.allowlist.provider_endpoints)
    assert provider.provider_shapes["api.anthropic.com"] == ProviderRequestShape(
        paths=("/v1/messages", "/v1/messages/count_tokens"),
        model_ids=("claude-haiku-4-5-20251001", "claude-sonnet-4-5"),
    )
    assert provider.provider_shapes["gw.example"] == ProviderRequestShape(
        paths=("/v1/chat/completions",), model_ids=("gpt-x",)
    )


def test_two_providers_on_one_host_union_their_model_sets() -> None:
    provider = build_proxy_provider(
        _config(
            a=ProviderConfig(type="anthropic", models={"x": "model-a"}),
            b=ProviderConfig(type="anthropic", models={"y": "model-b"}),
        )
    )
    assert provider is not None
    assert provider.provider_shapes["api.anthropic.com"].model_ids == ("model-a", "model-b")


def test_the_sidecar_config_carries_the_shapes_and_refuses_to_load_without_them() -> None:
    """The host writes the shapes into the sidecar's config and the sidecar rebuilds them; a
    config with no shapes is refused at load, because a proxy with none would put the real key
    on any request to a provider host — the hole this control closes, reopened by omission."""
    config = SidecarConfig(
        provider_endpoints=("api.anthropic.com",),
        infrastructure_endpoints=(),
        allowlist_extra=(),
        provider_of_host=_PROVIDER_OF_HOST,
        credential_export=_broker().sidecar_export(),
        max_requests=10,
        max_request_bytes=1000,
        flow_log_path="/bw/flows.jsonl",
        provider_shapes=_SHAPES,
    )
    assert SidecarConfig.from_json(config.to_json()).provider_shapes == _SHAPES
    import json

    stripped = json.loads(config.to_json())
    del stripped["provider_shapes"]
    with pytest.raises(KeyError):
        SidecarConfig.from_json(json.dumps(stripped))


def test_the_committed_live_configs_hold_the_cli_to_the_observed_shape(tmp_path: Path) -> None:
    """The proven live claude-code run must keep reaching `ready`: its config yields a shape that
    admits exactly the request the pinned CLI was observed to send, with its configured model."""
    from bellwether.config import load_config

    config = load_config(Path("examples/live/config-claude-code.yaml"))
    provider = build_proxy_provider(config, brokered_providers=["anthropic"])
    assert provider is not None
    shape = provider.provider_shapes["api.anthropic.com"]
    observed_body = b'{"model": "claude-haiku-4-5-20251001", "messages": [], "stream": true}'
    assert (
        shape_violation(method="POST", path=_OBSERVED_PATH, body=observed_body, shape=shape) == ""
    )
    assert shape_violation(method="POST", path="/v1/files?beta=true", body=b"", shape=shape)


def test_the_executor_derives_the_finding_from_plane_d_before_the_header_is_built() -> None:
    """Pinned on the source because the executor needs a Docker daemon and the minimal sandbox
    test image carries no HTTP client to send a refused request with; the producer it calls and
    the gate it feeds are each proven above, and the proxy's own refusal is measured against the
    real mitmdump (spec-notes §10.5.2)."""
    source = (
        Path(__file__).resolve().parents[1] / "src" / "bellwether" / "cli" / "execution.py"
    ).read_text(encoding="utf-8")
    plane_d = source.index("plane_d = egress_actions(egress_flows")
    finding = source.index("plane_d += provider_endpoint_actions(")
    header = source.index("header = RunHeader(")
    assert plane_d < finding < header
