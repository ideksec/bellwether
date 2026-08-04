"""``.bellwether/config.yaml`` — the global configuration document (§21)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from bellwether.config.models.common import Document, StrictModel, YamlWord
from bellwether.config.models.provider import ProviderConfig

__all__ = [
    "BciWeights",
    "CanaryConfig",
    "CaptureConfig",
    "Config",
    "EnforcedSetting",
    "ExecutionConfig",
    "HarnessConfig",
    "SandboxConfig",
    "ZoneConfig",
]


class HarnessConfig(StrictModel):
    """One configured agent runtime (§9.4)."""

    type: Literal["claude-code", "api-loop", "generic-subprocess"]
    version_pin: str | None = None
    install: Literal["auto", "preinstalled"] = "auto"
    #: Only meaningful for ``api-loop``: the tools Bellwether itself implements.
    tools: list[str] | None = None


class SandboxConfig(StrictModel):
    """Container backend and isolation profile (§9.2)."""

    backend: Literal["docker", "gvisor", "firecracker"] = "docker"
    image: str
    memory: str = "2g"
    cpus: Annotated[float, Field(gt=0)] = 2.0
    #: 512 rather than 256: a Node harness plus a language server plus git plus Python
    #: approaches 256 in normal operation, and hitting the limit produces a
    #: ``sandbox_error`` that reads as a skill failure.
    pids_limit: Annotated[int, Field(ge=1)] = 512
    #: 900 rather than 300: a full agentic session that reads a repository and writes a
    #: report routinely exceeds five minutes, and §12.2's ``exit_reason`` assertion turns
    #: those into failures that look like skill instability.
    timeout_seconds: Annotated[int, Field(ge=1)] = 900
    writable_paths: list[str] = Field(default_factory=lambda: ["/work", "/tmp"])
    randomize_identifiers: bool = True


class ZoneConfig(StrictModel):
    """The three filesystem zones, treated differently by capture and by policy (§10.2)."""

    workspace: str = "/work"
    harness_state: str = "/home/agent/.claude"
    scratch: str = "/tmp"


class CaptureConfig(StrictModel):
    """Which capture planes are active (§10). All of them run host-side (§10.0)."""

    filesystem_writes: Annotated[Literal["overlay", "off"], YamlWord] = "overlay"
    filesystem_reads: Annotated[Literal["fanotify", "off"], YamlWord] = "fanotify"
    process: Annotated[Literal["ebpf", "ptrace", "off"], YamlWord] = "ebpf"
    harness_hooks: bool = True
    #: A writable file in a mount is not acceptable: the sink must be owned by the host,
    #: outside the sandbox's ability to edit its own evidence (§10.1).
    harness_event_sink: Literal["fifo", "unix-socket"] = "fifo"
    zones: ZoneConfig = Field(default_factory=ZoneConfig)


class PerRunCaps(StrictModel):
    """Bounds on the residual model-API channel (§3.3, §10.5.2)."""

    max_requests: Annotated[int, Field(ge=1)] = 400
    max_request_bytes: Annotated[int, Field(ge=1)] = 33_554_432


class EgressConfig(StrictModel):
    """The recording proxy (§10.5)."""

    mode: Literal["proxy"] = "proxy"
    #: In-process couples mitmproxy's pinned transitive dependencies to Bellwether's
    #: resolved environment; the sidecar is the supported deployment (§10.5, §22).
    deployment: Literal["sidecar", "inprocess"] = "sidecar"
    #: Default-deny. Model endpoints are added automatically from ``providers``.
    allowlist: list[str] = Field(default_factory=list)
    record_response_bodies: bool = True
    max_body_bytes: Annotated[int, Field(ge=0)] = 65_536
    scan_model_api_bodies: bool = True
    parse_server_side_tools: bool = True
    volume_anomaly_factor: Annotated[float, Field(gt=0)] = 5.0
    per_run_caps: PerRunCaps = Field(default_factory=PerRunCaps)


class DnsConfig(StrictModel):
    """The controlled resolver (§10.6). An HTTP proxy does not see UDP/53."""

    mode: Annotated[Literal["controlled_resolver", "off"], YamlWord] = "controlled_resolver"
    allowlist: list[str] = Field(default_factory=list)
    log_all_queries: bool = True


class CanaryConfig(StrictModel):
    """Canary planting and redaction (§10.4, §3.5)."""

    enabled: bool = True
    canary_set: Annotated[
        Literal["default", "minimal", "custom"],
        Field(validation_alias="set", serialization_alias="set"),
    ] = "default"
    custom_path: str | None = None
    randomize_markers: bool = True
    randomize_paths: bool = True
    #: Redaction happens at capture time so no artifact ever holds a raw canary value;
    #: the teardown pass is a second net, not the primary control (§9.1 step 11).
    redact_at_capture: bool = True
    alerting_webhook: str | None = None

    @model_validator(mode="after")
    def _custom_needs_path(self) -> CanaryConfig:
        if self.canary_set == "custom" and not self.custom_path:
            raise ValueError("canaries.set 'custom' requires 'custom_path'")
        return self


class JudgeTarget(StrictModel):
    provider: str
    model_alias: str


class JudgesConfig(StrictModel):
    """Judged assertions (§12.3). Judged scores never contribute to security gates."""

    default: JudgeTarget
    n: Annotated[int, Field(ge=1)] = 3
    #: Label-level, not content-level. Judges are blind to model identity, condition and
    #: order; they are not blind to output content, and claiming otherwise would be
    #: exactly the overclaim §2 exists to prevent.
    label_blind: bool = True
    bootstrap_resamples: Annotated[int, Field(ge=1)] = 10_000
    bootstrap_seed: int = 20260804


class EmbeddingsConfig(StrictModel):
    """Optional. Absent, the output component is excluded from the BCI and the
    remaining weights are renormalised (§13.7)."""

    provider: str | None = None


class BciWeights(StrictModel):
    """Weights of the five BCI components (§13.7)."""

    outcome: Annotated[float, Field(ge=0, le=1)] = 0.30
    trigger: Annotated[float, Field(ge=0, le=1)] = 0.20
    trajectory: Annotated[float, Field(ge=0, le=1)] = 0.15
    capability: Annotated[float, Field(ge=0, le=1)] = 0.30
    output: Annotated[float, Field(ge=0, le=1)] = 0.05

    @model_validator(mode="after")
    def _sum_to_one(self) -> BciWeights:
        total = sum(
            (self.outcome, self.trigger, self.trajectory, self.capability, self.output),
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"the five BCI component weights must sum to 1.0, not {total:.6g}; "
                "renormalisation is for components that could not be measured, "
                "not for a mis-specified weighting"
            )
        return self


class MetricsConfig(StrictModel):
    bci_weights: BciWeights = Field(default_factory=BciWeights)
    #: Provisional. Calibrate against benign-stable / benign-chaotic; a threshold below
    #: the measured noise floor (§24) is meaningless.
    trajectory_cluster_threshold: Annotated[float, Field(ge=0, le=1)] = 0.2
    sensitive_directories: list[str] = Field(
        default_factory=lambda: [
            ".git/",
            ".ssh/",
            ".aws/",
            ".config/",
            ".gnupg/",
            ".docker/",
            ".kube/",
            "~/",
        ]
    )


class BaselinesConfig(StrictModel):
    storage: Literal["git", "release-asset", "cache"] = "git"


class ExecutionConfig(StrictModel):
    concurrency: Annotated[int, Field(ge=1)] = 4
    #: Infrastructure causes only. A skill that OOMs is data, not a flake (§13.2).
    retry_on_infra_error: Annotated[int, Field(ge=0)] = 2
    cache: bool = True
    cache_ttl_days: Annotated[int, Field(ge=0)] = 14


class ReportingConfig(StrictModel):
    html: bool = True
    sarif: bool = True
    retention_days: Annotated[int, Field(ge=0)] = 30


@dataclass(frozen=True)
class EnforcedSetting:
    """A setting whose disablement would make Bellwether report a result it has not earned.

    §21 names five. Setting any of them to the permissive value emits a ``critical``
    configuration finding and, under any profile above ``low``, refuses to run.
    """

    path: str
    observed: str
    required: str
    consequence: str

    def render(self) -> str:
        return (
            f"{self.path} is {self.observed}, which is not permitted "
            f"(expected {self.required}): {self.consequence}"
        )


class Config(Document):
    """The parsed ``.bellwether/config.yaml``."""

    kind: Literal["Config"]

    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    harnesses: dict[str, HarnessConfig] = Field(default_factory=dict)
    sandbox: SandboxConfig
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)
    dns: DnsConfig = Field(default_factory=DnsConfig)
    canaries: CanaryConfig = Field(default_factory=CanaryConfig)
    judges: JudgesConfig | None = None
    embeddings: EmbeddingsConfig = Field(default_factory=EmbeddingsConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    baselines: BaselinesConfig = Field(default_factory=BaselinesConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    @field_validator("providers", "harnesses")
    @classmethod
    def _named(cls, value: dict[str, object]) -> dict[str, object]:
        for name in value:
            if not name or name.strip() != name:
                raise ValueError(f"{name!r} is not a usable name")
        return value

    @model_validator(mode="after")
    def _judges_reference_a_configured_provider(self) -> Config:
        if self.judges and self.providers and self.judges.default.provider not in self.providers:
            known = ", ".join(sorted(self.providers)) or "none configured"
            raise ValueError(
                f"judges.default.provider {self.judges.default.provider!r} "
                f"is not a configured provider (configured: {known})"
            )
        return self

    def enforced_setting_violations(self) -> list[EnforcedSetting]:
        """Return the §21 enforced settings that have been turned off."""
        violations: list[EnforcedSetting] = []
        if not self.egress.scan_model_api_bodies:
            violations.append(
                EnforcedSetting(
                    "egress.scan_model_api_bodies",
                    "false",
                    "true",
                    "the model endpoint is authenticated, high-bandwidth and bidirectional; "
                    "a skill wanting to exfiltrate puts the value in a prompt (§3.3)",
                )
            )
        if self.egress.deployment != "sidecar":
            violations.append(
                EnforcedSetting(
                    "egress.deployment",
                    self.egress.deployment,
                    "sidecar",
                    "in-process operation couples the proxy's pinned dependencies to "
                    "Bellwether's resolved environment (§10.5)",
                )
            )
        if self.dns.mode != "controlled_resolver":
            violations.append(
                EnforcedSetting(
                    "dns.mode",
                    self.dns.mode,
                    "controlled_resolver",
                    "an HTTP proxy does not see UDP/53, so the DNS exfiltration channel "
                    "of §3.1 reopens in full",
                )
            )
        if self.canaries.enabled and not self.canaries.redact_at_capture:
            violations.append(
                EnforcedSetting(
                    "canaries.redact_at_capture",
                    "false",
                    "true",
                    "canary values would reach artifacts, which are attached to CI runs",
                )
            )
        if self.canaries.enabled and not self.canaries.randomize_markers:
            violations.append(
                EnforcedSetting(
                    "canaries.randomize_markers",
                    "false",
                    "true",
                    "a predictable marker format is the cheapest way for a skill to "
                    "detect that it is under evaluation (§3.5)",
                )
            )
        return violations

    def advisories(self) -> list[str]:
        """Non-blocking observations worth printing at load time."""
        notes: list[str] = []
        if "@sha256:" not in self.sandbox.image:
            notes.append(
                f"sandbox.image {self.sandbox.image!r} is not pinned by digest; "
                "a moving tag makes two evaluations non-comparable"
            )
        for name, provider in sorted(self.providers.items()):
            unfilled = provider.unfilled_aliases()
            if unfilled:
                notes.append(
                    f"providers.{name}.models still holds placeholders for: "
                    f"{', '.join(unfilled)} — fill in current model ids for your provider"
                )
        if self.capture.process == "off":
            notes.append(
                "capture.process is off; process-execution evidence will be reported as "
                "not_evaluable rather than passing (§10.7)"
            )
        return notes
