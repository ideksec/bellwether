"""``.bellwether/config.yaml`` — the global configuration document (§21)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from bellwether.config.models.common import Document, StrictModel, YamlWord
from bellwether.config.models.provider import ProviderConfig
from bellwether.constants import SENSITIVE_DIRECTORIES

__all__ = [
    "NOT_BUILT_SETTINGS",
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
    #: Matches §21 and IsolationProfile.writable_paths. The harness state zone must be
    #: here: under a read-only root, a path with no writable mount is read-only whatever
    #: the profile declares.
    writable_paths: list[str] = Field(
        default_factory=lambda: ["/work", "/tmp", "/home/agent/.claude"]
    )
    randomize_identifiers: bool = True

    @field_validator("backend")
    @classmethod
    def _only_docker_is_built(cls, value: str) -> str:
        # §9.2 names gVisor and Firecracker, and the schema accepted both — but every run started
        # a plain Docker container. An operator who asked for the stronger boundary silently got
        # the weaker one, which is the worst way for a control to be inert. Refused, not warned.
        if value != "docker":
            raise ValueError(
                f"sandbox.backend {value!r} is not built in this version; only 'docker' is — "
                "a run would start a plain Docker container, not the isolation you asked for"
            )
        return value


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
    #: The recording-proxy sidecar image, digest-pinned like ``sandbox.image``. Empty leaves
    #: the proxy unwired: the run has no egress plane and the sandbox runs with no network, the
    #: first-light configuration. Set it (in a live config) to route the sandbox through the
    #: proxy and observe egress (§10.5).
    image: str = ""
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
    #: The controlled-resolver sidecar image, digest-pinned like ``sandbox.image``. Empty leaves
    #: the resolver unwired: the run has no DNS plane. Set it (in a live config) to point the
    #: sandbox at the resolver via ``--dns`` and observe query names — the covert channel that
    #: routes around the HTTP proxy (§10.6). Mirrors ``egress.image``.
    image: str = ""
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
    #: The §13.5.4 list, reaching the analysis through ``canonicalize``. Defaulted from
    #: the constant rather than restated, because the two spellings drifted once already:
    #: this list said ``~/`` while the matcher yields ``~``, so the home root would have
    #: been switched off the moment the list was connected.
    sensitive_directories: list[str] = Field(default_factory=lambda: list(SENSITIVE_DIRECTORIES))

    @field_validator("sensitive_directories")
    @classmethod
    def _entries_can_match(cls, value: list[str]) -> list[str]:
        """Refuse an entry no tier-2 capability could ever equal (§13.5.4).

        Membership is exact against the token ``sensitive_directory_of`` extracts, so an
        entry it cannot produce is not a weak rule — it is no rule, silently. A list that
        reads as protection and is not is the defect this whole gate exists to close, so
        it fails at config load instead of at nothing.
        """
        for entry in value:
            if entry == "~":
                continue
            if not entry:
                # `StrictModel` sets `str_strip_whitespace`, so pydantic has already stripped
                # every entry before this runs: `" .aws/"` arrives as `".aws/"` and works, and a
                # whitespace-only entry arrives empty and lands here. An earlier version of this
                # validator carried a separate "leading or trailing whitespace" branch to make
                # that message clearer — it was unreachable, could not be revert-proved, and its
                # own advice for a whitespace-only entry was to "write it as ''", which this
                # branch rejects. Saying it here, once, is the whole fix.
                raise ValueError(
                    "sensitive_directories carries an empty entry (or one that is only "
                    "whitespace, which is stripped before validation); each entry names one "
                    "directory (with a trailing slash) or one workspace-root file"
                )
            if entry.startswith("~") or entry in ("${HOME}", "$HOME"):
                raise ValueError(
                    f"sensitive_directories entry {entry!r} cannot match: the home root is "
                    "spelled '~', with no trailing slash and no expansion, and a path "
                    "beneath it is named by its own directory (e.g. '.aws/')"
                )
            if "/" in entry.rstrip("/"):
                raise ValueError(
                    f"sensitive_directories entry {entry!r} cannot match: an entry names a "
                    "single directory or file, not a path — use '.aws/', not '~/.aws/'"
                )
        return value


class BaselinesConfig(StrictModel):
    storage: Literal["git", "release-asset", "cache"] = "git"


class RunLimitsConfig(StrictModel):
    """What one run may spend before the adapter stops it (§9.2, §12.7).

    These are *operator* bounds, not observations about the skill, and the outcome they
    produce says so: hitting ``max_turns`` or ``max_tool_calls`` is timeout-shaped (§12.7
    scores it as a failure, because an agent that cannot finish inside a generous bound has
    told you something), while ``max_total_tokens`` is ``budget_exceeded`` and therefore
    ``not_evaluable``. Tightening either of the first two turns an operator's choice into a
    skill's failing score, so the limits in force are recorded on every run header rather
    than left implicit — a reader of a limit-stopped trace can see which bound stopped it
    and who chose that bound.

    The wall clock is deliberately absent: §7.2 gives it to the scenario (``timeout_seconds``,
    else the suite's ``defaults``), and a second wall clock here would silently override the
    per-scenario one that the suite author chose.
    """

    #: 32 rather than a tighter bound: a real agentic session that reads a repository and
    #: writes a report routinely spends a dozen turns, and a cap that bites reads as a skill
    #: that could not finish.
    max_turns: Annotated[int, Field(ge=1)] = 32
    max_tool_calls: Annotated[int, Field(ge=1)] = 128
    #: The one bound that is a cost control rather than a behavioural one; ``bellwether run
    #: --max-tokens`` overrides it per invocation.
    max_total_tokens: Annotated[int, Field(ge=1)] = 1_000_000


class ExecutionConfig(StrictModel):
    concurrency: Annotated[int, Field(ge=1)] = 4
    #: Infrastructure causes only. A skill that OOMs is data, not a flake (§13.2).
    retry_on_infra_error: Annotated[int, Field(ge=0)] = 2
    cache: bool = True
    cache_ttl_days: Annotated[int, Field(ge=0)] = 14
    #: Per-run bounds the adapter enforces. Configuration rather than policy on purpose:
    #: §19.2 requires that a policy change re-derive verdicts from cached traces without
    #: re-running anything, which would not hold if a profile could change what runs happen.
    limits: RunLimitsConfig = Field(default_factory=RunLimitsConfig)


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
    def _harness_type_is_its_name(self) -> Config:
        # The executor chooses the adapter by the harness's *name*, and ``type`` was never read:
        # ``harnesses: {claude-code: {type: api-loop}}`` ran the Claude Code CLI. A declaration
        # that disagrees with what runs is refused, as is the adapter that was never built.
        for name, harness in self.harnesses.items():
            if harness.type == "generic-subprocess":
                raise ValueError(
                    f"harnesses.{name}.type 'generic-subprocess' is not built in this version; "
                    "the built harnesses are 'api-loop' and 'claude-code'"
                )
            if name != harness.type:
                raise ValueError(
                    f"harnesses.{name}.type is {harness.type!r}, but the harness that runs is "
                    f"chosen by its name ({name!r}); name the entry {harness.type!r}"
                )
        return self

    @model_validator(mode="after")
    def _judges_reference_a_configured_provider(self) -> Config:
        if self.judges and self.providers and self.judges.default.provider not in self.providers:
            known = ", ".join(sorted(self.providers)) or "none configured"
            raise ValueError(
                f"judges.default.provider {self.judges.default.provider!r} "
                f"is not a configured provider (configured: {known})"
            )
        return self

    def not_built_settings(self) -> list[tuple[str, str]]:
        """The settings this ``config.yaml`` sets that this build does not act on, with why.

        Only what the document sets explicitly — a default the operator never wrote is not a
        claim they made — and each registry entry at most once, at the path it was written.
        """
        found: dict[str, tuple[str, str]] = {}
        for path in _explicit_paths(self):
            for pattern, reason in NOT_BUILT_SETTINGS.items():
                if pattern not in found and _matches(pattern, path):
                    found[pattern] = (".".join(path.split(".")[: len(pattern.split("."))]), reason)
        return sorted(found.values())

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
        if self.egress.image and "@sha256:" not in self.egress.image:
            notes.append(
                f"egress.image {self.egress.image!r} is not pinned by digest; "
                "a moving proxy image makes two evaluations non-comparable"
            )
        if self.dns.image and "@sha256:" not in self.dns.image:
            notes.append(
                f"dns.image {self.dns.image!r} is not pinned by digest; "
                "a moving resolver image makes two evaluations non-comparable"
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


#: Settings the schema accepts that this build does not act on, and why (CLAUDE.md: "a control
#: the schema accepts must enforce or refuse"). A path matches a field and everything under it;
#: ``*`` matches one dict key. :meth:`Config.not_built_settings` reports every one of these that a
#: ``config.yaml`` sets explicitly, and ``doctor`` and ``run`` say so, so an operator never reads a
#: setting as honoured when nothing reads it. ``tests/test_config_registry.py`` fails the build on a
#: field classified nowhere, and on an entry here that the code has started to read.
NOT_BUILT_SETTINGS: dict[str, str] = {
    "harnesses.*.install": "Bellwether installs no harness; the sandbox image carries it",
    "harnesses.*.tools": "api-loop always offers its built-in tool set",
    "capture.filesystem_writes": "the overlay write plane is always mounted; 'off' is ignored",
    "capture.filesystem_reads": "the fanotify read plane is not built (v0.2)",
    "capture.process": "the eBPF/ptrace process plane is not built (v0.3)",
    "capture.harness_hooks": "claude-code's hooks are always installed",
    "capture.harness_event_sink": "the hook sink is always a host-owned FIFO",
    "egress.record_response_bodies": "the proxy records requests; response bodies are not kept",
    "egress.max_body_bytes": "the proxy records requests; response bodies are not kept",
    "egress.parse_server_side_tools": "server-side tool calls are not parsed (plane unavailable)",
    "egress.volume_anomaly_factor": "the egress_volume_anomaly disposition is not scored",
    "dns.log_all_queries": "the controlled resolver always records every query",
    "canaries.canary_set": "the default canary set is always planted",
    "canaries.custom_path": "the default canary set is always planted",
    "canaries.randomize_paths": "canary files are planted at fixed paths (~/.aws/credentials, …)",
    "canaries.alerting_webhook": "no alert is sent; a leak is reported in the verdict",
    "judges": "the judge subsystem is not built; judged gates are not composed",
    "embeddings": "no embedding provider is used; the BCI output component is excluded",
    "baselines.storage": "baselines are read from the --baselines directory",
    "execution.concurrency": "runs execute one at a time",
    "reporting.html": "the HTML report is always written",
    "reporting.sarif": "no SARIF report is produced",
    "reporting.retention_days": "Bellwether never prunes artifacts",
}


def _explicit_paths(model: StrictModel, prefix: str = "") -> list[str]:
    """Every field path a document set explicitly, dict entries included as ``*``-free keys."""
    paths: list[str] = []
    for name in sorted(model.model_fields_set):
        path = f"{prefix}.{name}" if prefix else name
        paths.append(path)
        value = getattr(model, name)
        if isinstance(value, StrictModel):
            paths.extend(_explicit_paths(value, path))
        elif isinstance(value, dict):
            for key in sorted(value):
                entry = value[key]
                paths.append(f"{path}.{key}")
                if isinstance(entry, StrictModel):
                    paths.extend(_explicit_paths(entry, f"{path}.{key}"))
    return paths


def _matches(pattern: str, path: str) -> bool:
    want, have = pattern.split("."), path.split(".")
    if len(have) < len(want):
        return False
    return all(w in ("*", h) for w, h in zip(want, have, strict=False))
