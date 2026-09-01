"""ARF: the Agent Run Format trace schema, normalization and merge (§11).

Responsibility
    ``run_header`` / ``action`` / ``run_footer`` models, the JSONL writer and reader,
    incomplete-trace detection (no footer implies ``not_evaluable``), path
    normalisation, the three capability tiers, platform-baseline subtraction, and
    **epoch anchoring** (§11.5) — the cross-plane ordering rule.

MUST NOT
    Do analysis. Metrics live in :mod:`bellwether.metrics`.

WP-3 built the schema, writer and reader. Canonicalization and epoch anchoring are WP-7:
never merge planes by wall-clock sort — within an epoch, order by ``(plane_priority,
kind, normalized_target, stable_hash)``. WP-7 is the package most likely to be got subtly
wrong, and WP-19's noise floor is the only test that proves it.
"""

from __future__ import annotations

from bellwether.trace.build import (
    assemble_coverage,
    canary_actions,
    dns_actions,
    egress_actions,
    egress_body_actions,
    exit_reason_from_events,
    filesystem_actions,
    harness_actions,
    model_channel_actions,
    redact_trace_actions,
    token_totals_from_events,
    tool_result_actions,
    written_file_actions,
)
from bellwether.trace.canonical import (
    CanonicalTrace,
    NormalizationContext,
    StepSignature,
    canonicalize,
    capability_for,
)
from bellwether.trace.epochs import PLANE_PRIORITY, anchor_events
from bellwether.trace.models import (
    ARF_VERSION,
    Action,
    Actor,
    CanonBlock,
    Capability,
    Correlation,
    Coverage,
    ExitReason,
    IdentityBlock,
    PlaneCoverage,
    PlantedCanary,
    RunFooter,
    RunHeader,
    SandboxRef,
    ScopeBlock,
    SkillRef,
    TargetRef,
    TokenTotals,
)
from bellwether.trace.reader import Evaluability, Trace, iter_actions, parse_trace, read_trace
from bellwether.trace.tool_vocabulary import FilesystemAccess, filesystem_access, tool_target
from bellwether.trace.writer import TraceWriter, serialize_record, write_trace

__all__ = [
    "ARF_VERSION",
    "PLANE_PRIORITY",
    "Action",
    "Actor",
    "CanonBlock",
    "CanonicalTrace",
    "Capability",
    "Correlation",
    "Coverage",
    "Evaluability",
    "ExitReason",
    "FilesystemAccess",
    "IdentityBlock",
    "NormalizationContext",
    "PlaneCoverage",
    "PlantedCanary",
    "RunFooter",
    "RunHeader",
    "SandboxRef",
    "ScopeBlock",
    "SkillRef",
    "StepSignature",
    "TargetRef",
    "TokenTotals",
    "Trace",
    "TraceWriter",
    "anchor_events",
    "assemble_coverage",
    "canary_actions",
    "canonicalize",
    "capability_for",
    "dns_actions",
    "egress_actions",
    "egress_body_actions",
    "exit_reason_from_events",
    "filesystem_access",
    "filesystem_actions",
    "harness_actions",
    "iter_actions",
    "model_channel_actions",
    "parse_trace",
    "read_trace",
    "redact_trace_actions",
    "serialize_record",
    "token_totals_from_events",
    "tool_result_actions",
    "tool_target",
    "write_trace",
    "written_file_actions",
]
