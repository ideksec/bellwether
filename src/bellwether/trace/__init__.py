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

from bellwether.trace.build import assemble_coverage, filesystem_actions
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
    RunFooter,
    RunHeader,
    SandboxRef,
    ScopeBlock,
    SkillRef,
    TargetRef,
    TokenTotals,
)
from bellwether.trace.reader import Evaluability, Trace, iter_actions, parse_trace, read_trace
from bellwether.trace.writer import TraceWriter, serialize_record, write_trace

__all__ = [
    "ARF_VERSION",
    "Action",
    "Actor",
    "CanonBlock",
    "Capability",
    "Correlation",
    "Coverage",
    "Evaluability",
    "ExitReason",
    "IdentityBlock",
    "PlaneCoverage",
    "RunFooter",
    "RunHeader",
    "SandboxRef",
    "ScopeBlock",
    "SkillRef",
    "TargetRef",
    "TokenTotals",
    "Trace",
    "TraceWriter",
    "assemble_coverage",
    "filesystem_actions",
    "iter_actions",
    "parse_trace",
    "read_trace",
    "serialize_record",
    "write_trace",
]
