"""The evidence index: one trace, pre-sorted for assertion evaluation (§12.1).

Assertions evaluate against the trace, the final workspace state, and the final output
— never against the model's self-report of what it did. The index extracts each
evidence category once, with normalized paths, so every assertion in the catalogue
reads the same prepared facts rather than re-walking the action list with its own
private interpretation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bellwether.sandbox import normalize_container_path
from bellwether.trace import (
    Action,
    Coverage,
    ExitReason,
    NormalizationContext,
    PlaneCoverage,
    Trace,
    filesystem_access,
)

__all__ = ["EgressEvidence", "EvidenceIndex", "ToolCallEvidence", "WriteEvidence"]


@dataclass(frozen=True)
class ToolCallEvidence:
    seq: int
    name: str
    input: dict[str, Any]
    #: The input serialised once, for ``args_match`` regexes.
    args_json: str


@dataclass(frozen=True)
class WriteEvidence:
    """One persisted filesystem change, from Plane B."""

    seq: int
    zone: str
    #: Normalized (``${WORKSPACE}/...``) absolute path.
    path: str
    deleted: bool


@dataclass(frozen=True)
class EgressEvidence:
    """One permitted egress flow the recording proxy observed, from Plane D (§10.5)."""

    seq: int
    host: str
    #: ``model_api`` / ``harness_infrastructure`` / ``skill_attributed`` (§10.5.0). Only
    #: the last is the skill's own traffic; the precedence check (§10.8) compares only
    #: that class against Plane A claims, because harness traffic has no A-side claim.
    egress_class: str


@dataclass(frozen=True)
class EvidenceIndex:
    """Everything the deterministic catalogue consumes, extracted once."""

    tool_calls: tuple[ToolCallEvidence, ...]
    writes: tuple[WriteEvidence, ...]
    #: Paths the harness reported reading (the ``read`` tool), normalized. Plane A
    #: evidence: usable for presence claims, never for absence claims (§10.8).
    reported_reads: tuple[tuple[int, str], ...]
    activated_skills: tuple[tuple[int, str], ...]
    final_output: str | None
    final_output_seq: int | None
    exit_reason: ExitReason | None
    trace_complete: bool
    wall_clock_ms: int | None
    total_tokens: int | None
    coverage: Coverage
    #: The run's own skill, for the bare ``skill_activated`` assertion.
    skill_name: str
    #: The final workspace on disk, where the caller still has it. Content-inspecting
    #: assertions (``content_match``, ``artifact_valid``) need real bytes; without this
    #: they return ``not_evaluable`` rather than guessing from digests.
    workspace: Path | None = None
    egress_blocked_present: bool = False
    #: Every permitted Plane D flow, with its §10.5.0 class — what the §10.8 precedence
    #: check compares against Plane A tool-call claims.
    egress_requests: tuple[EgressEvidence, ...] = ()
    #: A Plane C ``canary_leak`` finding is in the trace: a planted canary appeared at a
    #: non-model destination (§10.4.1) — critical by classification, and what turns the
    #: canary gate from pass to block. Presence evidence, so plane fidelity cannot soften it.
    canary_leak_present: bool = False
    #: A Plane C ``canary_without_read`` finding is in the trace: a planted canary reached
    #: the model's context with no recorded read carrying it there (§10.4.1, high) — the
    #: value arrived by some path Plane A cannot account for. What turns the canary-reads
    #: gate from pass to block.
    canary_without_read_present: bool = False
    #: A Plane E ``dns_blocked`` action is in the trace: the controlled resolver refused a
    #: name outside the allowlist (§10.6) — evidence of intent, exactly like a default-deny
    #: egress block, and what turns the DNS gate from pass to block.
    dns_blocked_present: bool = False
    context: NormalizationContext = field(
        default_factory=lambda: NormalizationContext(workspace_root="/work")
    )

    @classmethod
    def from_trace(
        cls,
        trace: Trace,
        context: NormalizationContext,
        *,
        workspace: Path | None = None,
    ) -> EvidenceIndex:
        tool_calls: list[ToolCallEvidence] = []
        writes: list[WriteEvidence] = []
        reads: list[tuple[int, str]] = []
        activated: list[tuple[int, str]] = []
        final_output: str | None = None
        final_output_seq: int | None = None
        egress_blocked = False
        egress_requests: list[EgressEvidence] = []
        canary_leak = False
        canary_without_read = False
        dns_blocked = False

        for action in trace.actions:
            if action.plane == "harness":
                _index_harness_action(action, context, tool_calls, reads, activated)
                if action.kind == "final_output":
                    text = action.action.get("text")
                    final_output = text if isinstance(text, str) else ""
                    final_output_seq = action.seq
            elif action.plane == "filesystem":
                write = _index_filesystem_action(action, context)
                if write is not None:
                    writes.append(write)
            elif action.kind == "egress_blocked":
                egress_blocked = True
            elif action.kind == "egress_request":
                host = action.action.get("host")
                egress_class = action.action.get("egress_class")
                if isinstance(host, str) and isinstance(egress_class, str):
                    egress_requests.append(
                        EgressEvidence(seq=action.seq, host=host, egress_class=egress_class)
                    )
            elif action.kind == "dns_blocked":
                dns_blocked = True
            elif action.plane == "credentials" and action.kind == "canary_leak":
                canary_leak = True
            elif action.plane == "credentials" and action.kind == "canary_without_read":
                canary_without_read = True

        footer = trace.footer
        return cls(
            tool_calls=tuple(tool_calls),
            writes=tuple(writes),
            reported_reads=tuple(reads),
            activated_skills=tuple(activated),
            final_output=final_output,
            final_output_seq=final_output_seq,
            exit_reason=trace.exit_reason,
            trace_complete=trace.is_complete,
            wall_clock_ms=footer.wall_clock_ms if footer else None,
            total_tokens=footer.tokens.total if footer else None,
            coverage=trace.header.coverage,
            skill_name=trace.header.skill.name,
            workspace=workspace,
            egress_blocked_present=egress_blocked,
            egress_requests=tuple(egress_requests),
            canary_leak_present=canary_leak,
            canary_without_read_present=canary_without_read,
            dns_blocked_present=dns_blocked,
            context=context,
        )

    def workspace_writes(self) -> list[WriteEvidence]:
        return [write for write in self.writes if write.zone == "workspace" and not write.deleted]

    def plane_reason(self, plane: str, *, for_absence: bool = False) -> str | None:
        """The §10.7 reason an assertion cannot run, or None where the plane is usable.

        ``for_absence`` applies §10.8's stricter test. A ``partial`` plane is usable for a
        presence claim but not for an absence one: it observed only part of its domain and
        so cannot witness that something never happened. Presence assertions leave
        ``for_absence`` at its default; absence assertions set it, and a partial plane
        then reads as ``not_evaluable`` with its coverage reason rather than silently
        passing the absence claim.
        """
        unavailable = self.coverage.unavailable()
        if plane in unavailable:
            return unavailable[plane]
        status: PlaneCoverage | None = getattr(self.coverage, plane, None)
        if status is None:
            return f"the {plane} plane recorded no coverage for this run"
        if for_absence and not status.is_usable_for_absence():
            return status.reason or (
                f"{plane} coverage is {status.fidelity}, which cannot support an absence "
                "claim: only part of the plane's domain was observed"
            )
        return None


def _index_harness_action(
    action: Action,
    context: NormalizationContext,
    tool_calls: list[ToolCallEvidence],
    reads: list[tuple[int, str]],
    activated: list[tuple[int, str]],
) -> None:
    if action.kind == "tool_call":
        tool = action.action.get("tool")
        tool_input = action.action.get("input")
        if isinstance(tool, str):
            payload = tool_input if isinstance(tool_input, dict) else {}
            tool_calls.append(
                ToolCallEvidence(
                    seq=action.seq,
                    name=tool,
                    input=payload,
                    args_json=json.dumps(payload, sort_keys=True),
                )
            )
            # The same harness-tool table the canonicaliser uses (§11.2), so a `Read` on
            # Claude Code and a `read` on api-loop are the same reported read here.
            access = filesystem_access(tool, payload)
            if access is not None and not access.write:
                reads.append((action.seq, _normalize_tool_path(access.path, context)))
    elif action.kind == "skill_activated":
        skill = action.action.get("skill")
        if isinstance(skill, str):
            activated.append((action.seq, skill))


def _index_filesystem_action(action: Action, context: NormalizationContext) -> WriteEvidence | None:
    if action.kind not in ("file_write", "file_delete"):
        return None
    path = action.action.get("path")
    zone = action.action.get("zone")
    if not isinstance(path, str) or not isinstance(zone, str):
        return None
    return WriteEvidence(
        seq=action.seq,
        zone=zone,
        path=context.normalize_path(path),
        deleted=action.kind == "file_delete",
    )


def _normalize_tool_path(path: str, context: NormalizationContext) -> str:
    """The path a tool call actually *reached*, normalized (§11.4, §12.6).

    ``..`` is collapsed the same way ``capability_for`` collapses it (via
    ``normalize_container_path``), so ``reported_reads`` records the reached path rather
    than the raw one. Without this the two views disagree: a read of ``sub/../.env``
    would evade a ``file_not_read('${WORKSPACE}/.env')`` derived from ``deny_read``, and a
    traversal escape such as ``../../etc/shadow`` would still carry a ``${WORKSPACE}``
    prefix and read as an in-scope workspace access instead of the out-of-scope
    ``/etc/shadow`` it truly is.
    """
    absolute = path if path.startswith("/") else f"{context.workspace_root.rstrip('/')}/{path}"
    reached = str(normalize_container_path(absolute))
    return context.normalize_path(reached)
