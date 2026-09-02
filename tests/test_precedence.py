"""Plane precedence: when planes disagree (§10.8 — WP-18).

The property with teeth: a finding is raised only where both planes are in-domain and the
plane whose *silence* is being read supports an absence claim. The spec's warning is that
the naive rule — any disagreement is a finding — fires on nearly every run while the
``high`` profile blocks on it; these tests pin each row of the matrix in both directions,
including the false-positive cases the section exists to prevent. The done-when (a real
``benign-stable`` container run at overlay-diff fidelity produces zero findings) is
asserted in ``test_execution_docker.py``.
"""

from __future__ import annotations

import datetime as dt
import json

from bellwether.assertions import (
    EgressEvidence,
    EvidenceIndex,
    ToolCallEvidence,
    WriteEvidence,
    trace_inconsistencies,
)
from bellwether.assertions.evidence import _index_filesystem_action
from bellwether.trace import Action, Coverage, NormalizationContext, PlaneCoverage


def _fs_write(path: str, *, canary_path: bool = False) -> Action:
    payload: dict[str, object] = {
        "path": path,
        "zone": "workspace",
        "zone_relative": path.rsplit("/", 1)[-1],
        "change": "created",
    }
    if canary_path:
        payload["canary_path"] = True
    return Action(
        seq=5,
        ts=dt.datetime(2026, 9, 2, tzinfo=dt.UTC),
        plane="filesystem",
        kind="file_write",
        action=payload,
    )


def test_a_planted_canary_write_is_not_write_evidence() -> None:
    """§10.4.3: the overlay captures a file canary's read-only bind as a `created`. Marked
    `canary_path`, it must not enter the write evidence the §10.8 matrix reads, or a benign run
    would report a cross-plane "disagreement" over Bellwether's own bait it never wrote. An
    ordinary unclaimed write is still indexed (and remains the matrix's business)."""
    ctx = NormalizationContext(workspace_root="/work")
    assert _index_filesystem_action(_fs_write("/work/.env", canary_path=True), ctx) is None
    assert _index_filesystem_action(_fs_write("/work/notes.md"), ctx) is not None


def _tool_call(seq: int, name: str, payload: dict[str, object]) -> ToolCallEvidence:
    return ToolCallEvidence(
        seq=seq, name=name, input=payload, args_json=json.dumps(payload, sort_keys=True)
    )


def _index(
    *,
    tool_calls: tuple[ToolCallEvidence, ...] = (),
    writes: tuple[WriteEvidence, ...] = (),
    egress: tuple[EgressEvidence, ...] = (),
    coverage: Coverage | None = None,
) -> EvidenceIndex:
    return EvidenceIndex(
        tool_calls=tool_calls,
        writes=writes,
        reported_reads=(),
        activated_skills=(),
        final_output=None,
        final_output_seq=None,
        exit_reason="completed",
        trace_complete=True,
        wall_clock_ms=None,
        total_tokens=None,
        coverage=coverage
        if coverage is not None
        else Coverage(
            harness_events=PlaneCoverage(fidelity="full"),
            filesystem_writes=PlaneCoverage(fidelity="overlay_diff"),
            egress=PlaneCoverage(fidelity="full"),
        ),
        skill_name="s",
        egress_requests=egress,
        context=NormalizationContext(workspace_root="/work"),
    )


# ---------------------------------------------------------------------------
# File write (persisted): B authoritative, A corroborating
# ---------------------------------------------------------------------------


def test_a_persisted_write_a_never_claimed_is_an_inconsistency() -> None:
    """B's positive observation is trustworthy even at overlay-diff — the file is really
    on disk — and Plane A at full fidelity supports the absence claim "A never said so"."""
    index = _index(
        writes=(WriteEvidence(seq=7, zone="workspace", path="${WORKSPACE}/x", deleted=False),)
    )
    (finding,) = trace_inconsistencies(index)
    assert finding.signal == "file_write_persisted"
    assert finding.subject == "${WORKSPACE}/x"
    assert finding.seq == 7
    assert "Plane B" in finding.reason and "Plane A" in finding.reason


def test_a_write_the_write_tool_claimed_is_consistent() -> None:
    index = _index(
        tool_calls=(_tool_call(1, "write", {"path": "report.md", "content": "x"}),),
        writes=(
            WriteEvidence(seq=7, zone="workspace", path="${WORKSPACE}/report.md", deleted=False),
        ),
    )
    assert trace_inconsistencies(index) == ()


def test_a_write_a_bash_command_mentions_is_consistent() -> None:
    """The claim test is generous on purpose: a path anywhere in any tool call's arguments
    — a shell redirect included — counts. A generous match can only suppress a finding,
    never fabricate one, the correct failure direction for a check `high` blocks on."""
    index = _index(
        tool_calls=(_tool_call(1, "bash", {"command": "echo hi > notes/out.txt"}),),
        writes=(
            WriteEvidence(
                seq=3, zone="workspace", path="${WORKSPACE}/notes/out.txt", deleted=False
            ),
        ),
    )
    assert trace_inconsistencies(index) == ()


def test_an_a_claim_without_b_evidence_is_never_a_finding() -> None:
    """The false positive §10.8 exists to prevent: at overlay-diff, Plane B legitimately
    misses transient files, so a Plane A write with no Plane B record is *expected*. A
    lower-fidelity plane may fail to corroborate; that is not a finding."""
    index = _index(tool_calls=(_tool_call(1, "write", {"path": "transient.tmp", "content": ""}),))
    assert trace_inconsistencies(index) == ()


def test_non_workspace_zones_and_deletes_are_out_of_the_row() -> None:
    """Harness-state and tmp writes are the harness's own machinery, and the shipped
    harness has no delete tool — neither has an A-side claim channel, so raising on them
    could only ever be a false positive."""
    index = _index(
        writes=(
            WriteEvidence(seq=1, zone="harness_state", path="${HOME}/.claude/log", deleted=False),
            WriteEvidence(seq=2, zone="tmp", path="/tmp/scratch", deleted=False),
            WriteEvidence(seq=3, zone="workspace", path="${WORKSPACE}/gone.txt", deleted=True),
        )
    )
    assert trace_inconsistencies(index) == ()


def test_an_unavailable_write_plane_disarms_the_row() -> None:
    """No Plane B, no comparison — a fidelity gap is never manufactured into a finding."""
    index = _index(
        writes=(WriteEvidence(seq=7, zone="workspace", path="${WORKSPACE}/x", deleted=False),),
        coverage=Coverage(
            harness_events=PlaneCoverage(fidelity="full"),
            filesystem_writes=PlaneCoverage(fidelity="unavailable", reason="no overlay"),
        ),
    )
    assert trace_inconsistencies(index) == ()


def test_a_partial_plane_a_cannot_support_the_absence_claim() -> None:
    """Both rows read an absence on Plane A ("A never claimed it"), so §10.8's stricter
    fidelity test applies to A: partial harness events could have missed the claim, and a
    claim possibly-missed must not be read as a claim never made."""
    index = _index(
        writes=(WriteEvidence(seq=7, zone="workspace", path="${WORKSPACE}/x", deleted=False),),
        egress=(EgressEvidence(seq=9, host="api.example.test", egress_class="skill_attributed"),),
        coverage=Coverage(
            harness_events=PlaneCoverage(fidelity="partial", reason="hook stream truncated"),
            filesystem_writes=PlaneCoverage(fidelity="overlay_diff"),
            egress=PlaneCoverage(fidelity="full"),
        ),
    )
    assert trace_inconsistencies(index) == ()


# ---------------------------------------------------------------------------
# Egress request: D authoritative, A corroborating
# ---------------------------------------------------------------------------


def test_skill_attributed_egress_a_never_mentioned_is_an_inconsistency() -> None:
    index = _index(
        egress=(
            EgressEvidence(seq=11, host="exfil.attacker.example", egress_class="skill_attributed"),
        )
    )
    (finding,) = trace_inconsistencies(index)
    assert finding.signal == "egress_request"
    assert finding.subject == "exfil.attacker.example"
    assert "Plane D" in finding.reason and "Plane A" in finding.reason


def test_egress_a_fetch_call_mentions_is_consistent() -> None:
    index = _index(
        tool_calls=(_tool_call(1, "fetch", {"url": "https://api.example.test/v1/data"}),),
        egress=(EgressEvidence(seq=11, host="api.example.test", egress_class="skill_attributed"),),
    )
    assert trace_inconsistencies(index) == ()


def test_harness_traffic_is_never_compared_against_a() -> None:
    """Model-API and harness-infrastructure flows have no Plane A claim by construction —
    the harness makes them, not the skill — so they are out of the row's domain entirely."""
    index = _index(
        egress=(
            EgressEvidence(seq=1, host="api.anthropic.com", egress_class="model_api"),
            EgressEvidence(
                seq=2, host="telemetry.harness.example", egress_class="harness_infrastructure"
            ),
        )
    )
    assert trace_inconsistencies(index) == ()


def test_an_unobserved_egress_plane_disarms_the_row() -> None:
    index = _index(
        egress=(EgressEvidence(seq=11, host="x.example", egress_class="skill_attributed"),),
        coverage=Coverage(
            harness_events=PlaneCoverage(fidelity="full"),
            egress=PlaneCoverage(fidelity="unavailable", reason="no proxy wired"),
        ),
    )
    assert trace_inconsistencies(index) == ()


def test_the_report_shows_disagreements_only_where_any_exist() -> None:
    """The section is rendered from `security.runtime` when findings exist, labelled
    advisory (the disposition is not scored in this version) — and is absent entirely on a
    consistent run, because an empty "no inconsistencies" section would imply every §10.8
    row was comparable when several never are."""
    from bellwether.report import SecuritySummary, render_html_report, render_pr_comment
    from tests.test_report import make_figures, make_summary

    clean = make_summary()
    assert "Cross-plane disagreements" not in render_pr_comment(clean, make_figures())
    assert "Cross-plane disagreements" not in render_html_report(clean, make_figures())

    reason = "Plane B shows a persisted workspace write at ${WORKSPACE}/x that no Plane A tool call claimed"
    inconsistent = clean.model_copy(
        update={"security": SecuritySummary(runtime={"trace_inconsistency": [reason]})}
    )
    comment = render_pr_comment(inconsistent, make_figures())
    assert "Cross-plane disagreements (§10.8)" in comment
    assert reason in comment
    assert "not scored into the verdict" in comment
    html = render_html_report(inconsistent, make_figures())
    assert "Cross-plane disagreements (§10.8)" in html
    assert "not scored into the verdict" in html


def test_findings_are_deterministically_ordered() -> None:
    """§24: sorted by (signal, subject, seq), whatever order the planes were indexed in."""
    index = _index(
        writes=(
            WriteEvidence(seq=9, zone="workspace", path="${WORKSPACE}/zz", deleted=False),
            WriteEvidence(seq=2, zone="workspace", path="${WORKSPACE}/aa", deleted=False),
        ),
        egress=(EgressEvidence(seq=5, host="b.example", egress_class="skill_attributed"),),
    )
    findings = trace_inconsistencies(index)
    assert [f.subject for f in findings] == ["b.example", "${WORKSPACE}/aa", "${WORKSPACE}/zz"]
