"""WP-12: the report layer (§17.2, §13.8, §17.4).

The done-when has two halves: ``summary.json`` validates against its schema, and a
golden-trace run produces byte-identical output across two invocations. Both are asserted
directly. The rest of the file guards the presentation rules with teeth — the BCI never
rendered alone, the "consistently failing" annotation, every figure carrying its
``n_evaluable`` and look, and the §2 limitations footer rendered whole.
"""

from __future__ import annotations

import json
from pathlib import Path

from bellwether.constants import REPORT_LIMITATIONS
from bellwether.report import (
    CapabilityProfileSummary,
    CapabilityRow,
    ConsistencySummary,
    Figures,
    FunctionalSummary,
    GateSummary,
    MatrixSummary,
    PolicyRef,
    ScopeRow,
    SecuritySummary,
    SkillRef,
    StripRow,
    Summary,
    TrajectoryCluster,
    VerdictSummary,
    default_limitations,
    render_capability_heatmap,
    render_pr_comment,
    render_strip_chart,
    render_summary_json,
    render_trajectory_clusters,
    summary_json_schema,
)

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / (
    "src/bellwether/report/schemas/summary.schema.json"
)


def make_summary(*, pass_rate: float = 0.8636363636, bci: float = 78.0) -> Summary:
    """A representative summary — the fixed input behind the golden-output assertions."""
    return Summary(
        eval_id="ev_golden",
        created_at="2026-08-05T00:00:00Z",
        bellwether_version="0.1.0",
        skill=SkillRef(
            name="security-review",
            package_digest="sha256:aa",
            payload_digest="sha256:bb",
            criticality="high",
        ),
        policy=PolicyRef(profile="high", digest="sha256:cc"),
        matrix=MatrixSummary(
            scenarios=2,
            targets=2,
            runs_planned=24,
            runs_completed=24,
            runs_evaluable=22,
            looks=(6, 12, 20),
            boundary_z=2.289,
            sets_stopped_at_look={"1": 3, "2": 1},
            sets_held_open_for_capability=1,
        ),
        verdict=VerdictSummary(
            status="conditional",
            gates=(
                GateSummary(
                    name="functional",
                    status="pass",
                    observed="0.76",
                    threshold="0.7",
                    reason="frontier: lower bound clears",
                ),
                GateSummary(
                    name="consistency",
                    status="warn",
                    observed="78",
                    threshold="85",
                    reason="small: bci 78",
                ),
            ),
        ),
        functional=FunctionalSummary(
            pass_rate=pass_rate,
            n_evaluable=22,
            lower_bound=0.76,
            threshold=0.7,
            decision="pass",
            ci_boundary=(0.76, 0.93),
            stopped_at_look=2,
        ),
        consistency=ConsistencySummary(
            bci=bci,
            pass_rate=pass_rate,
            components={"outcome": 0.86, "capability": 0.81},
            capability_jaccard_weighted=0.81,
            capability_jaccard_plain=0.94,
        ),
        capability_profile=CapabilityProfileSummary(
            tier1={"core": ["workspace_read"], "peripheral": []}
        ),
        security=SecuritySummary(),
        limitations=default_limitations(),
    )


def make_figures() -> Figures:
    return Figures(
        strip=(
            StripRow(
                label="scan/frontier",
                cells=("pass", "pass", "pass", "fail", "timeout", "pass"),
                n_evaluable=6,
                look_boundaries=(6,),
                stopped_at_look=1,
                lower_bound=0.44,
            ),
            StripRow(
                label="scan/small",
                cells=("pass", "not_evaluable", "excluded_quality", "fail"),
                n_evaluable=3,
                stopped_at_look=1,
                lower_bound=0.20,
            ),
        ),
        clusters=(
            TrajectoryCluster("c1", 4, ("read", "grep", "write"), 0.05),
            TrajectoryCluster("c2", 2, ("read", "bash"), 0.10),
        ),
        heatmap=(
            CapabilityRow("egress", "api.example.com", (False, True, False), high_risk=True),
            CapabilityRow("workspace_read", "src/app.py", (True, True, True)),
            CapabilityRow("workspace_read", "README.md", (True, False, True)),
        ),
        run_labels=("r1", "r2", "r3"),
        declared_vs_observed=(
            ScopeRow("workspace_read", declared=True, observed=True, disposition="in scope"),
            ScopeRow("egress", declared=False, observed=True, disposition="exceeded"),
        ),
    )


# ---------------------------------------------------------------------------
# The done-when: schema validation + byte-identical output
# ---------------------------------------------------------------------------


def test_summary_renders_byte_identical_across_two_invocations() -> None:
    summary = make_summary()
    assert render_summary_json(summary) == render_summary_json(summary)


def test_summary_round_trips_through_its_schema() -> None:
    """Re-parsing the rendered JSON through the model is validation against the schema:
    an extra or mistyped key would raise here."""
    rendered = render_summary_json(make_summary())
    reparsed = Summary.model_validate(json.loads(rendered))
    assert render_summary_json(reparsed) == rendered


def test_committed_schema_matches_the_model() -> None:
    """The shipped JSON Schema must not drift from what the model actually emits."""
    from bellwether.determinism import canonical_json

    on_disk = _SCHEMA_PATH.read_text(encoding="utf-8")
    regenerated = canonical_json(summary_json_schema(), indent=2) + "\n"
    assert on_disk == regenerated, "run the schema generator; summary.schema.json is stale"


def test_summary_carries_the_schema_version() -> None:
    data = json.loads(render_summary_json(make_summary()))
    assert data["schema_version"] == "1.0"


def test_pr_comment_renders_byte_identical_across_two_invocations() -> None:
    summary, figures = make_summary(), make_figures()
    assert render_pr_comment(summary, figures) == render_pr_comment(summary, figures)


# ---------------------------------------------------------------------------
# Presentation rules with teeth
# ---------------------------------------------------------------------------


def test_bci_is_never_rendered_without_the_pass_rate() -> None:
    """§13.3: a BCI with no pass rate beside it reads as quality; forbid it."""
    comment = render_pr_comment(make_summary(), make_figures())
    for line in comment.splitlines():
        if "BCI" in line:
            assert "pass rate" in line, f"BCI line lacks the pass rate: {line!r}"


def test_a_consistently_failing_skill_is_annotated() -> None:
    """§13.7: p̂ < 0.5 means the BCI measures the stability of failure — say so."""
    failing = make_summary(pass_rate=0.2, bci=95.0)
    comment = render_pr_comment(failing, make_figures())
    assert "consistently failing" in comment


def test_a_healthy_pass_rate_carries_no_failing_annotation() -> None:
    comment = render_pr_comment(make_summary(pass_rate=0.86), make_figures())
    assert "consistently failing" not in comment


def test_the_limitations_footer_is_rendered_whole() -> None:
    """§2: the footer is non-negotiable and complete — every limitation, verbatim."""
    comment = render_pr_comment(make_summary(), make_figures())
    for limitation in REPORT_LIMITATIONS:
        assert limitation in comment


def test_the_strip_chart_marks_look_boundaries_and_carries_n_and_look() -> None:
    chart = render_strip_chart(make_figures().strip)
    assert "|" in chart  # a look boundary is drawn
    assert "n=6" in chart
    assert "stopped at look 1" in chart
    assert "LB 0.44" in chart


def test_a_timeout_is_not_drawn_like_an_assertion_failure() -> None:
    """§17.4: how a run failed is evidence; a timeout glyph must differ from a fail glyph."""
    from bellwether.report import STRIP_GLYPHS

    assert STRIP_GLYPHS["timeout"] != STRIP_GLYPHS["fail"]
    chart = render_strip_chart(make_figures().strip)
    assert STRIP_GLYPHS["timeout"] in chart


def test_the_heatmap_groups_tier3_under_tier1_and_flags_high_risk() -> None:
    figures = make_figures()
    heatmap = render_capability_heatmap(figures.heatmap, figures.run_labels)
    assert "egress/" in heatmap  # tier-1 group header
    assert "workspace_read/" in heatmap
    assert "!" in heatmap  # the high-risk egress capability is marked


def test_the_heatmap_row_order_is_independent_of_input_order() -> None:
    """Determinism: shuffling the rows must not change the rendered grid."""
    figures = make_figures()
    shuffled = tuple(reversed(figures.heatmap))
    a = render_capability_heatmap(figures.heatmap, figures.run_labels)
    b = render_capability_heatmap(shuffled, figures.run_labels)
    assert a == b


def test_trajectory_clusters_are_ordered_largest_first() -> None:
    clusters = (
        TrajectoryCluster("small", 1, ("read",), 0.0),
        TrajectoryCluster("big", 9, ("read", "write"), 0.02),
    )
    rendered = render_trajectory_clusters(clusters)
    assert rendered.index("big") < rendered.index("small")


def test_empty_figures_degrade_without_raising() -> None:
    assert "No repetition sets" in render_strip_chart(())
    assert "No trajectory clusters" in render_trajectory_clusters(())
    assert "No capabilities observed" in render_capability_heatmap((), ())


def test_descriptive_only_ceiling_is_surfaced() -> None:
    summary = make_summary()
    descriptive = summary.model_copy(
        update={"matrix": summary.matrix.model_copy(update={"descriptive_only": True})}
    )
    comment = render_pr_comment(descriptive, make_figures())
    assert "descriptive_only" in comment
