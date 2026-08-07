"""All output rendering: markdown, JSON, SARIF, HTML (§17).

Responsibility
    The artifact tree of §17.1, the schema-versioned ``summary.json`` of §17.2, the two
    findings containers of §17.3, the static HTML report with hand-rolled inline SVG,
    and the PR comment of §18.2.

MUST NOT
    Compute anything. Everything rendered here was decided upstream.

Built by WP-12. Presentation rules with teeth: the BCI is never rendered without the
pass rate adjacent; every figure carries ``n_evaluable`` and the look it came from; a
"consistently failing" annotation appears wherever the pass rate is below 0.5; and the
footer carries the §2 limitations verbatim. The §16.3 language lint applies to every
template in this package.

WP-12 ships ``summary.json`` (:mod:`.summary`), the three text figures (:mod:`.figures`),
and the Markdown PR comment (:mod:`.markdown`). The findings containers, the artifact
tree, and the static HTML report follow in later packages.
"""

from __future__ import annotations

from bellwether.report.figures import (
    STRIP_GLYPHS,
    CapabilityRow,
    StripCell,
    StripRow,
    TrajectoryCluster,
    render_capability_heatmap,
    render_strip_chart,
    render_trajectory_clusters,
)
from bellwether.report.html import render_html_report
from bellwether.report.markdown import Figures, ScopeRow, render_pr_comment
from bellwether.report.summary import (
    SCHEMA_VERSION,
    CapabilityProfileSummary,
    ComponentExclusion,
    ConsistencySummary,
    CostSummary,
    CrossModelSummary,
    FunctionalSummary,
    GateSummary,
    MatrixSummary,
    NoiseFloor,
    PolicyRef,
    RegressionSummary,
    SecuritySummary,
    SkillRef,
    Summary,
    VerdictSummary,
    default_limitations,
    render_summary_json,
    summary_json_schema,
)

__all__ = [
    "SCHEMA_VERSION",
    "STRIP_GLYPHS",
    "CapabilityProfileSummary",
    "CapabilityRow",
    "ComponentExclusion",
    "ConsistencySummary",
    "CostSummary",
    "CrossModelSummary",
    "Figures",
    "FunctionalSummary",
    "GateSummary",
    "MatrixSummary",
    "NoiseFloor",
    "PolicyRef",
    "RegressionSummary",
    "ScopeRow",
    "SecuritySummary",
    "SkillRef",
    "StripCell",
    "StripRow",
    "Summary",
    "TrajectoryCluster",
    "VerdictSummary",
    "default_limitations",
    "render_capability_heatmap",
    "render_html_report",
    "render_pr_comment",
    "render_strip_chart",
    "render_summary_json",
    "render_trajectory_clusters",
    "summary_json_schema",
]
