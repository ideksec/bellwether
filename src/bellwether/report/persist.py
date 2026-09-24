"""Persisting the report figures so a stored tree can be re-rendered (§17.1, §20).

The renderers take a :class:`Summary` and a :class:`Figures`. The summary is already the
machine-readable ``summary.json``; the figures were computed from the readings and then
thrown away, which is why ``bellwether report <EVAL_ID>`` could not re-render a stored tree.
This module gives the figures a file — ``metrics/figures.json`` — as canonical JSON, and
reads it back into the same dataclasses, so a re-render is a pure function of the tree.

The file is versioned separately from ``summary.json``: it is a rendering input, not a
downstream contract, and its shape follows the figure dataclasses rather than §17.2.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from bellwether.determinism import canonical_json
from bellwether.errors import BellwetherError
from bellwether.report.figures import CapabilityRow, StripRow, TrajectoryCluster
from bellwether.report.markdown import Figures, ScopeRow

__all__ = ["FIGURES_VERSION", "figures_from_json", "render_figures_json"]

#: Bumped on any change to the figure dataclasses' persisted shape.
FIGURES_VERSION = "1"


def render_figures_json(figures: Figures) -> str:
    """Serialise the figures as canonical JSON (sorted keys, floats rounded once)."""
    payload: dict[str, Any] = {
        "figures_version": FIGURES_VERSION,
        "strip": [
            {
                "label": row.label,
                "cells": list(row.cells),
                "n_evaluable": row.n_evaluable,
                "look_boundaries": list(row.look_boundaries),
                "stopped_at_look": row.stopped_at_look,
                "lower_bound": row.lower_bound,
            }
            for row in figures.strip
        ],
        "clusters": [
            {
                "cluster_id": cluster.cluster_id,
                "run_count": cluster.run_count,
                "representative": list(cluster.representative),
                "mean_intra_distance": cluster.mean_intra_distance,
            }
            for cluster in figures.clusters
        ],
        "heatmap": [
            {
                "tier1_class": row.tier1_class,
                "capability": row.capability,
                "exercised": list(row.exercised),
                "high_risk": row.high_risk,
            }
            for row in figures.heatmap
        ],
        "run_labels": list(figures.run_labels),
        "declared_vs_observed": [
            {
                "capability": row.capability,
                "declared": row.declared,
                "observed": row.observed,
                "disposition": row.disposition,
            }
            for row in figures.declared_vs_observed
        ],
        "scope_declared": figures.scope_declared,
    }
    return canonical_json(payload, indent=2) + "\n"


def _optional_bool(value: object) -> bool | None:
    """``scope_declared`` as written, or None for an artifact that predates it."""
    return value if isinstance(value, bool) else None


def figures_from_json(text: str, *, where: str = "figures.json") -> Figures:
    """Parse ``metrics/figures.json`` back into :class:`Figures`, or refuse naming why."""
    import json

    try:
        payload = json.loads(text)
    except ValueError as error:
        raise BellwetherError(f"{where}: not valid JSON: {error}") from None
    if not isinstance(payload, dict):
        raise BellwetherError(f"{where}: expected an object at the top level")
    version = payload.get("figures_version")
    if version != FIGURES_VERSION:
        raise BellwetherError(
            f"{where}: figures_version {version!r} is not the {FIGURES_VERSION!r} this build "
            "renders; the tree was written by another build and cannot be re-rendered by this one"
        )
    try:
        return Figures(
            strip=tuple(
                StripRow(
                    label=str(row["label"]),
                    cells=tuple(row["cells"]),
                    n_evaluable=int(row["n_evaluable"]),
                    look_boundaries=tuple(int(b) for b in row.get("look_boundaries", [])),
                    stopped_at_look=row.get("stopped_at_look"),
                    lower_bound=row.get("lower_bound"),
                )
                for row in payload.get("strip", [])
            ),
            clusters=tuple(
                TrajectoryCluster(
                    cluster_id=str(cluster["cluster_id"]),
                    run_count=int(cluster["run_count"]),
                    representative=tuple(str(s) for s in cluster.get("representative", [])),
                    mean_intra_distance=float(cluster["mean_intra_distance"]),
                )
                for cluster in payload.get("clusters", [])
            ),
            heatmap=tuple(
                CapabilityRow(
                    tier1_class=str(row["tier1_class"]),
                    capability=str(row["capability"]),
                    exercised=tuple(bool(x) for x in row.get("exercised", [])),
                    high_risk=bool(row.get("high_risk", False)),
                )
                for row in payload.get("heatmap", [])
            ),
            run_labels=tuple(str(label) for label in payload.get("run_labels", [])),
            declared_vs_observed=tuple(
                ScopeRow(
                    capability=str(row["capability"]),
                    declared=bool(row["declared"]),
                    observed=bool(row["observed"]),
                    disposition=str(row["disposition"]),
                )
                for row in payload.get("declared_vs_observed", [])
            ),
            scope_declared=_optional_bool(payload.get("scope_declared")),
        )
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        raise BellwetherError(f"{where}: malformed figures record: {error!r}") from None
