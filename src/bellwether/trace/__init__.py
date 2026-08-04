"""ARF: the Agent Run Format trace schema, normalization and merge (§11).

Responsibility
    ``run_header`` / ``action`` / ``run_footer`` models, the JSONL writer and reader,
    incomplete-trace detection (no footer implies ``not_evaluable``), path
    normalisation, the three capability tiers, platform-baseline subtraction, and
    **epoch anchoring** (§11.5) — the cross-plane ordering rule.

MUST NOT
    Do analysis. Metrics live in :mod:`bellwether.metrics`.

Built by WP-3 and WP-7. Never merge planes by wall-clock sort: within an epoch, order by
``(plane_priority, kind, normalized_target, stable_hash)``. WP-7 is the package most
likely to be got subtly wrong, and WP-19's noise floor is the only test that proves it.
``mypy --strict`` from the first commit.
"""

from __future__ import annotations

__all__: list[str] = []
