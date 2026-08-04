"""Policy evaluation and the release verdict (§16).

Responsibility
    Gate evaluation — **per target, taking the worst result** — the ``ready`` /
    ``conditional`` / ``not_ready`` computation of §16.2, and the §16.4 precondition
    check that refuses unsatisfiable policy/target combinations before any run executes.

MUST NOT
    Compute metrics. It consumes them.

Built by WP-11. Rules that are easy to lose: ``not_evaluable`` on a required gate blocks
and carries the coverage reason; a ``stale`` review attestation is ``not_evaluable``; a
``descriptive_only`` evaluation can never be ``ready``. ``mypy --strict`` from the first
commit.
"""

from __future__ import annotations

__all__: list[str] = []
