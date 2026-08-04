"""Bellwether — a CI/CD harness for AI agent skills.

Bellwether executes a candidate skill many times, across multiple models and vendors,
inside an instrumented sandbox; captures a deterministic record of everything the agent
actually did; measures how much that behaviour varies between runs; and renders a
release verdict against a policy the repository owner controls.

It warns; it does not vouch. See ``docs/spec.md`` §2 for the limitations that MUST
accompany every report, and §16.3 for the verdict vocabulary.

Module boundaries are defined in spec §8.1 and enforced by ``.importlinter``.
"""

from __future__ import annotations

__all__ = ["ARF_VERSION", "CANON_VERSION", "SUMMARY_SCHEMA_VERSION", "__version__"]

__version__ = "0.1.0.dev0"

#: Version of the Agent Run Format trace schema (§11.1).
ARF_VERSION = "1.0"

#: Schema version of ``summary.json`` (§17.2).
SUMMARY_SCHEMA_VERSION = "1.0"

#: Canonicalization version recorded in every trace's ``canon`` block (§11.4, §11.6).
#: Bump this whenever normalization, epoch anchoring, or the trajectory planes change;
#: traces canonicalized under different versions are not comparable.
CANON_VERSION = "1.0"
