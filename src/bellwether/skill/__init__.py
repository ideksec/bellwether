"""Skill package parsing: frontmatter, digests, file inventory (§6.1–6.3).

Responsibility
    Parse a skill directory, preserve unknown frontmatter fields rather than dropping
    them, compute the three load-bearing digests over a **sorted** file walk
    (``package_digest``, ``payload_digest``, ``description_digest``), estimate tokens,
    and inventory executables with interpreter detection.

MUST NOT
    Execute anything. Reading a skill is a static operation; a skill that runs during
    parsing has already defeated the sandbox.

Built by WP-2. Digests MUST be byte-reproducible across machines and filesystem
orderings — use :mod:`bellwether.determinism`.
"""

from __future__ import annotations

__all__: list[str] = []
