"""Skill package parsing: frontmatter, digests, file inventory (§6.1–6.3).

Responsibility
    Parse a skill directory, preserve unknown frontmatter fields rather than dropping
    them, compute the three load-bearing digests over a **sorted** file walk
    (``package_digest``, ``payload_digest``, ``description_digest``), estimate tokens,
    and inventory executables with interpreter detection.

MUST NOT
    Execute anything. Reading a skill is a static operation; a skill that runs during
    parsing has already defeated the sandbox.

Built by WP-2. Digests are byte-reproducible across machines and filesystem orderings —
see :mod:`bellwether.determinism`.
"""

from __future__ import annotations

from bellwether.skill.digests import (
    DIGEST_FORMAT,
    FileRecord,
    description_digest,
    merkle_digest,
    read_file_records,
)
from bellwether.skill.frontmatter import (
    Frontmatter,
    ParsedSkillMarkdown,
    normalize_description,
    parse_skill_markdown,
)
from bellwether.skill.inventory import Executable, detect_interpreter, estimate_tokens
from bellwether.skill.package import SKILL_FILE, ReviewState, SkillPackage, load_skill
from bellwether.skill.payload import (
    DEFAULT_PAYLOAD_ALLOWLIST,
    EVALS_DIR,
    PayloadAllowlist,
    PayloadSplit,
)

__all__ = [
    "DEFAULT_PAYLOAD_ALLOWLIST",
    "DIGEST_FORMAT",
    "EVALS_DIR",
    "SKILL_FILE",
    "Executable",
    "FileRecord",
    "Frontmatter",
    "ParsedSkillMarkdown",
    "PayloadAllowlist",
    "PayloadSplit",
    "ReviewState",
    "SkillPackage",
    "description_digest",
    "detect_interpreter",
    "estimate_tokens",
    "load_skill",
    "merkle_digest",
    "normalize_description",
    "parse_skill_markdown",
    "read_file_records",
]
