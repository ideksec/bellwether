"""Skill package parsing: frontmatter, digests, file inventory (§6.1–6.3).

Responsibility
    Parse a skill directory, preserve unknown frontmatter fields rather than dropping
    them, compute the three load-bearing digests over a **sorted** file walk
    (``package_digest``, ``payload_digest``, ``description_digest``), estimate tokens,
    and inventory executables with interpreter detection. Locate skills packaged inside
    an Agent Plugin bundle (agent-plugins.org) — a plugin is a container of skills, and
    each of its skills loads through the same ``load_skill``.

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
    has_unusual_path_characters,
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
from bellwether.skill.plugin import (
    PLUGIN_MANIFEST,
    PLUGIN_MCP_FILE,
    PLUGIN_SKILLS_DIR,
    PluginBundle,
    is_plugin_root,
    load_plugin,
    plugin_skill_dirs,
)

__all__ = [
    "DEFAULT_PAYLOAD_ALLOWLIST",
    "DIGEST_FORMAT",
    "EVALS_DIR",
    "PLUGIN_MANIFEST",
    "PLUGIN_MCP_FILE",
    "PLUGIN_SKILLS_DIR",
    "SKILL_FILE",
    "Executable",
    "FileRecord",
    "Frontmatter",
    "ParsedSkillMarkdown",
    "PayloadAllowlist",
    "PayloadSplit",
    "PluginBundle",
    "ReviewState",
    "SkillPackage",
    "description_digest",
    "detect_interpreter",
    "estimate_tokens",
    "has_unusual_path_characters",
    "is_plugin_root",
    "load_plugin",
    "load_skill",
    "merkle_digest",
    "normalize_description",
    "parse_skill_markdown",
    "plugin_skill_dirs",
    "read_file_records",
]
