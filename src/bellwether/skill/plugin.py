"""Locating skills inside an Agent Plugin bundle (agent-plugins.org, spec 1.0.0).

An *Agent Plugin* is a directory with a ``plugin.json`` manifest at its root; the skills
it carries live one per immediate child directory of ``skills/``, each in exactly the
format :func:`bellwether.skill.package.load_skill` already reads. Bellwether's unit of
evaluation stays the skill — a plugin is a container of skills, not a new kind of
evaluated thing — so this module only locates and describes: it finds the manifest,
enumerates the skill directories, and records what else the bundle carries (an
``mcp.json`` declaring MCP servers) so a run can say what it did *not* evaluate.

Manifest validation is lenient on the same reasoning as frontmatter parsing: a plugin is
attacker-authored in external mode, and a manifest defect must become a reported problem
on the skills it ships, never a way to dodge evaluation entirely. Only the two states
where there is nothing to work with — no directory, no ``plugin.json`` — raise.

Like the rest of the skill layer, everything here is static. A plugin is read, never
executed; in particular its MCP servers are never started.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from bellwether.errors import SkillError

# Same-package private reuse: the manifest is attacker-authored in external mode, so it
# gets the same bounded-read treatment as SKILL.md (a loader OOM aborts the evaluation
# before any sandbox exists).
from bellwether.skill.package import SKILL_FILE, _read_text_bounded

__all__ = [
    "PLUGIN_MANIFEST",
    "PLUGIN_MCP_FILE",
    "PLUGIN_SKILLS_DIR",
    "PluginBundle",
    "is_plugin_root",
    "load_plugin",
    "plugin_skill_dirs",
]

PLUGIN_MANIFEST = "plugin.json"
PLUGIN_SKILLS_DIR = "skills"
PLUGIN_MCP_FILE = "mcp.json"

#: The spec's name rule: 1–64 characters, lowercase letters, digits, hyphens, periods.
#: A name that fails it is reported and the directory name used instead — the declared
#: name is what the plugin claims to be, never the thing that builds a message a human
#: has to read unescaped.
_PLUGIN_NAME = re.compile(r"^[a-z0-9.-]{1,64}$")

#: Every 1.0.0-era schema identifier starts with this. Matching the prefix rather than
#: one exact URL keeps a future spec revision a reported observation, not a refusal.
_PLUGIN_SCHEMA_PREFIX = "https://agent-plugins.org/schemas/"


@dataclass(frozen=True)
class PluginBundle:
    """A located Agent Plugin: where it is, what it declares, which skills it carries."""

    root: Path
    #: The manifest's declared ``name`` where it is present and well-formed, else the
    #: directory name.
    name: str
    #: The skill directories under ``skills/``, sorted by directory name (§24 — the
    #: enumeration order must not depend on the filesystem). Each is a directory
    #: ``load_skill`` accepts as-is.
    skill_dirs: tuple[Path, ...]
    #: Whether the bundle carries an ``mcp.json``. MCP servers are executable behaviour
    #: this version does not stand up or observe; the caller must report that, because a
    #: silently ignored component reads as a clean one.
    has_mcp_servers: bool
    #: Non-fatal observations about the bundle itself, phrased for the report. These are
    #: about the *container*; each skill's own problems come from ``load_skill``.
    problems: tuple[str, ...] = ()


def is_plugin_root(path: Path) -> bool:
    """Whether ``path`` is an Agent Plugin root: a directory holding a ``plugin.json``."""
    return (path / PLUGIN_MANIFEST).is_file()


def plugin_skill_dirs(root: Path) -> tuple[Path, ...]:
    """The skill directories inside a plugin, per the spec's discovery rule.

    Each immediate child directory of ``skills/`` containing a ``SKILL.md`` regular file
    is one skill; anything else under ``skills/`` (a loose file, a directory without a
    ``SKILL.md``) is not. A missing ``skills/`` is an empty result, not an error — the
    spec makes every component location optional. Sorted by name so the run order is a
    property of the bundle, not of the filesystem.
    """
    skills_root = root / PLUGIN_SKILLS_DIR
    if not skills_root.is_dir():
        return ()
    return tuple(
        sorted(
            (
                child
                for child in skills_root.iterdir()
                if child.is_dir() and (child / SKILL_FILE).is_file()
            ),
            key=lambda child: child.name,
        )
    )


def load_plugin(root: Path) -> PluginBundle:
    """Read an Agent Plugin bundle from ``root``.

    Raises :class:`SkillError` only when there is no bundle to read — ``root`` is not a
    directory, or holds no ``plugin.json``. Every defect *inside* the bundle (a manifest
    that does not parse, a name that breaks the spec's rule, a ``skills`` entry of the
    wrong filesystem kind) is reported in :attr:`PluginBundle.problems` and attributed to
    the skills the caller loads from it.
    """
    if not root.is_dir():
        raise SkillError(f"{root} is not a directory")
    manifest_file = root / PLUGIN_MANIFEST
    if not manifest_file.is_file():
        raise SkillError(
            f"{root} has no {PLUGIN_MANIFEST}; an Agent Plugin is a directory containing one"
        )

    problems: list[str] = []
    data = _read_manifest(manifest_file, problems)
    name = _declared_name(data, fallback=root.name, problems=problems)
    _check_schema(data, problems)

    skills_root = root / PLUGIN_SKILLS_DIR
    if skills_root.exists() and not skills_root.is_dir():
        # The spec's rule for a wrong filesystem kind: that component is invalid, the
        # rest of the bundle still loads. Zero skills from a bundle that *looks* like it
        # ships some must be said out loud, not returned as a quiet empty tuple.
        problems.append(
            f"'{PLUGIN_SKILLS_DIR}' exists but is not a directory, so no skills load "
            "from this plugin"
        )

    return PluginBundle(
        root=root,
        name=name,
        skill_dirs=plugin_skill_dirs(root),
        has_mcp_servers=(root / PLUGIN_MCP_FILE).is_file(),
        problems=tuple(problems),
    )


def _read_manifest(manifest_file: Path, problems: list[str]) -> dict[str, object]:
    """Parse ``plugin.json`` leniently: a defect is a problem, not an escape hatch."""
    try:
        loaded = json.loads(_read_text_bounded(manifest_file, label=PLUGIN_MANIFEST))
    except SkillError:
        # The bounded-read refusal (a multi-gigabyte manifest) is the loader protecting
        # itself, and stands.
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        problems.append(f"{PLUGIN_MANIFEST} could not be parsed: {exc}")
        return {}
    if not isinstance(loaded, dict):
        problems.append(f"{PLUGIN_MANIFEST} must be a JSON object, not a {type(loaded).__name__}")
        return {}
    return loaded


def _declared_name(data: dict[str, object], *, fallback: str, problems: list[str]) -> str:
    declared = data.get("name")
    if isinstance(declared, str) and _PLUGIN_NAME.fullmatch(declared):
        return declared
    if declared is None and "name" not in data:
        if data:
            problems.append(
                f"{PLUGIN_MANIFEST} has no 'name', which the spec requires; the "
                f"directory name {fallback!r} is used instead"
            )
    else:
        problems.append(
            f"declared plugin name {declared!r} does not match the spec's name rule "
            "(1-64 characters: lowercase letters, digits, hyphens, periods); the "
            f"directory name {fallback!r} is used instead"
        )
    return fallback


def _check_schema(data: dict[str, object], problems: list[str]) -> None:
    if not data:
        return  # the manifest already failed to parse; one problem is enough
    schema = data.get("$schema")
    if not isinstance(schema, str) or not schema.startswith(_PLUGIN_SCHEMA_PREFIX):
        problems.append(
            f"{PLUGIN_MANIFEST} does not declare a recognised '$schema' (the spec "
            f"requires an identifier under {_PLUGIN_SCHEMA_PREFIX})"
        )
