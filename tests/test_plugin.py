"""Locating skills inside an Agent Plugin bundle (agent-plugins.org, spec 1.0.0).

The properties that matter: the spec's discovery rule is followed exactly (each immediate
child of ``skills/`` with a ``SKILL.md`` is one skill, nothing else is); a manifest defect
becomes a reported problem, never a way to dodge evaluation; and what the bundle carries
beyond skills (``mcp.json``) is recorded so the caller can say it was not evaluated.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bellwether.errors import SkillError
from bellwether.skill import (
    is_plugin_root,
    load_plugin,
    load_skill,
    plugin_skill_dirs,
)

MANIFEST = {
    "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
    "name": "deployment.tools",
}


def _make_plugin(root: Path, *, manifest: object = None, skills: tuple[str, ...] = ()) -> Path:
    plugin = root / "my-plugin"
    plugin.mkdir(parents=True, exist_ok=True)
    body = manifest if manifest is not None else MANIFEST
    (plugin / "plugin.json").write_text(
        body if isinstance(body, str) else json.dumps(body), encoding="utf-8"
    )
    for name in skills:
        skill = plugin / "skills" / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: d\n---\nbody\n", encoding="utf-8"
        )
    return plugin


def test_a_wellformed_plugin_loads_with_its_skills_sorted(tmp_path: Path) -> None:
    plugin = _make_plugin(tmp_path, skills=("zeta", "alpha", "mid"))
    bundle = load_plugin(plugin)
    assert bundle.name == "deployment.tools"
    assert bundle.problems == ()
    assert not bundle.has_mcp_servers
    assert [d.name for d in bundle.skill_dirs] == ["alpha", "mid", "zeta"]


def test_each_plugin_skill_loads_through_load_skill_unchanged(tmp_path: Path) -> None:
    """The unit of evaluation stays the skill: a plugin-nested skill directory is exactly
    the directory ``load_skill`` already reads — no new format, no adapter between them."""
    plugin = _make_plugin(tmp_path, skills=("alpha",))
    (bundle,) = [load_plugin(plugin)]
    package = load_skill(bundle.skill_dirs[0])
    assert package.name == "alpha"


def test_is_plugin_root(tmp_path: Path) -> None:
    plugin = _make_plugin(tmp_path)
    assert is_plugin_root(plugin)
    assert not is_plugin_root(tmp_path)
    assert not is_plugin_root(tmp_path / "does-not-exist")


def test_no_directory_or_no_manifest_raises(tmp_path: Path) -> None:
    """Only the two nothing-to-read states raise; everything inside a bundle is lenient."""
    with pytest.raises(SkillError, match="not a directory"):
        load_plugin(tmp_path / "missing")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(SkillError, match=r"plugin\.json"):
        load_plugin(empty)


def test_a_manifest_that_does_not_parse_is_a_problem_not_an_escape(tmp_path: Path) -> None:
    """A hostile or broken plugin.json must not stop the skills it ships from being
    evaluated — a parse failure that aborted the load would let a bundle dodge the gate."""
    plugin = _make_plugin(tmp_path, manifest="{not json", skills=("alpha",))
    bundle = load_plugin(plugin)
    assert bundle.name == "my-plugin"
    assert [d.name for d in bundle.skill_dirs] == ["alpha"]
    assert any("could not be parsed" in problem for problem in bundle.problems)


def test_a_non_object_manifest_is_a_problem(tmp_path: Path) -> None:
    plugin = _make_plugin(tmp_path, manifest='["a", "list"]', skills=("alpha",))
    bundle = load_plugin(plugin)
    assert any("must be a JSON object" in problem for problem in bundle.problems)
    assert [d.name for d in bundle.skill_dirs] == ["alpha"]


def test_a_name_breaking_the_spec_rule_falls_back_to_the_directory(tmp_path: Path) -> None:
    """The spec's name rule is 1-64 chars of lowercase alphanumerics, hyphens, periods.
    A name outside it is reported and the directory name used — the declared name is what
    the plugin claims, never the string a message is built from unchecked."""
    manifest = dict(MANIFEST, name="Bad Name/../With Path")
    bundle = load_plugin(_make_plugin(tmp_path, manifest=manifest))
    assert bundle.name == "my-plugin"
    assert any("does not match the spec's name rule" in problem for problem in bundle.problems)


def test_a_missing_name_is_reported(tmp_path: Path) -> None:
    manifest = {"$schema": MANIFEST["$schema"]}
    bundle = load_plugin(_make_plugin(tmp_path, manifest=manifest))
    assert bundle.name == "my-plugin"
    assert any("has no 'name'" in problem for problem in bundle.problems)


def test_an_unrecognised_schema_is_reported(tmp_path: Path) -> None:
    manifest = {"name": "ok-name", "$schema": "https://example.com/other.schema.json"}
    bundle = load_plugin(_make_plugin(tmp_path, manifest=manifest))
    assert bundle.name == "ok-name"
    assert any("'$schema'" in problem for problem in bundle.problems)


def test_discovery_follows_the_spec_rule_exactly(tmp_path: Path) -> None:
    """Only an immediate child directory of skills/ holding a SKILL.md is a skill: a loose
    file, a directory without one, and a nested grandchild all stay out."""
    plugin = _make_plugin(tmp_path, skills=("alpha",))
    (plugin / "skills" / "loose-file.md").write_text("x", encoding="utf-8")
    (plugin / "skills" / "not-a-skill").mkdir()
    nested = plugin / "skills" / "not-a-skill" / "nested"
    nested.mkdir()
    (nested / "SKILL.md").write_text("---\nname: n\ndescription: d\n---\n", encoding="utf-8")
    assert [d.name for d in plugin_skill_dirs(plugin)] == ["alpha"]


def test_a_missing_skills_directory_is_empty_not_an_error(tmp_path: Path) -> None:
    """The spec makes every component location optional; a plugin can ship only MCP
    servers. That is a bundle with nothing for Bellwether to evaluate, not a crash."""
    bundle = load_plugin(_make_plugin(tmp_path))
    assert bundle.skill_dirs == ()
    assert bundle.problems == ()


def test_skills_of_the_wrong_filesystem_kind_is_reported(tmp_path: Path) -> None:
    """The spec: a component location of the wrong kind makes that component invalid but
    the rest still loads. Zero skills from a bundle that looks like it ships some must be
    said out loud — a silent empty result reads as 'nothing to evaluate' when the truth
    is 'could not read what there is'."""
    plugin = _make_plugin(tmp_path)
    (plugin / "skills").write_text("i am a file", encoding="utf-8")
    bundle = load_plugin(plugin)
    assert bundle.skill_dirs == ()
    assert any("not a directory" in problem for problem in bundle.problems)


def test_mcp_servers_are_recorded_never_started(tmp_path: Path) -> None:
    """An mcp.json declares executable behaviour this version does not stand up. The flag
    exists so the caller reports it as unevaluated — a component silently ignored reads
    as a component that ran clean."""
    plugin = _make_plugin(tmp_path, skills=("alpha",))
    (plugin / "mcp.json").write_text(
        json.dumps({"$schema": "x", "mcpServers": {"srv": {"type": "stdio", "command": "run"}}}),
        encoding="utf-8",
    )
    bundle = load_plugin(plugin)
    assert bundle.has_mcp_servers
