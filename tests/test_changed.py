"""Attributing changed files to skills (§18) — so CI evaluates only what a PR touched.

The property that matters: a change *inside* a skill (its SKILL.md, its manifest, a reference
file) counts as that skill; a change *outside* every skill counts as nothing; a deleted skill
is never handed back. Getting this wrong means either re-running every skill on every push
(burning budget and attaching verdicts to untouched skills) or missing a changed one.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from bellwether.cli.changed import changed_skills, plugin_root_for, skill_dir_for


def _make_skill(root: Path, rel: str) -> None:
    directory = root / rel
    (directory / "evals").mkdir(parents=True, exist_ok=True)
    (directory / "SKILL.md").write_text(
        "---\nname: s\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    (directory / "evals" / "manifest.yaml").write_text("kind: SkillManifest\n", encoding="utf-8")


def test_a_change_to_skill_md_is_that_skill(tmp_path: Path) -> None:
    _make_skill(tmp_path, "skills/alpha")
    assert changed_skills(["skills/alpha/SKILL.md"], root=tmp_path) == [
        PurePosixPath("skills/alpha")
    ]


def test_a_change_under_the_skill_is_attributed_to_it(tmp_path: Path) -> None:
    """The manifest and progressive-disclosure files live beside SKILL.md; touching them
    changes the skill's declared scope or behaviour, so they count."""
    _make_skill(tmp_path, "skills/alpha")
    assert changed_skills(["skills/alpha/evals/manifest.yaml"], root=tmp_path) == [
        PurePosixPath("skills/alpha")
    ]


def test_a_change_outside_every_skill_touches_nothing(tmp_path: Path) -> None:
    _make_skill(tmp_path, "skills/alpha")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("x", encoding="utf-8")
    assert changed_skills(["docs/guide.md", "README.md"], root=tmp_path) == []


def test_multiple_changes_in_one_skill_collapse(tmp_path: Path) -> None:
    _make_skill(tmp_path, "skills/alpha")
    changed = changed_skills(
        ["skills/alpha/SKILL.md", "skills/alpha/evals/manifest.yaml"], root=tmp_path
    )
    assert changed == [PurePosixPath("skills/alpha")]


def test_a_new_skill_is_detected(tmp_path: Path) -> None:
    """A PR that adds a skill lists its new SKILL.md; the file exists on disk, so it counts."""
    _make_skill(tmp_path, "skills/brandnew")
    assert changed_skills(["skills/brandnew/SKILL.md"], root=tmp_path) == [
        PurePosixPath("skills/brandnew")
    ]


def test_a_deleted_skill_is_not_returned(tmp_path: Path) -> None:
    """The diff still names the removed SKILL.md, but it is gone on disk — there is nothing
    left to evaluate, so it must not come back as work."""
    assert changed_skills(["skills/gone/SKILL.md"], root=tmp_path) == []
    assert skill_dir_for("skills/gone/SKILL.md", root=tmp_path) is None


def test_result_is_sorted_and_deduplicated(tmp_path: Path) -> None:
    for name in ("skills/charlie", "skills/alpha", "skills/bravo"):
        _make_skill(tmp_path, name)
    changed = changed_skills(
        [
            "skills/charlie/SKILL.md",
            "skills/alpha/evals/manifest.yaml",
            "skills/bravo/SKILL.md",
            "skills/alpha/SKILL.md",
        ],
        root=tmp_path,
    )
    assert [str(skill) for skill in changed] == ["skills/alpha", "skills/bravo", "skills/charlie"]


def test_blank_and_whitespace_paths_are_ignored(tmp_path: Path) -> None:
    _make_skill(tmp_path, "skills/alpha")
    assert changed_skills(["", "   ", "skills/alpha/SKILL.md"], root=tmp_path) == [
        PurePosixPath("skills/alpha")
    ]


def test_a_path_that_escapes_the_repo_root_is_ignored(tmp_path: Path) -> None:
    """BW-34: a '../'-prefixed or absolute changed path must never be attributed to a SKILL.md
    outside the checkout. Such a path names no file in the evaluated repo, so it is no skill —
    and probing outside root could hand back a directory that is not part of the run at all."""
    root = tmp_path / "repo"
    _make_skill(root, "skills/alpha")
    # A SKILL.md sitting OUTSIDE the repo root, reachable only by climbing out with '..' or by
    # an absolute path — exactly what the guard must refuse to attribute.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SKILL.md").write_text("---\nname: s\ndescription: d\n---\n", encoding="utf-8")

    # Only the in-repo skill comes back; the escaping path contributes nothing.
    assert changed_skills(["../outside/evil.py", "skills/alpha/SKILL.md"], root=root) == [
        PurePosixPath("skills/alpha")
    ]
    # And directly: neither a relative escape nor an absolute path names a skill dir.
    assert skill_dir_for("../outside/evil.py", root=root) is None
    assert skill_dir_for(str(outside / "evil.py"), root=root) is None


def _make_plugin(root: Path, rel: str, skills: tuple[str, ...]) -> None:
    plugin = root / rel
    plugin.mkdir(parents=True, exist_ok=True)
    (plugin / "plugin.json").write_text('{"name": "p"}', encoding="utf-8")
    for name in skills:
        _make_skill(root, f"{rel}/skills/{name}")


def test_a_plugin_level_change_fans_out_to_every_bundled_skill(tmp_path: Path) -> None:
    """A change to plugin.json (or mcp.json, or an extension directory) has no per-skill
    attribution but can change what every bundled skill does when installed. Attributing
    it to nothing would print "no skills changed" for a PR that rewrote the bundle's
    manifest — the silent false-green this detection exists to avoid."""
    _make_plugin(tmp_path, "plugins/deploy", ("alpha", "beta"))
    for plugin_file in (
        "plugins/deploy/plugin.json",
        "plugins/deploy/mcp.json",
        "plugins/deploy/com.example.client/hooks.json",
    ):
        assert changed_skills([plugin_file], root=tmp_path) == [
            PurePosixPath("plugins/deploy/skills/alpha"),
            PurePosixPath("plugins/deploy/skills/beta"),
        ], plugin_file


def test_a_change_inside_a_plugin_skill_counts_only_as_that_skill(tmp_path: Path) -> None:
    """Attribution is skill-first: the precise attribution wins where it exists, so a
    one-skill edit in a ten-skill plugin does not pay for ten evaluations."""
    _make_plugin(tmp_path, "plugins/deploy", ("alpha", "beta"))
    assert changed_skills(["plugins/deploy/skills/alpha/SKILL.md"], root=tmp_path) == [
        PurePosixPath("plugins/deploy/skills/alpha")
    ]


def test_a_skill_deleted_from_a_plugin_reevaluates_the_survivors(tmp_path: Path) -> None:
    """The diff names files under the removed skill, which no longer has a SKILL.md — but
    they are still inside the plugin, whose composition just changed. The deleted skill
    itself is never returned (nothing left to evaluate); the surviving skills are."""
    _make_plugin(tmp_path, "plugins/deploy", ("alpha",))
    assert changed_skills(["plugins/deploy/skills/gone/SKILL.md"], root=tmp_path) == [
        PurePosixPath("plugins/deploy/skills/alpha")
    ]


def test_a_deleted_plugin_is_not_returned(tmp_path: Path) -> None:
    """The plugin.json is gone on disk: like a deleted skill, there is nothing left to
    evaluate, and nothing comes back as work."""
    assert changed_skills(["plugins/gone/plugin.json"], root=tmp_path) == []
    assert plugin_root_for("plugins/gone/plugin.json", root=tmp_path) is None


def test_a_plugin_change_with_no_skills_yields_nothing(tmp_path: Path) -> None:
    """A plugin carrying no skills (e.g. only MCP servers) has nothing Bellwether runs;
    empty output stays the honest result."""
    _make_plugin(tmp_path, "plugins/serversonly", ())
    assert changed_skills(["plugins/serversonly/mcp.json"], root=tmp_path) == []


def test_a_plugin_path_that_escapes_the_repo_root_is_ignored(tmp_path: Path) -> None:
    """The BW-34 containment rule applies to the plugin walk exactly as to the skill walk:
    a path climbing out of the checkout is never attributed to a plugin.json outside it."""
    root = tmp_path / "repo"
    root.mkdir()
    _make_plugin(tmp_path, "outside-plugin", ("alpha",))
    assert plugin_root_for("../outside-plugin/mcp.json", root=root) is None
    assert changed_skills(["../outside-plugin/mcp.json"], root=root) == []
