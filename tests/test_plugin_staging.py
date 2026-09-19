"""§5/§6/§18: an Agent Plugin is installed whole, in the layout a real client uses.

Bare-directory staging lifted each skill out of its bundle, which loses everything outside the
skill's own directory — shared references a skill body points at, the manifest itself — so a
skill that reads a sibling path works in a real client and fails under evaluation for a reason
that is about Bellwether rather than about the skill.

The naming fact these rest on was *observed* against the real CLI 2.1.274, not assumed: a skill
loaded from a bundle is reported qualified by it (``demo-bundle:demo-skill``). Without the
matching fix that would score every plugin-staged run as "the skill never activated" — a false
negative produced entirely by how Bellwether staged the skill.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

import pytest

from bellwether.assertions.engine import skill_name_matches
from bellwether.errors import SkillError
from bellwether.harness import RunLimits, claude_code_argv
from bellwether.sandbox import stage_plugin_bundle

INSTALL_ROOT = "/home/agent/.claude/plugins"


def _bundle(root: Path, *, skills: tuple[str, ...] = ("demo-skill", "other-skill")) -> Path:
    bundle = root / "demo-bundle"
    (bundle).mkdir(parents=True)
    (bundle / "plugin.json").write_text(
        json.dumps({"name": "demo-bundle", "version": "1.0.0"}), encoding="utf-8"
    )
    for name in skills:
        skill = bundle / "skills" / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: The {name} skill.\n---\nBody of {name}.\n",
            encoding="utf-8",
        )
        # Each skill carries its own machinery, which must not reach the container.
        (skill / "evals").mkdir()
        (skill / "evals" / "scenarios.yaml").write_text("apiVersion: x\n", encoding="utf-8")
    # The thing bare-directory staging loses: bundle content outside any skill.
    (bundle / "shared").mkdir()
    (bundle / "shared" / "reference.md").write_text("shared bundle content\n", encoding="utf-8")
    return bundle


def test_the_whole_bundle_is_staged_including_what_sits_outside_a_skill(tmp_path: Path) -> None:
    staged = stage_plugin_bundle(_bundle(tmp_path), tmp_path / "staged")

    assert "plugin.json" in staged.files
    assert "skills/demo-skill/SKILL.md" in staged.files
    # The defect this closes: a sibling path a skill body points at now exists in the container.
    assert "shared/reference.md" in staged.files
    assert (staged.root / "shared" / "reference.md").read_text(encoding="utf-8") == (
        "shared bundle content\n"
    )
    assert staged.skill_names == ("demo-skill", "other-skill")
    assert staged.install_path == PurePosixPath(INSTALL_ROOT) / "demo-bundle"


def test_no_evals_directory_anywhere_in_the_bundle_reaches_the_container(tmp_path: Path) -> None:
    """The §3.5 invariant applies bundle-wide, not just to the skill under test: a skill that
    can see the test machinery can behave only while it is being watched."""
    staged = stage_plugin_bundle(_bundle(tmp_path), tmp_path / "staged")

    assert not any("evals" in Path(name).parts for name in staged.files)
    assert not list(staged.root.rglob("scenarios.yaml"))
    assert not (staged.root / "skills" / "demo-skill" / "evals").exists()
    # Named, not silently dropped — one per skill that carried machinery.
    assert staged.refused_machinery == (
        "skills/demo-skill/evals",
        "skills/other-skill/evals",
    )


def test_a_symlink_escaping_the_bundle_is_refused(tmp_path: Path) -> None:
    """A link out of the bundle places host content inside the container's view of it."""
    bundle = _bundle(tmp_path)
    (bundle / "escape.md").symlink_to("/etc/passwd")
    staged = stage_plugin_bundle(bundle, tmp_path / "staged")

    assert "escape.md" in staged.refused_machinery
    assert "escape.md" not in staged.files
    assert not (staged.root / "escape.md").exists()


def test_staging_refuses_a_dirty_destination(tmp_path: Path) -> None:
    destination = tmp_path / "staged"
    destination.mkdir()
    (destination / "leftover").write_text("x", encoding="utf-8")
    with pytest.raises(SkillError, match="not empty"):
        stage_plugin_bundle(_bundle(tmp_path), destination)


def test_the_staged_bundle_is_byte_stable(tmp_path: Path) -> None:
    """§24: the same bundle stages to the same files on every machine, so a run-cache key over
    it means something."""
    bundle = _bundle(tmp_path)
    first = stage_plugin_bundle(bundle, tmp_path / "a")
    second = stage_plugin_bundle(bundle, tmp_path / "b")
    assert first.files == second.files
    assert first.skill_names == second.skill_names
    for name in first.files:
        assert (first.root / name).read_bytes() == (second.root / name).read_bytes()


def test_the_cli_is_told_to_install_the_bundle_whole(tmp_path: Path) -> None:
    """`--plugin-dir`, the flag observed on CLI 2.1.274: load a plugin from a directory."""
    argv = claude_code_argv(
        "go",
        model_id="m",
        limits=RunLimits(),
        plugin_dirs=[f"{INSTALL_ROOT}/demo-bundle"],
    )
    assert "--plugin-dir" in argv
    assert argv[argv.index("--plugin-dir") + 1] == f"{INSTALL_ROOT}/demo-bundle"
    # Repeatable, and absent when nothing is installed.
    assert "--plugin-dir" not in claude_code_argv("go", model_id="m", limits=RunLimits())


def test_a_bundle_qualified_activation_still_matches_the_skill_under_test() -> None:
    """The observed fact: the CLI reports a bundled skill as `<plugin>:<skill>`. Without this,
    every plugin-staged run would score its skill as never activating — a false negative
    produced by how Bellwether staged it, which looks exactly like evidence about the skill."""
    assert skill_name_matches("demo-bundle:demo-skill", "demo-skill")
    assert skill_name_matches("demo-skill", "demo-skill")
    # A different skill in the same bundle is still a different skill.
    assert not skill_name_matches("demo-bundle:other-skill", "demo-skill")


def test_a_scenario_may_still_name_one_bundles_skill_exactly() -> None:
    """Only the recorded side is unqualified. An expected name carrying its own qualifier is
    compared whole, so two bundles shipping the same skill name stay distinguishable."""
    assert skill_name_matches("demo-bundle:demo-skill", "demo-bundle:demo-skill")
    assert not skill_name_matches("other-bundle:demo-skill", "demo-bundle:demo-skill")
    assert not skill_name_matches("demo-skill", "demo-bundle:demo-skill")
