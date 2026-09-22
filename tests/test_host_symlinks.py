"""A skill may not make the host read what the skill itself cannot (§6.1, §7.2, §9.1).

A skill package is evaluated content; in CI its author is whoever opened the pull request, and
the host loads it as root. Staging already refused a symlink out of the package tree — but the
loader read through one first. ``SKILL.md -> /proc/self/environ`` put the host's environment
(which holds the real API key under ``sudo --preserve-env``) into the skill body sent to the
model and into the trace; ``evals/fixtures -> /root`` had the host copy ``/root`` into the
sandbox workspace. Each test below plants a secret *outside* the package and a link to it
*inside*, and asserts the secret reaches nothing.

One rule, applied everywhere a skill-authored path is read on the host: it must resolve inside
the skill (or plugin) directory. A link that stays inside is the skill's own content and is
followed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bellwether.cli.fixtures import EMPTY_FIXTURE, resolve_fixture
from bellwether.errors import BellwetherError, SkillError
from bellwether.skill import load_plugin, load_skill, plugin_skill_dirs

_SECRET = "HOST-ONLY-SECRET-7f3a"
_SKILL_MD = "---\nname: s\ndescription: d\n---\nbody\n"


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """A directory outside every package, holding what the host can read and a skill cannot."""
    home = tmp_path / "host-home"
    home.mkdir()
    (home / "secret.md").write_text(f"---\nname: s\ndescription: d\n---\n{_SECRET}\n")
    (home / "token").write_text(_SECRET)
    (home / "scenarios.yaml").write_text(f"prompt: {_SECRET}\n")
    (home / "SKILL.md").write_text(f"---\nname: linked\ndescription: d\n---\n{_SECRET}\n")
    return home


def _skill(tmp_path: Path) -> Path:
    skill = tmp_path / "pkg" / "s"
    skill.mkdir(parents=True)
    return skill


# --- load_skill -----------------------------------------------------------------------------


def test_a_skill_md_linked_out_of_the_package_is_refused_not_read(
    tmp_path: Path, outside: Path
) -> None:
    skill = _skill(tmp_path)
    (skill / "SKILL.md").symlink_to(outside / "secret.md")
    with pytest.raises(SkillError, match="outside the skill directory") as refused:
        load_skill(skill)
    assert _SECRET not in str(refused.value)


def test_a_skill_md_linked_within_the_package_is_the_skills_own_content(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    (skill / "docs").mkdir()
    (skill / "docs" / "real.md").write_text(_SKILL_MD)
    (skill / "SKILL.md").symlink_to(Path("docs") / "real.md")
    assert load_skill(skill).parsed.body.strip() == "body"


def test_an_evals_directory_linked_out_is_refused_before_its_prompts_are_read(
    tmp_path: Path, outside: Path
) -> None:
    """The scenarios' prompts go to the model, so a linked-in file is sent, not only read."""
    skill = _skill(tmp_path)
    (skill / "SKILL.md").write_text(_SKILL_MD)
    (skill / "evals").symlink_to(outside, target_is_directory=True)
    with pytest.raises(SkillError, match=r"evals/scenarios\.yaml"):
        load_skill(skill)


def test_a_manifest_linked_out_is_refused(tmp_path: Path, outside: Path) -> None:
    skill = _skill(tmp_path)
    (skill / "SKILL.md").write_text(_SKILL_MD)
    (skill / "evals").mkdir()
    (skill / "evals" / "manifest.yaml").symlink_to(outside / "scenarios.yaml")
    with pytest.raises(SkillError, match=r"evals/manifest\.yaml"):
        load_skill(skill)


def test_a_payload_doc_linked_out_is_never_read_for_its_token_estimate(
    tmp_path: Path, outside: Path
) -> None:
    skill = _skill(tmp_path)
    (skill / "SKILL.md").write_text(_SKILL_MD)
    (skill / "notes.md").symlink_to(outside / "secret.md")
    assert "notes.md" not in load_skill(skill).token_estimates


# --- plugins --------------------------------------------------------------------------------


def _plugin(tmp_path: Path) -> Path:
    plugin = tmp_path / "plugin"
    (plugin / "skills" / "good").mkdir(parents=True)
    (plugin / "plugin.json").write_text('{"name": "p"}')
    (plugin / "skills" / "good" / "SKILL.md").write_text(_SKILL_MD)
    return plugin


def test_a_plugin_skill_directory_linked_out_is_not_loaded_and_says_so(
    tmp_path: Path, outside: Path
) -> None:
    plugin = _plugin(tmp_path)
    (plugin / "skills" / "evil").symlink_to(outside, target_is_directory=True)

    assert [d.name for d in plugin_skill_dirs(plugin)] == ["good"]
    bundle = load_plugin(plugin)
    assert [d.name for d in bundle.skill_dirs] == ["good"]
    assert any("evil" in problem and "outside" in problem for problem in bundle.problems)


def test_a_plugin_manifest_linked_out_is_refused(tmp_path: Path, outside: Path) -> None:
    plugin = _plugin(tmp_path)
    (plugin / "plugin.json").unlink()
    (plugin / "plugin.json").symlink_to(outside / "token")
    with pytest.raises(SkillError, match="outside"):
        load_plugin(plugin)


# --- fixtures -------------------------------------------------------------------------------


@pytest.mark.parametrize("name", [None, "default", "anything"])
def test_a_fixtures_directory_linked_out_is_refused_whatever_the_fixture_name(
    tmp_path: Path, outside: Path, name: str | None
) -> None:
    """The name check resolved the root *and* the name, so a linked root passed every name;
    the flat-layout fallback and the no-name path returned the root with no check at all."""
    skill = _skill(tmp_path)
    (skill / "evals").mkdir()
    (skill / "evals" / "fixtures").symlink_to(outside, target_is_directory=True)
    with pytest.raises(BellwetherError, match="outside the skill directory"):
        resolve_fixture(skill, name)


def test_the_empty_workspace_is_never_created_through_a_linked_evals(
    tmp_path: Path, outside: Path
) -> None:
    skill = _skill(tmp_path)
    (skill / "evals").symlink_to(outside, target_is_directory=True)
    for name in (None, EMPTY_FIXTURE):
        with pytest.raises(BellwetherError, match="outside the skill directory"):
            resolve_fixture(skill, name)
    assert not (outside / ".empty-workspace").exists()


def test_the_run_commands_default_fixture_uses_the_same_rule(tmp_path: Path, outside: Path) -> None:
    """``run`` had its own copy of the fixture lookup; the copy is where the rule was missing."""
    from bellwether.cli.app import _run_fixture

    skill = _skill(tmp_path)
    (skill / "evals").mkdir()
    (skill / "evals" / "fixtures").symlink_to(outside, target_is_directory=True)
    with pytest.raises(BellwetherError, match="outside the skill directory"):
        _run_fixture(skill)


# --- eval_id --------------------------------------------------------------------------------


def test_the_evaluation_directory_is_named_by_the_slug_not_the_declared_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hardening, not a reachable escape: a declared name containing ``/`` is already refused
    by the baseline lookup before this path is built. The directory root writes to is still
    named from the slug, so the next caller that reorders them cannot reopen it."""
    from typer.testing import CliRunner

    from bellwether.cli import run as run_module
    from bellwether.cli.app import app
    from bellwether.sandbox import DockerBackend

    runner = CliRunner()
    assert runner.invoke(app, ["init", str(tmp_path)]).exit_code == 0
    skill = _skill(tmp_path)
    (skill / "SKILL.md").write_text(
        '---\nname: "..weird name:with;chars"\ndescription: d\n---\nb\n'
    )
    seen: dict[str, object] = {}

    class _StopError(Exception):
        pass

    def factory(_image: str, runs_root: Path, eval_id: str, **_kw: object) -> object:
        seen.update(runs_root=runs_root, eval_id=eval_id)
        raise _StopError

    monkeypatch.setattr(run_module, "sandbox_executor_factory", factory)
    monkeypatch.setattr(DockerBackend, "available", lambda _self: (True, ""))
    out = tmp_path / "out"
    runner.invoke(
        app,
        [
            "run",
            str(skill),
            "--config",
            str(tmp_path / ".bellwether" / "config.yaml"),
            "--policy",
            str(tmp_path / ".bellwether" / "policy.yaml"),
            "--out",
            str(out),
        ],
    )
    assert str(seen["eval_id"]).startswith("weird-name-with-chars-")
    assert seen["runs_root"] == out / str(seen["eval_id"]) / "runs"
