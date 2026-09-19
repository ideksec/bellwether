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
import os
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

    # A symlink refusal is not machinery: the two are kept apart, as `StagedPayload` does.
    assert staged.refused_symlinks == ("escape.md",)
    assert "escape.md" not in staged.refused_machinery
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


# ---------------------------------------------------------------------------
# Review fixes: what must never reach the container, and where the bundle mounts
# ---------------------------------------------------------------------------


def test_a_bundle_that_is_its_own_checkout_does_not_ship_its_git_directory(
    tmp_path: Path,
) -> None:
    """§3.5, the version the working-tree rule misses. Leaving `evals/` behind is not enough
    when the bundle is its own git checkout: `git show HEAD:evals/scenarios.yaml` recovers the
    machinery from `.git`, and a skill that can read the test machinery can behave only while
    it is being watched."""
    bundle = _bundle(tmp_path)
    (bundle / ".git" / "objects").mkdir(parents=True)
    (bundle / ".git" / "objects" / "pack").write_bytes(b"the evals live in here")
    (bundle / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    staged = stage_plugin_bundle(bundle, tmp_path / "staged")

    assert not any(part.startswith(".git") for name in staged.files for part in Path(name).parts)
    assert not (staged.root / ".git").exists()
    assert staged.refused_vcs == (".git",)


def test_ordinary_dotfiles_are_still_staged(tmp_path: Path) -> None:
    """The exclusion is version-control metadata, not dotfiles: a bundle's own `.env` or
    `.claude` is content a real client installs, and dropping it would recreate the very gap
    whole-bundle staging exists to close."""
    bundle = _bundle(tmp_path)
    (bundle / ".env.example").write_text("API_KEY=\n", encoding="utf-8")
    (bundle / ".claude").mkdir()
    (bundle / ".claude" / "settings.json").write_text("{}", encoding="utf-8")

    staged = stage_plugin_bundle(bundle, tmp_path / "staged")
    assert ".env.example" in staged.files
    assert ".claude/settings.json" in staged.files


def test_a_fifo_in_the_bundle_does_not_hang_the_staging(tmp_path: Path) -> None:
    """Opening a FIFO blocks until a writer appears, and nothing is going to write. The
    observed tree must never decide whether the observer finishes (§10.0)."""
    bundle = _bundle(tmp_path)
    os.mkfifo(bundle / "pipe")

    staged = stage_plugin_bundle(bundle, tmp_path / "staged")
    assert "pipe" not in staged.files
    assert staged.refused_special == ("pipe",)


def test_a_relative_bundle_path_installs_under_the_directory_it_names(tmp_path: Path) -> None:
    """`stage_payload` asserts its install path cannot escape, and the bundle must too. The
    subtlety: taking the path's name verbatim puts `..` in the container path, and a lexical
    containment check does *not* catch it — `plugins/..` compares as relative to `plugins`
    while resolving to its parent, which would mount the bundle read-only over the
    harness-state zone. Resolving first is what makes the guard real."""
    bundle = _bundle(tmp_path)
    via_dots = bundle / "skills" / ".."  # the bundle itself, named awkwardly

    staged = stage_plugin_bundle(via_dots, tmp_path / "staged")

    assert staged.install_path == PurePosixPath(INSTALL_ROOT) / "demo-bundle"
    assert ".." not in staged.install_path.parts
    assert staged.install_path.is_relative_to(PurePosixPath(INSTALL_ROOT))


def test_a_bundle_with_no_usable_directory_name_is_refused(tmp_path: Path) -> None:
    """The filesystem root resolves to no name at all: there is nowhere to install it."""
    with pytest.raises(SkillError, match="usable as a directory inside the container"):
        stage_plugin_bundle(Path("/"), tmp_path / "staged")


def test_a_prepared_sandbox_omits_the_payload_mount_when_it_is_not_installed(
    tmp_path: Path,
) -> None:
    """The defect a review caught: the skill under test is *inside* the bundle, so installing
    the bare payload as well offers the harness two copies of it — `demo-skill` and
    `demo-bundle:demo-skill` — and which activated is undecidable. Worse, if the bare copy
    wins, the sibling-bundle content this staging exists to provide is still absent."""
    from dataclasses import replace

    from bellwether.sandbox import ZoneMap
    from bellwether.sandbox.session import PreparedSandbox
    from bellwether.sandbox.staging import stage_payload
    from bellwether.skill import load_skill

    skill = tmp_path / "solo"
    (skill / "evals").mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: solo\ndescription: A skill.\n---\nBody.\n", encoding="utf-8"
    )
    payload = stage_payload(load_skill(skill), tmp_path / "payload")
    workspace = tmp_path / "ws"
    workspace.mkdir()

    class _Fixture:
        root = workspace

    prepared = PreparedSandbox(
        identifiers=_identifiers(),
        zones=ZoneMap(),
        isolation=_isolation(),
        workspace=_Fixture(),  # type: ignore[arg-type]
        payload=payload,
        upper_dir=tmp_path / "upper",
        work_dir=tmp_path / "work",
    )
    installed = [target for _, target, _ in prepared.mounts()]
    assert payload.install_path in installed

    bundled = replace(prepared, install_payload=False)
    assert payload.install_path not in [target for _, target, _ in bundled.mounts()]
    # The workspace is untouched: this removes one mount, it does not reshape the run.
    assert len(bundled.mounts()) == len(prepared.mounts()) - 1


def _identifiers():  # type: ignore[no-untyped-def]
    from bellwether.determinism import SeededRng
    from bellwether.sandbox import derive_identifiers

    return derive_identifiers(SeededRng(1, "ids"), randomize=False)


def _isolation():  # type: ignore[no-untyped-def]
    from bellwether.sandbox import IsolationProfile

    return IsolationProfile()


# ---------------------------------------------------------------------------
# Second review round: the container path, the exclusion rule, and the cache key
# ---------------------------------------------------------------------------


def test_the_bundle_installs_under_its_own_name_not_the_host_directorys(tmp_path: Path) -> None:
    """The same plugin has to land at the same container path on every machine.

    Deriving it from the host checkout's directory name made the path an accident of where the
    operator cloned: `plugin/` on CI and `plugin-dev/` on a laptop install at two different
    paths, which makes the run cache machine-local (§24) and leaks the operator's directory
    layout into the sandbox the skill can read.
    """
    from bellwether.skill import load_plugin

    checked_out_as = tmp_path / "checkout-2024-06"
    checked_out_as.mkdir()
    bundle_dir = _bundle(checked_out_as)
    bundle_dir.rename(checked_out_as / "wherever-the-operator-put-it")
    bundle = load_plugin(checked_out_as / "wherever-the-operator-put-it")

    staged = stage_plugin_bundle(bundle.root, tmp_path / "staged", name=bundle.name)

    # `plugin.json` declares `demo-bundle`; the directory is called something else entirely.
    assert bundle.name == "demo-bundle"
    assert staged.install_path == PurePosixPath(INSTALL_ROOT) / "demo-bundle"


def test_a_declared_name_that_is_not_a_directory_name_never_reaches_the_container_path(
    tmp_path: Path,
) -> None:
    """The manifest's name reaches a container path, so it is validated there too.

    The spec's name rule admits periods, so `..` is a *well-formed* declared name — and it
    would put the bundle's mount one level above the plugin root, over the harness-state zone.
    Where a value came from does not make it usable as a directory name, so the declared name
    goes through the same guard the host directory name does, and the directory name is what
    is used when it fails.
    """
    bundle = _bundle(tmp_path)
    for index, declared in enumerate(("..", ".", "", "../elsewhere", "acme:tools")):
        staged = stage_plugin_bundle(bundle, tmp_path / f"staged-{index}", name=declared)
        assert staged.install_path == PurePosixPath(INSTALL_ROOT) / "demo-bundle"


def test_a_relative_bundle_path_with_no_declared_name_still_installs(tmp_path: Path) -> None:
    """The regression that made the fallback matter rather than be dead code.

    `bellwether run .` on a bundle whose manifest declares no name gets `""` from
    `load_plugin` — a relative path has no last component — so deriving the container path from
    the bundle name *alone* refused a run that had worked the day before. The resolved
    directory name is what it points at, and that is what installs.
    """
    import json
    import os

    from bellwether.skill import load_plugin

    bundle = _bundle(tmp_path)
    (bundle / "plugin.json").write_text(json.dumps({"version": "1.0.0"}), encoding="utf-8")
    cwd = Path.cwd()
    os.chdir(bundle)
    try:
        loaded = load_plugin(Path())
        # `Path()` is `.`: a relative path with no last component, which is the fact that
        # turned this into a refusal.
        assert loaded.name == ""
        staged = stage_plugin_bundle(loaded.root, tmp_path / "staged", name=loaded.name)
    finally:
        os.chdir(cwd)

    assert staged.install_path == PurePosixPath(INSTALL_ROOT) / "demo-bundle"


def test_a_directory_name_docker_cannot_mount_is_refused_before_docker_sees_it(
    tmp_path: Path,
) -> None:
    """A colon is legal in a directory name and fatal in a bind mount.

    The bundle is mounted with `-v <host>:<container>:ro`, so a container path carrying a colon
    makes docker refuse the whole run with "invalid volume specification" — an error about
    docker syntax, for a problem about the operator's directory name. Refused here, where the
    message can say what to do about it.
    """
    checkout = tmp_path / "acme:tools"
    checkout.mkdir()
    bundle = _bundle(checkout)
    bundle.rename(checkout / "inner")
    (checkout / "inner").rename(tmp_path / "acme:tools-bundle")

    with pytest.raises(SkillError, match="usable as a directory inside the container"):
        stage_plugin_bundle(tmp_path / "acme:tools-bundle", tmp_path / "staged", name=None)


def test_an_upper_cased_evals_directory_is_still_machinery(tmp_path: Path) -> None:
    """The §3.5 invariant must not depend on how a checkout spelled the directory.

    `payload._is_machinery` already folds case and Unicode form for a skill; the bundle walk
    compared the exact string, so a checkout on a case-insensitive filesystem — or an author
    who typed `EVALS/` — would ship the evaluation machinery into the container, and every run
    of that skill would observe a skill that knows it is being watched.
    """
    bundle = _bundle(tmp_path)
    loud = bundle / "skills" / "demo-skill" / "EVALS"
    loud.mkdir()
    (loud / "scenarios.yaml").write_text("apiVersion: x\n", encoding="utf-8")

    staged = stage_plugin_bundle(bundle, tmp_path / "staged")

    assert not any("EVALS" in path for path in staged.files)
    assert "skills/demo-skill/EVALS" in staged.refused_machinery
    assert not (staged.root / "skills" / "demo-skill" / "EVALS").exists()


def test_an_upper_cased_vcs_directory_is_still_skipped(tmp_path: Path) -> None:
    """Same rule, same reason: `.Git` on a case-insensitive filesystem is still a checkout,
    and `git show HEAD:evals/scenarios.yaml` recovers the machinery from it."""
    bundle = _bundle(tmp_path)
    (bundle / ".Git").mkdir()
    (bundle / ".Git" / "config").write_text("[core]\n", encoding="utf-8")

    staged = stage_plugin_bundle(bundle, tmp_path / "staged")

    assert not any(path.startswith(".Git") for path in staged.files)
    assert ".Git" in staged.refused_vcs


def test_the_cache_key_digests_only_what_reaches_the_container(tmp_path: Path) -> None:
    """A plugin developed in its own checkout must not thrash the run cache.

    The digest keyed the run cache on the whole working directory, including `.git` and every
    `evals/` — none of which staging copies. So a commit, or an edit to the scenarios that are
    already part of the scenario digest, changed the key while the thing actually placed in the
    container was byte-identical, and the cost of that miss is paid in model tokens (§19.2).
    """
    from bellwether.sandbox import plugin_bundle_digest

    bundle = _bundle(tmp_path)
    (bundle / ".git").mkdir()
    (bundle / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    before = plugin_bundle_digest(bundle)

    (bundle / ".git" / "HEAD").write_text("ref: refs/heads/other\n", encoding="utf-8")
    (bundle / "skills" / "demo-skill" / "evals" / "scenarios.yaml").write_text(
        "apiVersion: changed\n", encoding="utf-8"
    )
    assert plugin_bundle_digest(bundle) == before, "excluded content moved the cache key"

    # And the converse, because a digest that never changes is worse than no digest: content
    # the container *does* see moves it.
    (bundle / "shared" / "reference.md").write_text("different\n", encoding="utf-8")
    assert plugin_bundle_digest(bundle) != before


def test_the_digest_and_the_copy_agree_on_what_is_excluded(tmp_path: Path) -> None:
    """One rule, asserted against both users of it. A digest that describes a different set of
    files from the one staged is the failure mode the shared predicate exists to prevent: the
    cache would replay a trace recorded from a bundle that is not this one."""
    from bellwether.determinism import sorted_walk
    from bellwether.sandbox.staging import bundle_exclusion

    bundle = _bundle(tmp_path)
    (bundle / ".git").mkdir()
    (bundle / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    staged = stage_plugin_bundle(bundle, tmp_path / "staged")
    digested = {
        relative.as_posix()
        for relative in sorted_walk(bundle)
        if bundle_exclusion(relative.parts) is None
    }
    assert digested == set(staged.files)


def test_the_repositorys_own_bellwether_directories_never_reach_the_container(
    tmp_path: Path,
) -> None:
    """§3.5 at its most load-bearing, and the exclusion list missed it.

    `evals/` is the *skill's* machinery. A plugin bundle that is its own checkout also carries
    the *repository's*: `.bellwether/` holds the config, the platform baseline, the stored
    baselines and the **policy** — the gates this very skill is about to be judged against —
    and `.bellwether-out/` holds the traces of previous evaluations. Staging the bundle whole
    put both inside the container, which tells the skill under test not merely that it is
    being watched but exactly what would clear it.
    """
    from bellwether.config.document import CONFIG_DIR

    bundle = _bundle(tmp_path)
    (bundle / CONFIG_DIR.name).mkdir()
    (bundle / CONFIG_DIR.name / "policy.yaml").write_text("gates: {}\n", encoding="utf-8")
    (bundle / CONFIG_DIR.name / "baselines").mkdir()
    (bundle / CONFIG_DIR.name / "baselines" / "demo.json").write_text("{}", encoding="utf-8")
    out = bundle / f"{CONFIG_DIR.name}-out"
    (out / "eval-1").mkdir(parents=True)
    (out / "eval-1" / "trace.arf.jsonl").write_text("{}\n", encoding="utf-8")

    staged = stage_plugin_bundle(bundle, tmp_path / "staged")

    assert not any(path.startswith(CONFIG_DIR.name) for path in staged.files), staged.files
    assert not (staged.root / CONFIG_DIR.name).exists()
    assert not (staged.root / f"{CONFIG_DIR.name}-out").exists()
    # Named, not silently dropped — and as machinery, which is what they are.
    assert CONFIG_DIR.name in staged.refused_machinery
    assert f"{CONFIG_DIR.name}-out" in staged.refused_machinery
    # The content that *should* travel still does.
    assert "shared/reference.md" in staged.files


def test_the_cache_key_ignores_a_symlink_the_copy_refuses(tmp_path: Path) -> None:
    """The digest has to describe the bundle *as installed*, symlinks included.

    An escaping symlink is refused by the copy, so re-pointing one at a different host file
    changes nothing inside the container — but it moved the cache key, which means a key that
    claims to describe a bundle in which nothing moved.
    """
    from bellwether.sandbox import plugin_bundle_digest

    bundle = _bundle(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a").write_text("a\n", encoding="utf-8")
    (outside / "b").write_text("b\n", encoding="utf-8")
    link = bundle / "escaping"
    link.symlink_to(outside / "a")

    staged = stage_plugin_bundle(bundle, tmp_path / "staged")
    assert "escaping" in staged.refused_symlinks and "escaping" not in staged.files

    before = plugin_bundle_digest(bundle)
    link.unlink()
    link.symlink_to(outside / "b")
    assert plugin_bundle_digest(bundle) == before
