"""WP-4, host-side: zones, fixtures, payload staging, identifiers, isolation profile.

Done when (the parts reachable without a container daemon): two materialisations of the
same fixture are byte- and metadata-identical, and no file under ``evals/`` can reach the
container.

The container lifecycle — overlay mount, upper-directory diff, an actual run under
``--cap-drop=ALL`` — is the other half of WP-4 and needs a daemon.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

import pytest

from bellwether.determinism import SeededRng
from bellwether.errors import SkillError
from bellwether.sandbox import (
    DIRECTORY_MODE,
    EXECUTABLE_MODE,
    FILE_MODE,
    NORMALIZED_MTIME,
    IsolationProfile,
    ZoneMap,
    derive_identifiers,
    fixture_digest,
    materialize_fixture,
    normalize_container_path,
    prepare_sandbox,
    stage_payload,
)
from bellwether.skill import load_skill

# ---------------------------------------------------------------------------
# Zones (§10.2)
# ---------------------------------------------------------------------------


@pytest.fixture
def zones() -> ZoneMap:
    return ZoneMap()


@pytest.mark.parametrize(
    ("path", "zone", "relative"),
    [
        ("/work/a7f3c1/src/auth.py", "workspace", "a7f3c1/src/auth.py"),
        ("/work", "workspace", "."),
        ("/home/agent/.claude/settings.json", "harness_state", "settings.json"),
        ("/tmp/scratch-1", "scratch", "scratch-1"),
        ("/etc/passwd", "outside", "/etc/passwd"),
        ("/home/agent/.ssh/id_ed25519", "outside", "/home/agent/.ssh/id_ed25519"),
    ],
)
def test_paths_are_assigned_to_their_zone(
    zones: ZoneMap, path: str, zone: str, relative: str
) -> None:
    assigned = zones.classify(path)
    assert assigned.zone == zone
    assert assigned.relative == PurePosixPath(relative)


def test_traversal_is_collapsed_before_classification(zones: ZoneMap) -> None:
    """A prefix comparison on the raw string would read this as an in-scope access."""
    assigned = zones.classify("/work/a7f3c1/../../etc/passwd")
    assert assigned.zone == "outside"
    assert assigned.absolute == PurePosixPath("/etc/passwd")
    assert assigned.used_traversal


def test_traversal_that_stays_inside_is_still_flagged(zones: ZoneMap) -> None:
    """§12.6 flags a traversal landing near a baseline entry as a near-miss, so the fact
    that `..` was used has to survive normalisation."""
    assigned = zones.classify("/work/a/../b/file.txt")
    assert assigned.zone == "workspace"
    assert assigned.relative == PurePosixPath("b/file.txt")
    assert assigned.used_traversal


def test_traversal_above_the_root_stays_at_the_root(zones: ZoneMap) -> None:
    assert normalize_container_path("/../../../etc/passwd") == PurePosixPath("/etc/passwd")


def test_the_longest_zone_root_wins() -> None:
    """A harness that keeps its state inside the workspace must still be harness state,
    or every session file lands in the workspace diff."""
    nested = ZoneMap(
        workspace=PurePosixPath("/work"),
        harness_state=PurePosixPath("/work/.claude"),
        scratch=PurePosixPath("/tmp"),
    )
    assert nested.classify("/work/.claude/session.json").zone == "harness_state"
    assert nested.classify("/work/src/main.py").zone == "workspace"


def test_zone_rules_keep_harness_state_out_of_the_workspace_diff(zones: ZoneMap) -> None:
    """§10.2: without this, `workspace_unchanged` never passes for any skill."""
    workspace = zones.classify("/work/x/file.txt").rules
    harness = zones.classify("/home/agent/.claude/x").rules
    scratch = zones.classify("/tmp/x").rules

    assert workspace.in_workspace_diff
    assert not harness.in_workspace_diff
    assert not scratch.in_workspace_diff

    assert harness.write_finding_kind == "harness_state_write"
    assert scratch.coarsen_to_tier2


# ---------------------------------------------------------------------------
# Fixture materialisation (§9.1 step 1, §9.3)
# ---------------------------------------------------------------------------


@pytest.fixture
def fixture_source(tmp_path: Path) -> Path:
    source = tmp_path / "fixture"
    (source / "src").mkdir(parents=True)
    (source / "src" / "auth.py").write_text("def login(): ...\n", encoding="utf-8")
    (source / "README.md").write_text("# project\n", encoding="utf-8")

    script = source / "run.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    script.chmod(0o700)
    return source


def _metadata(root: Path) -> dict[str, tuple[int, int]]:
    return {
        path.relative_to(root).as_posix(): (path.stat().st_mode & 0o777, int(path.stat().st_mtime))
        for path in sorted(root.rglob("*"))
    }


def test_two_materialisations_are_byte_and_metadata_identical(
    fixture_source: Path, tmp_path: Path
) -> None:
    """The WP-4 done-when criterion.

    An ordinary copy stamps each repetition with the time it happened, which is
    non-identical in exactly the way §9.3 forbids and adds metadata churn to the
    filesystem diff that reads as skill behaviour.
    """
    first = materialize_fixture(fixture_source, tmp_path / "one")
    second = materialize_fixture(fixture_source, tmp_path / "two")

    assert first.digest == second.digest
    assert _metadata(first.root) == _metadata(second.root)


def test_mtimes_and_modes_are_normalised(fixture_source: Path, tmp_path: Path) -> None:
    result = materialize_fixture(fixture_source, tmp_path / "workspace")

    for path in result.root.rglob("*"):
        assert int(path.stat().st_mtime) == NORMALIZED_MTIME
        if path.is_dir():
            assert path.stat().st_mode & 0o777 == DIRECTORY_MODE

    assert (result.root / "README.md").stat().st_mode & 0o777 == FILE_MODE
    # The executable bit survives: a fixture whose script stops being executable is a
    # broken fixture, and the run would fail for a reason unrelated to the skill.
    assert (result.root / "run.sh").stat().st_mode & 0o777 == EXECUTABLE_MODE


def test_a_differing_umask_does_not_change_the_result(fixture_source: Path, tmp_path: Path) -> None:
    original = os.umask(0o077)
    try:
        strict = materialize_fixture(fixture_source, tmp_path / "strict")
    finally:
        os.umask(original)
    loose = materialize_fixture(fixture_source, tmp_path / "loose")

    assert _metadata(strict.root) == _metadata(loose.root)


def test_directory_mtimes_survive_their_contents(fixture_source: Path, tmp_path: Path) -> None:
    """Writing a file into a directory updates that directory's mtime, so normalising
    directories before their contents would silently undo itself."""
    result = materialize_fixture(fixture_source, tmp_path / "workspace")
    assert int((result.root / "src").stat().st_mtime) == NORMALIZED_MTIME


def test_canary_paths_are_excluded_from_the_digest(fixture_source: Path, tmp_path: Path) -> None:
    """§9.3: without this the run cache would miss on every evaluation, because §3.5
    randomises canary content per evaluation and §19 keys the cache on fixture_digest."""
    plain = materialize_fixture(fixture_source, tmp_path / "plain")

    canaried = tmp_path / "canaried"
    materialize_fixture(fixture_source, canaried)
    (canaried / ".env").write_text("TOKEN=first-evaluation\n", encoding="utf-8")

    assert fixture_digest(canaried, frozenset({".env"})) == plain.digest

    (canaried / ".env").write_text("TOKEN=second-evaluation\n", encoding="utf-8")
    assert fixture_digest(canaried, frozenset({".env"})) == plain.digest


def test_the_digest_notices_a_content_change(fixture_source: Path, tmp_path: Path) -> None:
    before = materialize_fixture(fixture_source, tmp_path / "before")
    (fixture_source / "README.md").write_text("# project, revised\n", encoding="utf-8")
    after = materialize_fixture(fixture_source, tmp_path / "after")
    assert before.digest != after.digest


def test_a_workspace_is_never_reused(fixture_source: Path, tmp_path: Path) -> None:
    destination = tmp_path / "workspace"
    materialize_fixture(fixture_source, destination)
    with pytest.raises(FileExistsError, match="re-materialised per repetition"):
        materialize_fixture(fixture_source, destination)


def test_a_missing_fixture_is_named(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="fixture directory not found"):
        materialize_fixture(tmp_path / "absent", tmp_path / "workspace")


# ---------------------------------------------------------------------------
# Payload staging (§9.1 step 3, §3.5)
# ---------------------------------------------------------------------------


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    root = tmp_path / "security-review"
    (root / "reference").mkdir(parents=True)
    (root / "evals" / "fixtures").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: security-review\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    (root / "reference" / "checklist.md").write_text("- check\n", encoding="utf-8")
    (root / "evals" / "manifest.yaml").write_text(
        "apiVersion: bellwether/v1\nkind: SkillManifest\nmetadata: {owner: x}\n", encoding="utf-8"
    )
    (root / "evals" / "fixtures" / "seed.txt").write_text("seed\n", encoding="utf-8")
    return root


def test_nothing_under_evals_reaches_the_staging_directory(skill_dir: Path, tmp_path: Path) -> None:
    """The §3.5 invariant: a skill that can see the test machinery can behave only while
    it is being watched."""
    staged = stage_payload(load_skill(skill_dir), tmp_path / "payload")

    assert not staged.contains_machinery()
    assert set(staged.files) == {"SKILL.md", "reference/checklist.md"}
    assert not (staged.root / "evals").exists()
    assert not list(staged.root.rglob("manifest.yaml"))


def test_the_staged_payload_has_normalised_metadata(skill_dir: Path, tmp_path: Path) -> None:
    staged = stage_payload(load_skill(skill_dir), tmp_path / "payload")
    for path in staged.root.rglob("*"):
        assert int(path.stat().st_mtime) == NORMALIZED_MTIME


def test_the_install_path_is_recorded(skill_dir: Path, tmp_path: Path) -> None:
    staged = stage_payload(load_skill(skill_dir), tmp_path / "payload")
    assert staged.install_path == PurePosixPath("/home/agent/.claude/skills/security-review")
    assert staged.payload_digest.startswith("sha256:")


def test_a_symlink_escaping_the_payload_is_refused(skill_dir: Path, tmp_path: Path) -> None:
    """A link out of the payload places host content inside the container's view of the
    skill, so it is refused rather than copied."""
    (skill_dir / "escape.md").symlink_to("/etc/passwd")
    staged = stage_payload(load_skill(skill_dir), tmp_path / "payload")

    assert staged.refused_symlinks == ("escape.md",)
    assert "escape.md" not in staged.files
    assert not (staged.root / "escape.md").exists()


def test_a_symlink_inside_the_payload_is_kept(skill_dir: Path, tmp_path: Path) -> None:
    (skill_dir / "alias.md").symlink_to("reference/checklist.md")
    staged = stage_payload(load_skill(skill_dir), tmp_path / "payload")
    assert "alias.md" in staged.files


def test_staging_refuses_a_dirty_destination(skill_dir: Path, tmp_path: Path) -> None:
    destination = tmp_path / "payload"
    destination.mkdir()
    (destination / "leftover").write_text("x", encoding="utf-8")
    with pytest.raises(SkillError, match="not empty"):
        stage_payload(load_skill(skill_dir), destination)


# ---------------------------------------------------------------------------
# Identifiers (§3.5)
# ---------------------------------------------------------------------------


def test_identifiers_are_randomised_across_runs_and_fixed_within_one() -> None:
    """§9.2: randomised across runs, constant within one. A hostname that changed
    mid-run would make any tool deriving an identifier from it produce varying output."""
    first = derive_identifiers(SeededRng(20260804, "run-1"))
    again = derive_identifiers(SeededRng(20260804, "run-1"))
    second = derive_identifiers(SeededRng(20260804, "run-2"))

    assert first == again
    assert first.workspace_root != second.workspace_root
    assert first.container_name != second.container_name


def test_identifiers_carry_no_project_tell() -> None:
    """A container named `bw-*` is a tell that survives every other mitigation here."""
    for ordinal in range(25):
        identifiers = derive_identifiers(SeededRng(20260804, f"run-{ordinal}"))
        blob = f"{identifiers.hostname} {identifiers.container_name} {identifiers.workspace_root}"
        for tell in ("bellwether", "bw-", "sandbox", "eval", "test", "fixture"):
            assert tell not in blob.lower()


def test_randomisation_can_be_turned_off_and_the_choice_is_recorded() -> None:
    """Findable containers help an operator; they also hand a skill a reliable tell, so
    the trace says which was in force rather than implying concealment."""
    identifiers = derive_identifiers(SeededRng(1, "run"), randomize=False, run_ordinal=3)
    assert not identifiers.randomized
    assert identifiers.container_name == "bellwether-sandbox-3"


def test_the_workspace_root_sits_under_its_zone() -> None:
    identifiers = derive_identifiers(SeededRng(1, "run"), workspace_base="/work")
    assert identifiers.workspace_root.is_relative_to(PurePosixPath("/work"))
    assert ZoneMap().classify(identifiers.workspace_root).zone == "workspace"


# ---------------------------------------------------------------------------
# Isolation profile (§9.2)
# ---------------------------------------------------------------------------


def test_the_default_profile_matches_the_specification() -> None:
    profile = IsolationProfile()
    assert profile.cap_drop == ("ALL",)
    assert profile.read_only_root
    assert profile.no_new_privileges
    assert profile.pids_limit == 512
    assert profile.timeout_seconds == 900
    assert not profile.docker_socket
    assert profile.violations() == []


def test_docker_flags_render_the_profile() -> None:
    """A profile that reads correctly and renders wrongly is the failure that would
    otherwise reach production unobserved."""
    flags = " ".join(IsolationProfile().docker_flags())
    assert "--cap-drop ALL" in flags
    assert "--read-only" in flags
    assert "--security-opt no-new-privileges" in flags
    assert "--pids-limit 512" in flags
    assert "--user agent" in flags


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"cap_drop": ()}, "capabilities were not fully dropped"),
        ({"cap_add": ("SYS_ADMIN",)}, "capabilities were added back"),
        ({"read_only_root": False}, "root filesystem was writable"),
        ({"docker_socket": True}, "equivalent to root on the host"),
        ({"user": "root"}, "ran as root"),
    ],
)
def test_weakenings_are_reported(kwargs: dict[str, object], expected: str) -> None:
    """A run under a relaxed profile is still evidence — about a different situation."""
    violations = " ".join(IsolationProfile(**kwargs).violations())  # type: ignore[arg-type]
    assert expected in violations


def test_the_pinned_environment_removes_varying_identifiers() -> None:
    profile = IsolationProfile()
    assert profile.pinned.timezone == "UTC"
    assert profile.pinned.locale == "C.UTF-8"
    assert set(profile.pinned.machine_id) == {"0"}


# ---------------------------------------------------------------------------
# The prepared sandbox (§9.1 steps 1-5)
# ---------------------------------------------------------------------------


def test_prepare_sandbox_assembles_a_run(
    skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    prepared = prepare_sandbox(
        load_skill(skill_dir),
        fixture_source,
        tmp_path / "run",
        rng=SeededRng(20260804, "run-1"),
    )

    assert prepared.upper_dir.is_dir()
    assert prepared.work_dir.is_dir()
    assert not prepared.payload.contains_machinery()

    host_paths = {host for host, _, _ in prepared.mounts()}
    assert prepared.workspace.root in host_paths
    # The payload is mounted read-only: a skill that can rewrite its own installed body
    # makes the trace describe something other than the reviewed artifact.
    assert [mode for host, _, mode in prepared.mounts() if host == prepared.payload.root] == ["ro"]

    environment = prepared.environment()
    assert environment["TZ"] == "UTC"
    assert environment["HOSTNAME"] == prepared.identifiers.hostname


def test_two_preparations_from_one_seed_agree(
    skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    package = load_skill(skill_dir)
    first = prepare_sandbox(
        package, fixture_source, tmp_path / "a", rng=SeededRng(20260804, "run-1")
    )
    second = prepare_sandbox(
        package, fixture_source, tmp_path / "b", rng=SeededRng(20260804, "run-1")
    )

    assert first.identifiers == second.identifiers
    assert first.workspace.digest == second.workspace.digest
    assert first.payload.payload_digest == second.payload.payload_digest


def test_the_upper_directory_is_outside_the_workspace(
    skill_dir: Path, fixture_source: Path, tmp_path: Path
) -> None:
    """The container writes into the workspace; it must not be able to reach the record
    of what it wrote (§9.1 step 4)."""
    prepared = prepare_sandbox(
        load_skill(skill_dir), fixture_source, tmp_path / "run", rng=SeededRng(1, "run")
    )
    assert not prepared.upper_dir.is_relative_to(prepared.workspace.root)
    assert not prepared.upper_dir.is_relative_to(prepared.payload.root)
