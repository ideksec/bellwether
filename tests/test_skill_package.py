"""WP-2: skill package parsing and the three digests (§6.1–6.3).

Done when: digests are byte-reproducible across two machines and two filesystem
orderings; ``payload_digest`` is unchanged by edits under ``evals/``;
``description_digest`` changes on a description-only edit and not otherwise.
"""

from __future__ import annotations

import datetime as dt
import shutil
from pathlib import Path

import pytest

from bellwether.errors import SkillError
from bellwether.skill import (
    EVALS_DIR,
    FileRecord,
    PayloadAllowlist,
    detect_interpreter,
    estimate_tokens,
    load_skill,
    merkle_digest,
    normalize_description,
    parse_skill_markdown,
    read_file_records,
)
from tests.conftest import EXAMPLE_SKILL

SKILL_MD = """---
name: security-review
description: Reviews a codebase for auth defects.
allowed-tools: [Read, Grep]
some-future-field: {nested: true}
---

# Security review

Body text.
"""


VALID_SUITE = """apiVersion: bellwether/v1
kind: ScenarioSuite
scenarios:
  - id: only-scenario
    expectation: should_trigger
    prompt: "a prompt"
    assert:
      - skill_activated: true
"""


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    root = tmp_path / "security-review"
    (root / "reference").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "evals" / "fixtures").mkdir(parents=True)

    (root / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    (root / "reference" / "checklist.md").write_text("- check auth\n", encoding="utf-8")
    (root / "scripts" / "scan.py").write_text(
        "#!/usr/bin/env python3\nprint('x')\n", encoding="utf-8"
    )
    (root / "evals" / "scenarios.yaml").write_text(VALID_SUITE, encoding="utf-8")
    (root / "evals" / "fixtures" / "seed.txt").write_text("seed\n", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Frontmatter
# ---------------------------------------------------------------------------


def test_unknown_frontmatter_fields_are_preserved(skill_dir: Path) -> None:
    """§6.1: an unexpected field is itself worth surfacing, so it must not be dropped."""
    package = load_skill(skill_dir)
    assert package.parsed.frontmatter is not None
    assert package.parsed.frontmatter.unknown_fields == {"some-future-field": {"nested": True}}


def test_known_frontmatter_fields_are_read(skill_dir: Path) -> None:
    package = load_skill(skill_dir)
    assert package.name == "security-review"
    assert package.declared_tools == ("Read", "Grep")


def test_allowed_tools_may_be_a_comma_separated_string() -> None:
    parsed = parse_skill_markdown("---\nname: x\nallowed-tools: Read, Grep , Bash\n---\nbody\n")
    assert parsed.frontmatter is not None
    assert parsed.frontmatter.allowed_tools == ["Read", "Grep", "Bash"]


@pytest.mark.parametrize(
    ("field", "value"),
    [("allowed-tools", "5"), ("name", "[a, b]"), ("description", "12")],
)
def test_a_wrong_typed_known_field_is_recorded_not_raised(field: str, value: str) -> None:
    """A skill is somebody else's file, often a third party's.

    Letting a ValidationError out would both break the rule that problems are reported as
    sentences, and let a malformed package stop the loader before any sandbox exists — so
    a hostile skill could avoid being described at all by shipping `allowed-tools: 5`.
    """
    parsed = parse_skill_markdown(f"---\nname: x\ndescription: d\n{field}: {value}\n---\nb\n")

    assert field in parsed.unusable_fields
    assert any(f"{field!r} is not usable" in problem for problem in parsed.problems)
    assert parsed.frontmatter is not None
    assert parsed.body == "b\n"


def test_frontmatter_that_is_wholly_unusable_still_parses() -> None:
    parsed = parse_skill_markdown("---\nname: {a: 1}\ndescription: [x]\n---\nbody\n")
    assert parsed.frontmatter is not None
    assert set(parsed.unusable_fields) == {"name", "description"}


def test_a_skill_with_a_wrong_typed_field_still_loads(tmp_path: Path) -> None:
    root = tmp_path / "sloppy"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: sloppy\ndescription: d\nallowed-tools: 5\n---\nbody\n", encoding="utf-8"
    )
    package = load_skill(root)
    assert package.name == "sloppy"
    assert package.declared_tools == ()
    assert package.parsed.unusable_fields == {"allowed-tools": 5}


def test_a_pinned_model_is_reported_as_a_problem() -> None:
    parsed = parse_skill_markdown("---\nname: x\ndescription: d\nmodel: some-model\n---\nbody\n")
    assert any("pins model" in problem for problem in parsed.problems)


def test_missing_frontmatter_is_recorded_not_fatal() -> None:
    parsed = parse_skill_markdown("# Just a heading\n")
    assert parsed.frontmatter is None
    assert parsed.body == "# Just a heading\n"
    assert any("no YAML frontmatter" in problem for problem in parsed.problems)


def test_a_skill_without_frontmatter_still_loads(tmp_path: Path) -> None:
    """A skill Bellwether refuses to load is one it can say nothing about."""
    root = tmp_path / "bare"
    root.mkdir()
    (root / "SKILL.md").write_text("# no frontmatter\n", encoding="utf-8")
    package = load_skill(root)
    assert package.name == "bare"
    assert package.description == ""
    assert package.problems


def test_a_directory_without_skill_md_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(SkillError, match=r"SKILL\.md"):
        load_skill(tmp_path)


# ---------------------------------------------------------------------------
# The three digests
# ---------------------------------------------------------------------------


def test_digests_are_reproducible_across_filesystem_orderings(
    skill_dir: Path, tmp_path: Path
) -> None:
    """A digest over an unsorted walk is machine-local, and so is every cache key from it.

    The two copies below are built in opposite creation order, which is what an
    iteration-order walk would surface as a different digest.
    """
    forward = load_skill(skill_dir)

    mirror = tmp_path / "mirror"
    mirror.mkdir()
    for relative in reversed([record.path for record in forward.files]):
        target = mirror / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(skill_dir / relative, target)

    reverse = load_skill(mirror)
    assert reverse.package_digest == forward.package_digest
    assert reverse.payload_digest == forward.payload_digest
    assert reverse.description_digest == forward.description_digest


def test_merkle_digest_does_not_depend_on_input_order(skill_dir: Path) -> None:
    records = read_file_records(skill_dir)
    assert merkle_digest(records) == merkle_digest(list(reversed(records)))


def test_a_newline_in_a_file_name_cannot_forge_a_digest() -> None:
    """Newlines are legal in POSIX filenames.

    Delimiting the digest input with them let one file named ``a\\nsha256:...\\nb`` hash
    identically to two files ``a`` and ``b``. A forgeable package_digest is a forgeable
    review attestation (§6.3) and a forgeable cache key (§19.2), so every field is
    length-prefixed.
    """
    forged = [FileRecord(path="a\nsha256:deadbeef\nb", sha256="sha256:x", size_bytes=1)]
    genuine = [
        FileRecord(path="a", sha256="sha256:deadbeef", size_bytes=1),
        FileRecord(path="b", sha256="sha256:x", size_bytes=1),
    ]
    assert merkle_digest(forged) != merkle_digest(genuine)


def test_a_control_character_in_a_file_name_is_reported(tmp_path: Path) -> None:
    """Not a correctness control — length-prefixing handles that — but a skill shipping
    such a file is doing something a reviewer should see."""
    root = tmp_path / "odd"
    root.mkdir()
    (root / "SKILL.md").write_text("---\nname: odd\ndescription: d\n---\nbody\n", "utf-8")
    (root / "we\nird.md").write_text("x", encoding="utf-8")

    package = load_skill(root)
    assert any("control characters" in problem for problem in package.problems)


def test_payload_digest_is_unchanged_by_edits_under_evals(skill_dir: Path) -> None:
    """Changing a scenario must not invalidate cached runs of an unchanged skill."""
    before = load_skill(skill_dir)

    (skill_dir / "evals" / "scenarios.yaml").write_text(
        VALID_SUITE.replace("a prompt", "a different prompt"), encoding="utf-8"
    )
    (skill_dir / "evals" / "new-file.yaml").write_text("added\n", encoding="utf-8")
    after = load_skill(skill_dir)

    assert after.payload_digest == before.payload_digest
    assert after.package_digest != before.package_digest


def test_payload_digest_changes_when_the_skill_changes(skill_dir: Path) -> None:
    before = load_skill(skill_dir)
    (skill_dir / "reference" / "checklist.md").write_text("- check auth\n- and authz\n", "utf-8")
    after = load_skill(skill_dir)

    assert after.payload_digest != before.payload_digest
    assert after.package_digest != before.package_digest


def test_description_digest_changes_only_on_a_description_edit(skill_dir: Path) -> None:
    before = load_skill(skill_dir)

    (skill_dir / "SKILL.md").write_text(
        SKILL_MD.replace("Body text.", "Body text, revised."), encoding="utf-8"
    )
    body_edit = load_skill(skill_dir)
    assert body_edit.description_digest == before.description_digest
    assert body_edit.payload_digest != before.payload_digest

    (skill_dir / "SKILL.md").write_text(
        SKILL_MD.replace("auth defects.", "authorization defects."), encoding="utf-8"
    )
    description_edit = load_skill(skill_dir)
    assert description_edit.description_digest != before.description_digest


def test_description_digest_survives_a_reflow(skill_dir: Path) -> None:
    """A rewrap is not a triggering change, and the library matrix is expensive (§7.4)."""
    before = load_skill(skill_dir)
    (skill_dir / "SKILL.md").write_text(
        SKILL_MD.replace(
            "description: Reviews a codebase for auth defects.",
            "description: >-\n  Reviews a codebase\n  for auth defects.",
        ),
        encoding="utf-8",
    )
    assert load_skill(skill_dir).description_digest == before.description_digest


def test_normalize_description_collapses_whitespace() -> None:
    assert normalize_description("  a\n  b\tc  ") == "a b c"


def test_a_symlink_is_hashed_not_followed(tmp_path: Path) -> None:
    """A package linking to a host file must hash the link — following it would make the
    digest depend on the host and would hide the link itself."""
    root = tmp_path / "linky"
    root.mkdir()
    (root / "SKILL.md").write_text("---\nname: linky\n---\n", encoding="utf-8")
    (root / "sneaky.md").symlink_to("/etc/passwd")

    package = load_skill(root)
    link = next(record for record in package.files if record.path == "sneaky.md")
    assert link.is_symlink
    assert link.symlink_target == "/etc/passwd"


# ---------------------------------------------------------------------------
# Payload allowlist
# ---------------------------------------------------------------------------


def test_nothing_under_evals_enters_the_payload(skill_dir: Path) -> None:
    """§3.5: a skill that can see the test machinery can behave only while observed."""
    package = load_skill(skill_dir)
    assert not any(path.startswith(EVALS_DIR) for path in package.payload.included)
    assert set(package.payload.excluded_machinery) == {
        "evals/scenarios.yaml",
        "evals/fixtures/seed.txt",
    }


def test_the_payload_holds_what_a_harness_would_load(skill_dir: Path) -> None:
    package = load_skill(skill_dir)
    assert set(package.payload.included) == {
        "SKILL.md",
        "reference/checklist.md",
        "scripts/scan.py",
    }


def test_unmatched_files_are_reported_rather_than_silently_dropped(skill_dir: Path) -> None:
    """An allowlist fails closed; the cost is that exclusions have to be visible."""
    (skill_dir / "data").mkdir()
    (skill_dir / "data" / "table.csv").write_text("a,b\n", encoding="utf-8")

    package = load_skill(skill_dir)
    assert package.payload.excluded_unmatched == ("data/table.csv",)
    assert any("payload allowlist did not match" in problem for problem in package.problems)


def test_a_bare_pattern_applies_at_the_root_only() -> None:
    allowlist = PayloadAllowlist()
    assert allowlist.matches("NOTES.md")
    assert not allowlist.matches("data/notes.md")


def test_evals_is_excluded_even_if_a_pattern_would_match_it() -> None:
    allowlist = PayloadAllowlist(patterns=("**", "*.yaml"))
    assert not allowlist.matches("evals/manifest.yaml")


# ---------------------------------------------------------------------------
# Inventory and estimates
# ---------------------------------------------------------------------------


def test_executables_are_inventoried_with_their_interpreter(skill_dir: Path) -> None:
    package = load_skill(skill_dir)
    script = next(item for item in package.executables if item.path == "scripts/scan.py")
    assert script.interpreter == "python"
    assert script.source == "shebang"
    assert script.in_payload


@pytest.mark.parametrize(
    ("first_line", "path", "expected", "source"),
    [
        ("#!/usr/bin/env python3\n", "s", "python", "shebang"),
        ("#!/bin/bash\n", "s", "bash", "shebang"),
        ("#!/usr/bin/env -S node --flag\n", "s", "node", "shebang"),
        (None, "run.sh", "sh", "extension"),
        (None, "notes.md", None, "unknown"),
    ],
)
def test_interpreter_detection(
    first_line: str | None, path: str, expected: str | None, source: str
) -> None:
    interpreter, detected_source, _ = detect_interpreter(first_line, path)
    assert interpreter == expected
    assert detected_source == source


def test_a_script_under_evals_is_marked_as_not_installed(skill_dir: Path) -> None:
    (skill_dir / "evals" / "helper.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    package = load_skill(skill_dir)
    helper = next(item for item in package.executables if item.path == "evals/helper.py")
    assert not helper.in_payload


def test_token_estimates_measure_the_body_not_the_frontmatter(skill_dir: Path) -> None:
    package = load_skill(skill_dir)
    assert package.body_tokens > 0
    assert package.token_estimates["reference/checklist.md"] > 0
    # The frontmatter is metadata the harness reads, not context the model pays for.
    assert package.body_tokens < estimate_tokens(SKILL_MD)


def test_estimate_tokens_handles_empty_text() -> None:
    assert estimate_tokens("") == 0
    assert estimate_tokens("   \n ") == 0


# ---------------------------------------------------------------------------
# Review attestation binding (§6.3)
# ---------------------------------------------------------------------------


def test_the_example_skill_loads_with_its_manifest_and_scenarios() -> None:
    package = load_skill(EXAMPLE_SKILL)
    assert package.manifest is not None
    assert package.scenarios is not None
    assert len(package.scenarios.scenarios) == 5


def test_a_review_recorded_against_other_bytes_is_stale() -> None:
    """Editing a skill after review does not carry the approval forward."""
    package = load_skill(EXAMPLE_SKILL)
    assert package.review_state() == "stale"


def test_a_review_matching_the_current_digest_is_current(tmp_path: Path) -> None:
    """Recording the attestation digest must reach a fixed point (§6.3).

    §6.2 records the digest inside a file the digest covers. Read literally that is
    self-referential and no review could ever be `current`; the attestation digest blanks
    the recorded value before hashing, which is what makes writing it in stable.
    """
    root = tmp_path / "reviewed"
    shutil.copytree(EXAMPLE_SKILL, root)
    manifest = root / "evals" / "manifest.yaml"

    digest = load_skill(root).attestation_digest
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000", digest
        ),
        encoding="utf-8",
    )

    package = load_skill(root)
    assert package.review_state() == "current"
    assert package.attestation_digest == digest
    assert package.review_age_days(dt.date(2026, 8, 4)) == 21


def test_editing_a_reviewed_skill_makes_the_review_stale(tmp_path: Path) -> None:
    root = tmp_path / "reviewed"
    shutil.copytree(EXAMPLE_SKILL, root)
    manifest = root / "evals" / "manifest.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            load_skill(root).attestation_digest,
        ),
        encoding="utf-8",
    )
    assert load_skill(root).review_state() == "current"

    (root / "SKILL.md").write_text(
        (root / "SKILL.md").read_text(encoding="utf-8") + "\nAlso read the environment.\n",
        encoding="utf-8",
    )
    assert load_skill(root).review_state() == "stale"


def test_a_skill_with_no_manifest_has_no_review() -> None:
    package = load_skill(EXAMPLE_SKILL, load_evals=False)
    assert package.manifest is None
    assert package.review_state() == "absent"
    assert package.review_age_days(dt.date(2026, 8, 4)) is None
