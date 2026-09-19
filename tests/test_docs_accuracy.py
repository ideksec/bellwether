"""The documented counts are asserted against the code that produces them.

Both numbers in this file were wrong in the change that introduced them, in the same direction:
they counted a withdrawn control as closed. `docs/STATUS.md` said two declared controls now gate
when one does; `docs/spec-notes.md` said seven dispositions remain inert and listed seven, leaving
out `harness_state_write` — whose gate had been withdrawn two paragraphs earlier for never being
able to fire, and which is therefore *more* inert, not less.

In a project whose thesis is that a declared control doing nothing must be named, undercounting
the inert set is the one direction the error must not go. A prose number nobody checks drifts on
the first change; these now fail the build instead.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from bellwether.cli.orchestrator import ENFORCED_SECURITY_RUNTIME_DISPOSITIONS
from bellwether.config.models.policy import SecurityRuntimeGate

_ROOT = Path(__file__).resolve().parent.parent


def _inert() -> list[str]:
    return sorted(
        field
        for field in SecurityRuntimeGate.model_fields
        if field not in ENFORCED_SECURITY_RUNTIME_DISPOSITIONS
    )


def test_the_withdrawn_disposition_is_still_counted_as_inert() -> None:
    """The specific miscount, pinned.

    `harness_state_write` is configured in the shipped policy and no gate reads it. It belongs
    on the inert list exactly because its gate was withdrawn.
    """
    assert "harness_state_write" in _inert()
    assert "harness_state_write" not in ENFORCED_SECURITY_RUNTIME_DISPOSITIONS


def test_spec_notes_states_the_real_inert_count() -> None:
    notes = (_ROOT / "docs" / "spec-notes.md").read_text(encoding="utf-8")
    match = re.search(r"\*\*(\w+)\*\* dispositions remain inert — (\w+) enforced of (\w+)", notes)
    assert match is not None, "the inert-disposition sentence in spec-notes has moved or changed"
    words = {
        "four": 4,
        "five": 5,
        "six": 6,
        "seven": 7,
        "eight": 8,
        "nine": 9,
        "ten": 10,
        "eleven": 11,
        "twelve": 12,
        "thirteen": 13,
    }
    stated_inert, stated_enforced, stated_total = (words[group.lower()] for group in match.groups())
    assert stated_inert == len(_inert())
    assert stated_enforced == len(ENFORCED_SECURITY_RUNTIME_DISPOSITIONS)
    assert stated_total == len(SecurityRuntimeGate.model_fields)


def test_spec_notes_names_every_inert_disposition() -> None:
    """A count that is right while the list is short is still telling an operator the wrong thing."""
    section = (
        (_ROOT / "docs" / "spec-notes.md")
        .read_text(encoding="utf-8")
        .split("### What this leaves")[-1]
    )
    missing = [name for name in _inert() if f"`{name}`" not in section]
    assert not missing, f"inert dispositions not named in spec-notes: {missing}"


def test_readme_gate_list_matches_the_composed_verdict(tmp_path: Path) -> None:
    """README's `security_runtime.*` bullets against the gates the pipeline actually composes.

    Twice now this test has claimed a code linkage it did not have. The first version compared
    README to a hard-coded Python set; the second to the *committed* demo verdicts — two
    committed literals agreeing with each other. Renaming the composed gate left both green,
    because nothing in this file ran the pipeline: the linkage was supplied by a different test
    (`test_demo.py`, which byte-compares the committed artifacts against a regeneration), so
    this one only caught README drift after someone remembered to regenerate.

    It now composes. `bellwether demo` takes half a second and runs the real gate assembly, so
    a renamed or dropped gate fails here, in the file whose whole subject is claims nobody
    verifies.
    """
    from bellwether.cli.demo import generate_demo

    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"\*\*(security_runtime\.[a-z_]+)\*\*", readme))

    generate_demo(
        skills_root=_ROOT / "examples" / "skills",
        out_dir=tmp_path / "out",
        tmp_dir=tmp_path / "traces",
    )
    composed: set[str] = set()
    for verdict in sorted((tmp_path / "out").glob("*/verdict.json")):
        payload = json.loads(verdict.read_text(encoding="utf-8"))
        composed |= {
            gate["name"]
            for gate in payload["gates"]
            if gate["name"].startswith("security_runtime.")
        }
    assert composed, "the demo composed no security_runtime gate"
    assert documented == composed


def _collected(marker: str | None) -> int:
    """How many tests pytest really collects, optionally under a marker expression."""
    import subprocess
    import sys

    argv = [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"]
    if marker is not None:
        argv += ["-m", marker]
    argv.append(str(_ROOT / "tests"))
    completed = subprocess.run(argv, capture_output=True, text=True, cwd=_ROOT, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    total = 0
    for line in completed.stdout.splitlines():
        _, separator, count = line.rpartition(": ")
        if separator and count.strip().isdigit():
            total += int(count)
    assert total, f"collection produced no counts:\n{completed.stdout}"
    return total


def test_status_states_the_real_test_counts() -> None:
    """The STATUS test-count line, against a real collection.

    This line drifted by four inside the very change that added this file — written before the
    last four tests were added and never revisited. A prose number nobody checks is exactly
    what the rest of this file is about, so it is checked.
    """
    status = (_ROOT / "docs" / "STATUS.md").read_text(encoding="utf-8")
    match = re.search(
        r"(\d+) tests: (\d+) offline, (\d+) under the `docker` mark",
        status,
    )
    assert match is not None, "the test-count line in STATUS has moved or changed shape"
    stated_total, stated_offline, stated_docker = (int(group) for group in match.groups())

    docker = _collected("docker")
    offline = _collected("not docker")
    assert (stated_docker, stated_offline, stated_total) == (docker, offline, docker + offline)
