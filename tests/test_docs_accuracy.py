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


def test_readme_gate_list_matches_the_composed_verdict() -> None:
    """README's `security_runtime.*` bullets against the gates the pipeline actually composes."""
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"\*\*(security_runtime\.[a-z_]+)\*\*", readme))
    expected = {
        "security_runtime.egress",
        "security_runtime.canaries",
        "security_runtime.canary_reads",
        "security_runtime.dns",
        "security_runtime.sensitive_directories",
    }
    assert documented == expected
