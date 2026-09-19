"""One corpus of escape spellings, applied to every predicate that decides containment.

Four review rounds on §13.5.4 ended with the same conclusion, recorded in CLAUDE.md: *reduce an
input to what it certainly means, then compare; do not list the ways it can be wrong.* Three of
those four rounds' headline findings were regressions from the previous round's fix in the same
predicate, because a reject-clause always has an unenumerated spelling.

An independent review then found the identical shape in two more places, neither of which had
been part of that arc: a scenario's ``fixture:`` name was joined onto the fixture root with
``/``, so an absolute name replaced the root outright; and a content assertion read its target
path straight off the final workspace, so a symlink the skill planted led out of it.

Both are fixed by normalising — resolve both sides, require that one contains the other — which
is the rule that answers every spelling at once. This file is what keeps that true: a single
corpus of spellings, run against every containment predicate the codebase has. A new predicate
is added here, and a predicate that grows a clever fast path has to keep passing the same list.

The corpus is deliberately not "the ways we have been attacked". It is the ways a path can name
something other than where it appears to point.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bellwether.assertions.engine import _read_contained
from bellwether.cli.fixtures import resolve_fixture
from bellwether.errors import BellwetherError

#: Names that must never resolve inside a root, whatever the predicate. Each is a *spelling*
#: of the same idea, which is the point: a predicate that rejects some of these and not others
#: is enumerating rather than normalising, and the one it misses is the next finding.
ESCAPES = [
    pytest.param("/etc", id="absolute"),
    pytest.param("../outside", id="parent"),
    pytest.param("../../outside", id="grandparent"),
    pytest.param("sub/../../outside", id="parent-after-descent"),
    pytest.param("./../outside", id="dot-then-parent"),
    pytest.param("sub/./../../outside", id="dot-padding"),
    pytest.param(".//..//outside", id="doubled-separators"),
    pytest.param("sub/../sub/../../outside", id="repeated-climb"),
]

#: And names that must resolve *inside* it. Half of a containment test is that it does not
#: refuse legitimate input — a predicate can reach 100% on the list above by rejecting
#: everything, and a containment rule that costs real names gets loosened back into a hole.
CONTAINED = [
    pytest.param("plain", id="plain"),
    pytest.param("nested/deeper", id="nested"),
    pytest.param("./plain", id="leading-dot"),
    pytest.param("nested/../plain", id="climb-that-stays-inside"),
    pytest.param("nested//deeper", id="doubled-separator-inside"),
]


def _fixture_tree(tmp_path: Path) -> Path:
    """A skill whose fixture root holds the contained names, beside an out-of-tree directory."""
    skill = tmp_path / "skill"
    root = skill / "evals" / "fixtures"
    for name in ("plain", "nested/deeper"):
        (root / name).mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.txt").write_text("SYNTHETIC", encoding="utf-8")
    return skill


@pytest.mark.parametrize("name", ESCAPES)
def test_a_fixture_name_cannot_escape_its_root(name: str, tmp_path: Path) -> None:
    with pytest.raises(BellwetherError, match="resolves outside the fixture roots"):
        resolve_fixture(_fixture_tree(tmp_path), name)


@pytest.mark.parametrize("name", CONTAINED)
def test_a_contained_fixture_name_still_resolves(name: str, tmp_path: Path) -> None:
    assert resolve_fixture(_fixture_tree(tmp_path), name).path.exists()


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    (workspace / "nested").mkdir(parents=True)
    for name in ("plain", "nested/deeper"):
        (workspace / name).write_text("inside", encoding="utf-8")
    (tmp_path / "outside").mkdir(exist_ok=True)
    (tmp_path / "outside" / "secret.txt").write_text("SYNTHETIC", encoding="utf-8")
    return workspace


@pytest.mark.parametrize("name", ESCAPES)
def test_an_assertion_read_cannot_escape_the_workspace(name: str, tmp_path: Path) -> None:
    assert _read_contained(_workspace(tmp_path), name) is None


@pytest.mark.parametrize("name", CONTAINED)
def test_an_assertion_read_still_reaches_a_contained_path(name: str, tmp_path: Path) -> None:
    assert _read_contained(_workspace(tmp_path), name) == "inside"


def test_a_symlink_out_of_the_workspace_is_refused_by_the_same_rule(tmp_path: Path) -> None:
    """The spelling no lexical check can see: the name is plain, and only resolving it shows
    where it lands. This is why the corpus is applied to a *normalising* predicate rather than
    to a list of forbidden characters."""
    workspace = _workspace(tmp_path)
    (workspace / "innocent").symlink_to(tmp_path / "outside" / "secret.txt")

    assert _read_contained(workspace, "innocent") is None


def test_a_symlink_out_of_the_fixture_root_is_refused_by_the_same_rule(tmp_path: Path) -> None:
    skill = _fixture_tree(tmp_path)
    (skill / "evals" / "fixtures" / "innocent").symlink_to(
        tmp_path / "outside", target_is_directory=True
    )

    with pytest.raises(BellwetherError, match="resolves outside the fixture roots"):
        resolve_fixture(skill, "innocent")
