"""Both content identities must distinguish the same properties, checked against one corpus.

A digest here is not a checksum for transport. ``payload_digest`` is what a review attestation
binds to (§6.3) and what the run cache keys on (§19.2); ``fixture_digest`` is the provenance of
the tree the sandbox started from and the other half of the same cache key. Two inputs the
container treats differently sharing one digest means a review carries forward across a change,
and a cached trace is replayed for a run that was never made.

The two were written months apart and drifted. A symlink/regular-file collision was found and
closed in ``skill/digests.py`` (``DIGEST_FORMAT/3``) and left open in ``sandbox/fixtures.py``,
where an independent review found it again; neither carried the executable bit, though both
stagers preserve it. Fixing one place and calling the class of bug closed is how the second
instance survives — so the properties are listed once, here, and every identity is held to all
of them.

Adding a property to this corpus is how you find out which identities do not yet carry it.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from bellwether.sandbox import fixture_digest
from bellwether.skill.digests import merkle_digest, read_file_records

#: The identity functions under test: name → (tree → digest).
IDENTITIES: dict[str, Callable[[Path], str]] = {
    "skill payload (§6.3, §19.2)": lambda root: merkle_digest(read_file_records(root)),
    "fixture tree (§9.1, §19.2)": fixture_digest,
}


def _pair(tmp_path: Path, build_a: Callable[[Path], None], build_b: Callable[[Path], None]):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    build_a(a)
    build_b(b)
    return a, b


def _symlink_vs_marker_file(tmp_path: Path) -> tuple[Path, Path]:
    """A symlink, against a regular file whose *content* is the symlink's stand-in text.

    Both identities hash a link as ``symlink:<target>``, which is byte-identical to that file's
    content — so without a per-entry kind tag the two trees hash the same.
    """
    return _pair(
        tmp_path,
        lambda root: (root / "run.sh").symlink_to("helper.sh"),
        lambda root: (root / "run.sh").write_text("symlink:helper.sh", encoding="utf-8"),
    )


def _executable_vs_inert(tmp_path: Path) -> tuple[Path, Path]:
    """The same bytes at 0644 and 0755 — inert text against something the agent can run.

    §9.3 normalises the mode to one or the other and both stagers preserve it, so the two trees
    behave differently in the container and must not share an identity.
    """

    def build(mode: int) -> Callable[[Path], None]:
        def make(root: Path) -> None:
            script = root / "build.sh"
            script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
            script.chmod(mode)

        return make

    return _pair(tmp_path, build(0o644), build(0o755))


def _different_content(tmp_path: Path) -> tuple[Path, Path]:
    return _pair(
        tmp_path,
        lambda root: (root / "a.txt").write_text("one", encoding="utf-8"),
        lambda root: (root / "a.txt").write_text("two", encoding="utf-8"),
    )


def _different_path(tmp_path: Path) -> tuple[Path, Path]:
    return _pair(
        tmp_path,
        lambda root: (root / "a.txt").write_text("same", encoding="utf-8"),
        lambda root: (root / "b.txt").write_text("same", encoding="utf-8"),
    )


def _link_target(tmp_path: Path) -> tuple[Path, Path]:
    return _pair(
        tmp_path,
        lambda root: (root / "run.sh").symlink_to("helper.sh"),
        lambda root: (root / "run.sh").symlink_to("elsewhere.sh"),
    )


#: Each entry builds two trees that a reader would call *different inputs*. Every identity must
#: agree, or it is saying two things the container distinguishes are the same thing.
DISTINCT_TREES = [
    pytest.param(_symlink_vs_marker_file, id="symlink-vs-file-holding-its-marker"),
    pytest.param(_executable_vs_inert, id="executable-bit"),
    pytest.param(_different_content, id="content"),
    pytest.param(_different_path, id="path"),
    pytest.param(_link_target, id="symlink-target"),
]


@pytest.mark.parametrize("identity", list(IDENTITIES), ids=list(IDENTITIES))
@pytest.mark.parametrize("build", DISTINCT_TREES)
def test_every_identity_distinguishes_every_property(
    identity: str, build: Callable[[Path], tuple[Path, Path]], tmp_path: Path
) -> None:
    a, b = build(tmp_path)
    digest = IDENTITIES[identity]

    assert digest(a) != digest(b), (
        f"{identity} gives the same digest to two trees the container treats differently. "
        "Two inputs sharing one identity means a review attestation carries forward across a "
        "change (§6.3) and a cached trace is replayed for a run that was never made (§19.2)."
    )


@pytest.mark.parametrize("identity", list(IDENTITIES), ids=list(IDENTITIES))
def test_every_identity_is_stable_for_identical_trees(identity: str, tmp_path: Path) -> None:
    """The other half. An identity that changed on identical input would miss the cache every
    time and make §24's byte-comparisons meaningless — and would pass every test above."""
    digest = IDENTITIES[identity]
    a, b = _pair(
        tmp_path,
        lambda root: (root / "a.txt").write_text("same", encoding="utf-8"),
        lambda root: (root / "a.txt").write_text("same", encoding="utf-8"),
    )

    assert digest(a) == digest(b)
