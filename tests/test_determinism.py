"""Determinism rules (§24), tested where they are implemented rather than assumed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bellwether.determinism import (
    SeededRng,
    canonical_json,
    canonicalize,
    format_float,
    round6,
    sorted_unique,
    sorted_walk,
    stable_hash,
)


def test_sorted_walk_is_independent_of_creation_order(tmp_path: Path) -> None:
    """A digest over an unsorted walk is not reproducible across machines (§6.1)."""
    first = tmp_path / "a"
    second = tmp_path / "b"
    for root, order in ((first, "zebra alpha middle"), (second, "middle zebra alpha")):
        for name in order.split():
            path = root / name[0] / f"{name}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name, encoding="utf-8")

    assert sorted_walk(first) == sorted_walk(second)
    assert [path.as_posix() for path in sorted_walk(first)] == [
        "a/alpha.md",
        "m/middle.md",
        "z/zebra.md",
    ]


def test_sorted_walk_does_not_follow_symlinks(tmp_path: Path) -> None:
    """A skill containing a link to a system file should hash the link, not the target."""
    (tmp_path / "real.txt").write_text("x", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    walked = {path.as_posix() for path in sorted_walk(tmp_path)}
    assert walked == {"real.txt", "link.txt"}


def test_round6_normalises_negative_zero() -> None:
    """``-0.0`` and ``0.0`` are numerically equal and must serialise identically."""
    assert canonical_json({"x": round6(-1e-12)}) == canonical_json({"x": 0.0})
    assert "-0" not in canonical_json({"x": -1e-12})


@given(st.floats(allow_nan=False, allow_infinity=False, width=32))
def test_round6_is_idempotent(value: float) -> None:
    assert round6(round6(value)) == round6(value)


def test_rounding_happens_at_serialisation_only() -> None:
    """§24: fixed float formatting at serialisation, never at computation."""
    accumulated = sum(1 / 3 for _ in range(3))
    assert accumulated == pytest.approx(1.0)
    assert json.loads(canonical_json({"x": accumulated}))["x"] == 1.0


def test_canonical_json_sorts_keys_and_sets() -> None:
    left = canonical_json({"b": {"z", "a", "m"}, "a": 1})
    right = canonical_json({"a": 1, "b": {"m", "a", "z"}})
    assert left == right
    assert left == '{"a":1,"b":["a","m","z"]}'


def test_canonical_json_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError, match="Out of range"):
        canonical_json({"x": float("inf")})


def test_canonicalize_rejects_types_it_cannot_order() -> None:
    with pytest.raises(TypeError, match="cannot canonicalize"):
        canonicalize(object())


def test_canonicalize_refuses_raw_bytes() -> None:
    """Bytes are a Sequence, so without an explicit branch a blob becomes a list of
    integers: valid JSON, silently useless, and invisible in a trace."""
    with pytest.raises(TypeError, match="encode them first"):
        canonical_json({"blob": b"\x00\x01"})


def test_canonicalize_is_a_fixed_point_through_json() -> None:
    value = {"a": (1, 2), "b": {"x"}, "c": Path("src/bellwether")}
    once = canonical_json(value)
    assert canonical_json(json.loads(once)) == once


def test_sorted_unique_deduplicates_and_orders() -> None:
    assert sorted_unique(["b", "a", "b"]) == ["a", "b"]


def test_stable_hash_does_not_use_the_builtin_hash() -> None:
    """Builtin ``hash`` is salted per process; ordering derived from it is not stable."""
    import hashlib

    digest = stable_hash("bellwether")
    assert digest == stable_hash(b"bellwether")
    assert digest == "sha256:" + hashlib.sha256(b"bellwether").hexdigest()
    assert len(digest) == len("sha256:") + 64


def test_format_float_is_locale_independent() -> None:
    assert format_float(1.5) == "1.5"
    assert "," not in format_float(1234.5)


def test_seeded_rng_is_reproducible_and_stream_separated() -> None:
    """§3.5 and §12.3: randomness is seeded, recorded, and separated by use."""
    assert (
        SeededRng(20260804, "canary-markers").token()
        == SeededRng(20260804, "canary-markers").token()
    )
    assert (
        SeededRng(20260804, "canary-markers").token() != SeededRng(20260804, "canary-paths").token()
    )
    assert (
        SeededRng(20260804, "canary-markers").token()
        != SeededRng(20260805, "canary-markers").token()
    )


def test_successive_draws_from_one_stream_differ() -> None:
    """The regression test for a stream that re-seeded on every call.

    Planting five canaries from one stream would otherwise have planted five identical
    markers — the predictable-marker tell §3.5 exists to remove — while looking correct.
    """
    rng = SeededRng(20260804, "canary-markers")
    assert len({rng.token(16) for _ in range(20)}) == 20

    chooser = SeededRng(20260804, "canary-paths")
    assert len({chooser.choice("abcdefghij") for _ in range(10)}) > 1


def test_two_streams_with_the_same_label_produce_the_same_sequence() -> None:
    """Reproducibility is sequence equality between instances, not self-repetition."""
    first = SeededRng(20260804, "canary-markers")
    second = SeededRng(20260804, "canary-markers")
    assert [first.token(8) for _ in range(5)] == [second.token(8) for _ in range(5)]


def test_a_derived_stream_is_independent_of_its_parents_position() -> None:
    """Adding a draw to the parent must not shift what a sub-stream yields."""
    untouched = SeededRng(20260804, "eval").derive("canaries").token()

    parent = SeededRng(20260804, "eval")
    parent.token()
    parent.token()
    assert parent.derive("canaries").token() == untouched


def test_canary_tokens_carry_no_fixed_prefix() -> None:
    """A recognisable marker format is how a skill detects that it is observed (§3.5)."""
    tokens = [SeededRng(seed, "canary-markers").token(24) for seed in range(20)]
    assert len({token[:4] for token in tokens}) > 1
    assert all(len(token) == 24 for token in tokens)
