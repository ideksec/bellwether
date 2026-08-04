"""Determinism primitives (§24).

Bellwether's own output MUST be byte-identical given identical input traces, excluding
timestamps and IDs. That is not achievable by intention; it requires explicit rules, and
each rule needs a home so it is used rather than remembered:

* all sets serialised in sorted order — :func:`sorted_unique`;
* fixed float formatting **at serialisation**, never at computation — :func:`round6`,
  applied by :func:`canonicalize` and nowhere else;
* no reliance on :func:`hash` ordering — :func:`stable_hash` is SHA-256 based, and CI
  sets ``PYTHONHASHSEED=0`` *and* does not depend on it;
* dict key order fixed by schema, not insertion — :func:`canonical_json` sorts keys;
* locale-independent number formatting — Python's float repr already is, and
  :func:`format_float` is the single place that would change if that stopped being true;
* sorted file-walk order for package digests (§6.1) — :func:`sorted_walk`;
* seeded and recorded RNG for the §12.3 bootstrap and §3.5 canary randomisation —
  :class:`SeededRng`.

This module is a leaf: it imports nothing from the rest of the package.

Retrofitting determinism into a codebase that assumed it is a rewrite. Use these from
the first commit of every module that serialises anything.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Hashable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "FLOAT_PLACES",
    "SeededRng",
    "canonical_json",
    "canonicalize",
    "format_float",
    "round6",
    "sorted_unique",
    "sorted_walk",
    "stable_hash",
    "stable_hash_bytes",
]

#: Decimal places applied to every float at serialisation. Applying this at computation
#: time instead accumulates rounding into the metrics, which is how a "deterministic"
#: pipeline ends up with results that depend on the order operations were applied in.
FLOAT_PLACES = 6


def round6(value: float) -> float:
    """Round a float for serialisation. Never call this mid-computation.

    Normalises negative zero, which otherwise serialises as ``-0.0`` and makes two
    numerically identical outputs differ byte-wise.
    """
    rounded = round(value, FLOAT_PLACES)
    return 0.0 if rounded == 0 else rounded


def format_float(value: float) -> str:
    """Format a float for display, independent of locale.

    Python's float formatting is already locale-independent; this function exists so the
    assumption has one place to be corrected if that ever changes.
    """
    return repr(round6(value))


def sorted_unique[T: Hashable](values: Iterable[T]) -> list[T]:
    """Deduplicate and sort, for any set that reaches an artifact.

    Sorting is by the natural order of the elements. Where elements are not mutually
    comparable the caller must project them to a sortable key first — an implicit
    fallback here would reintroduce exactly the ordering ambiguity this prevents.
    """
    return sorted(set(values))  # type: ignore[type-var]


def sorted_walk(root: Path, *, follow_symlinks: bool = False) -> list[Path]:
    """Return every regular file under ``root``, relative to it, in a stable order.

    Filesystem iteration order differs between machines and between filesystems. A digest
    computed over an unsorted walk is not reproducible, and every cache key derived from
    it becomes machine-local (§6.1, §24). Ordering is by POSIX path string so it does not
    depend on the platform separator.

    Symlinks are not followed by default: a skill package containing a symlink to
    ``/etc/passwd`` should hash the link, not the target.
    """
    files: list[Path] = []
    for entry in _iter_files(root, follow_symlinks=follow_symlinks):
        files.append(entry.relative_to(root))
    return sorted(files, key=lambda path: path.as_posix())


def _iter_files(root: Path, *, follow_symlinks: bool) -> Iterator[Path]:
    for entry in sorted(root.iterdir(), key=lambda path: path.name):
        if entry.is_symlink() and not follow_symlinks:
            yield entry
        elif entry.is_dir():
            yield from _iter_files(entry, follow_symlinks=follow_symlinks)
        elif entry.is_file():
            yield entry


def stable_hash_bytes(data: bytes) -> str:
    """SHA-256 of ``data``, hex, prefixed with its algorithm.

    Used everywhere a stable identity is needed. Never use the builtin :func:`hash`:
    it is salted per process and ordering derived from it is not reproducible.
    """
    return "sha256:" + hashlib.sha256(data).hexdigest()


def stable_hash(data: str | bytes) -> str:
    """SHA-256 of ``data``, encoding str as UTF-8 first."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return stable_hash_bytes(data)


def canonicalize(value: Any) -> Any:
    """Convert a value tree into its canonical, serialisable form.

    Sets become sorted lists, floats are rounded to :data:`FLOAT_PLACES`, mappings keep
    their keys as-is (ordering is applied by :func:`canonical_json`), and tuples become
    lists so that a round-trip through JSON is a fixed point.
    """
    if isinstance(value, bool) or value is None or isinstance(value, int | str):
        return value
    if isinstance(value, float):
        return round6(value)
    if isinstance(value, Mapping):
        return {str(key): canonicalize(item) for key, item in value.items()}
    if isinstance(value, set | frozenset):
        return [canonicalize(item) for item in sorted(value)]
    if isinstance(value, Sequence):
        return [canonicalize(item) for item in value]
    if isinstance(value, Path):
        return value.as_posix()
    raise TypeError(f"cannot canonicalize {type(value).__name__} for serialisation")


def canonical_json(value: Any, *, indent: int | None = None) -> str:
    """Serialise ``value`` deterministically.

    Keys sorted, floats rounded at this boundary and only here, no ASCII escaping so the
    bytes do not depend on the input alphabet, and NaN/Infinity rejected rather than
    emitted as non-standard JSON tokens.
    """
    return json.dumps(
        canonicalize(value),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        indent=indent,
        separators=(",", ":") if indent is None else (",", ": "),
    )


@dataclass(frozen=True)
class SeededRng:
    """A random source whose seed travels with its output.

    Every use of randomness in Bellwether — canary markers and paths (§3.5), fixture
    directory names, bootstrap resampling (§12.3) — MUST be seeded from a value recorded
    in the run header, so an evaluation is reproducible from its own artifacts.

    ``label`` separates independent streams drawn from the same evaluation seed, so
    adding a new use of randomness cannot shift the values another use would have drawn.
    """

    seed: int
    label: str

    def stream(self) -> random.Random:
        """Return a fresh generator for this ``(seed, label)`` pair."""
        derived = stable_hash(f"{self.seed}:{self.label}")
        return random.Random(int(derived.removeprefix("sha256:")[:16], 16))

    def choice[T](self, population: Sequence[T]) -> T:
        return self.stream().choice(population)

    def sample[T](self, population: Sequence[T], k: int) -> list[T]:
        return self.stream().sample(list(population), k)

    def token(self, length: int = 32, *, alphabet: str | None = None) -> str:
        """Draw an opaque token with no fixed prefix or recognisable structure (§3.5)."""
        chars = alphabet or "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        stream = self.stream()
        return "".join(stream.choice(chars) for _ in range(length))
