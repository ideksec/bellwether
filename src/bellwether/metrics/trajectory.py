"""Trajectory variance: cluster first, then measure (§13.4).

Revision 1 computed entropy over exact canonical step-sequence equality, and with any
nontrivial agent at small N five distinct sequences is the common outcome — which gives
``H_traj = 1.0`` for essentially every skill, a metric that carries no signal while
``max_trajectory_entropy: 0.7`` blocks everything. The fix is to cluster near-identical
sequences first, then measure over clusters.

Two rules make the figures trustworthy:

- **Gate on modal cluster share and mean edit distance, never on entropy.** ``H_traj`` is
  informational only and *not comparable across N* — the same qualitative behaviour (one
  dominant path, one deviation) scores differently at N = 3, 5, 10 — and the sequential
  design produces a different N per set as a matter of course. Modal cluster share is
  bounded, intuitive, and comparable across N, so it is what leads the section and feeds
  the BCI.
- **Report against the noise floor.** A skill whose measured dispersion is at or below the
  instrument's own noise floor (§24) is reported ``at_noise_floor``, never as a precise
  small number — reporting "2 clusters" when the instrument produces 2 on identical input
  is a fabrication.

Clustering is single-linkage at a distance cut, which is exactly the connected components
of the graph joining sequence pairs within ``trajectory_cluster_threshold``. That is
order-independent by construction; the *output* ordering (cluster order, representatives)
is made deterministic by lexicographic sorting, as §24's byte-identical test requires.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from rapidfuzz.distance import Levenshtein

from bellwether.determinism import round6
from bellwether.trace import StepSignature

__all__ = [
    "TrajectoryCluster",
    "TrajectoryMetrics",
    "normalised_edit_distance",
    "summarise_trajectory",
]

#: One sequence rendered as a tuple of opaque tokens for edit distance. Two signatures
#: are equal iff every field matches; the token is their stable string join.
_Sequence = tuple[str, ...]


def _tokens(sequence: Sequence[StepSignature]) -> _Sequence:
    return tuple("\x1f".join("" if part is None else part for part in step) for step in sequence)


def normalised_edit_distance(a: Sequence[StepSignature], b: Sequence[StepSignature]) -> float:
    """Levenshtein over step-signature tokens, divided by the longer length (§13.4).

    Two empty sequences are identical → 0.0. Otherwise the result is in ``(0, 1]`` and is
    symmetric, so the pairwise matrix is a metric the clustering can trust.
    """
    ta, tb = _tokens(a), _tokens(b)
    longest = max(len(ta), len(tb))
    if longest == 0:
        return 0.0
    return round6(Levenshtein.distance(ta, tb) / longest)


@dataclass(frozen=True)
class TrajectoryCluster:
    """One cluster of near-identical step sequences."""

    #: Indices of the runs in this cluster, sorted.
    members: tuple[int, ...]
    #: The lexicographically smallest sequence in the cluster, its representative.
    representative: tuple[StepSignature, ...]
    mean_intra_distance: float

    @property
    def size(self) -> int:
        return len(self.members)


@dataclass(frozen=True)
class TrajectoryMetrics:
    """The §13.4 trajectory figures for one repetition set."""

    clusters: tuple[TrajectoryCluster, ...]
    distinct_clusters: int
    modal_cluster_share: float | None
    mean_pairwise_distance: float | None
    #: Informational only, never gated, and displayed with N adjacent (§13.4).
    h_traj: float | None
    mean_step_count: float
    step_count_cv: float
    at_noise_floor: bool
    n: int
    threshold: float


def summarise_trajectory(
    sequences: Sequence[Sequence[StepSignature]],
    *,
    threshold: float = 0.2,
    noise_floor_distance: float | None = None,
) -> TrajectoryMetrics:
    """Cluster the step sequences and compute the §13.4 figures.

    Args:
        sequences: One canonical step sequence per evaluable run.
        threshold: ``trajectory_cluster_threshold`` — the single-linkage cut, default 0.2.
        noise_floor_distance: The calibrated §24 noise floor for mean pairwise distance.
            Where the measured dispersion is at or below it, ``at_noise_floor`` is set and
            the caller must render the qualitative label rather than the precise figures.
    """
    n = len(sequences)
    seqs = [tuple(s) for s in sequences]

    # Pairwise distances, and the single-linkage adjacency at the cut.
    distance: dict[tuple[int, int], float] = {}
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        parent[find(x)] = find(y)

    for i in range(n):
        for j in range(i + 1, n):
            d = normalised_edit_distance(seqs[i], seqs[j])
            distance[(i, j)] = d
            if d <= threshold:
                union(i, j)

    groups: dict[int, list[int]] = {}
    for index in range(n):
        groups.setdefault(find(index), []).append(index)

    clusters: list[TrajectoryCluster] = []
    for members in groups.values():
        members_sorted = tuple(sorted(members))
        representative = min((seqs[m] for m in members_sorted), key=lambda s: _tokens(s))
        intra = [
            distance[(min(i, j), max(i, j))]
            for a, i in enumerate(members_sorted)
            for j in members_sorted[a + 1 :]
        ]
        clusters.append(
            TrajectoryCluster(
                members=members_sorted,
                representative=representative,
                mean_intra_distance=round6(sum(intra) / len(intra)) if intra else 0.0,
            )
        )
    # Deterministic output order: by representative sequence, lexicographically (§24).
    clusters.sort(key=lambda c: _tokens(c.representative))

    modal_share = round6(max(c.size for c in clusters) / n) if clusters else None
    all_pairs = list(distance.values())
    mean_pairwise = round6(sum(all_pairs) / len(all_pairs)) if all_pairs else None
    h_traj = _cluster_entropy([c.size for c in clusters], n)

    counts = [len(s) for s in seqs]
    mean_len = sum(counts) / n if n else 0.0
    cv = _coefficient_of_variation(counts, mean_len)

    at_floor = (
        noise_floor_distance is not None
        and mean_pairwise is not None
        and mean_pairwise <= noise_floor_distance
    )

    return TrajectoryMetrics(
        clusters=tuple(clusters),
        distinct_clusters=len(clusters),
        modal_cluster_share=modal_share,
        mean_pairwise_distance=mean_pairwise,
        h_traj=h_traj,
        mean_step_count=round6(mean_len),
        step_count_cv=cv,
        at_noise_floor=at_floor,
        n=n,
        threshold=threshold,
    )


def _cluster_entropy(sizes: list[int], n: int) -> float | None:
    """``−Σ pᵢ log₂ pᵢ / log₂ N`` over clusters (§13.4).

    ``None`` at ``N ≤ 1``: the denominator ``log₂ N`` is zero and there is no variance to
    measure (§11.4). ``0·log₂0 = 0`` by the §11.4 convention.
    """
    if n <= 1 or not sizes:
        return None
    entropy = 0.0
    for size in sizes:
        p = size / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round6(entropy / math.log2(n))


def _coefficient_of_variation(counts: list[int], mean: float) -> float:
    """Population CV of the step counts. Zero where the mean is zero (all-empty)."""
    if not counts or mean == 0:
        return 0.0
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    return round6(math.sqrt(variance) / mean)
