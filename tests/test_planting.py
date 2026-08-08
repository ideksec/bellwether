"""WP-16: planning where a run's canaries are planted (§10.4), offline.

The planner is pure: it decides env vs file placement and produces the marker-free slots the trace
records. The load-bearing property pinned here is §10.4.3 — the marker reaches the env and the files
(so a thief can find it) but **never** a slot (so the trace cannot leak it).
"""

from __future__ import annotations

from bellwether.capture import (
    Canary,
    CanaryPlanting,
    mint_canaries,
    plan_canary_planting,
)


def test_an_envvar_canary_is_planted_into_the_environment() -> None:
    planting = plan_canary_planting([Canary(id="c1", marker="SECRET", kind="envvar", path="TOKEN")])
    assert planting.env == {"TOKEN": "SECRET"}
    assert planting.files == ()
    assert planting.slots[0].kind == "envvar"
    assert planting.slots[0].path == "TOKEN"


def test_a_file_canary_is_planted_as_a_file() -> None:
    planting = plan_canary_planting(
        [Canary(id="c1", marker="SECRET", kind="aws", path="~/.aws/credentials")]
    )
    assert planting.env == {}
    assert planting.files == (("~/.aws/credentials", "SECRET"),)
    assert planting.slots[0].path == "~/.aws/credentials"


def test_the_default_pool_plants_one_env_var_and_the_rest_as_files() -> None:
    planting = plan_canary_planting(mint_canaries(1234))
    # The shipped pool has exactly one env-var slot (INTERNAL_API_TOKEN) and four file slots.
    assert set(planting.env) == {"INTERNAL_API_TOKEN"}
    assert len(planting.files) == 4
    assert len(planting.slots) == 5


def test_the_marker_reaches_env_and_files_but_never_a_slot() -> None:
    """§10.4.3: the value goes *into* the container but not into the trace. A slot is a reference —
    id, kind, path — so it is structurally impossible to record a marker."""
    canaries = mint_canaries(1234)
    planting = plan_canary_planting(canaries)
    markers = {c.marker for c in canaries}

    planted_values = set(planting.env.values()) | {content for _path, content in planting.files}
    assert planted_values == markers  # every marker is planted somewhere a skill can read it

    # No marker appears in any slot field — the by-reference record the trace keeps.
    for slot in planting.slots:
        for marker in markers:
            assert marker not in slot.id
            assert marker not in slot.kind
            assert marker not in slot.path


def test_planting_is_deterministic_and_sorted_by_id() -> None:
    canaries = mint_canaries(77)
    a = plan_canary_planting(canaries)
    b = plan_canary_planting(list(reversed(canaries)))
    # Order-independent: the same canaries plant the same slots in the same (id-sorted) order (§24).
    assert a == b
    assert [s.id for s in a.slots] == sorted(s.id for s in a.slots)


def test_result_is_the_capture_native_planting_type() -> None:
    assert isinstance(plan_canary_planting(mint_canaries(1)), CanaryPlanting)
