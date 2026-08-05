"""WP-7: canonicalization and epoch anchoring (§11.4, §11.5).

The build plan's warning: this is the package most likely to be got subtly wrong —
over-test it. The two done-when criteria are asserted directly: the same event set
produces byte-identical ordering across 100 shuffled presentations, and jittering
non-spine timestamps by ±2s leaves the sequence unchanged.
"""

from __future__ import annotations

import datetime as dt
import random
from typing import Any

from bellwether.trace import (
    Action,
    CanonicalTrace,
    Correlation,
    NormalizationContext,
    anchor_events,
    canonicalize,
    capability_for,
    serialize_record,
)

START = dt.datetime(2026, 8, 6, 9, 0, 0, tzinfo=dt.UTC)
CTX = NormalizationContext(workspace_root="/work/a7f3c1")


def at(seconds: float) -> dt.datetime:
    return START + dt.timedelta(seconds=seconds)


def action(
    seq: int,
    seconds: float,
    plane: str,
    kind: str,
    payload: dict[str, Any] | None = None,
    *,
    anchor: int | None = None,
) -> Action:
    return Action(
        seq=seq,
        ts=at(seconds),
        plane=plane,  # type: ignore[arg-type]
        kind=kind,
        action=payload or {},
        correlation=Correlation(anchor_seq=anchor),
    )


def spine_with_two_calls() -> list[Action]:
    """A two-call Plane A stream. Call windows: [10, 14] and [30, 36] seconds."""
    return [
        action(0, 0, "harness", "skill_offered", {"skill": "s"}),
        action(1, 5, "harness", "model_turn", {"stop_reason": "tool_use"}),
        action(
            2, 10, "harness", "tool_call", {"tool": "bash", "tool_call_id": "tc_1", "input": {}}
        ),
        action(
            3,
            14,
            "harness",
            "tool_result",
            {"tool": "bash", "tool_call_id": "tc_1", "duration_ms": 4000},
        ),
        action(4, 20, "harness", "model_turn", {"stop_reason": "tool_use"}),
        action(
            5,
            30,
            "harness",
            "tool_call",
            {"tool": "write", "tool_call_id": "tc_2", "input": {"path": "out.md"}},
        ),
        action(
            6,
            36,
            "harness",
            "tool_result",
            {"tool": "write", "tool_call_id": "tc_2", "duration_ms": 6000},
        ),
        action(7, 40, "harness", "final_output", {"text": "done"}),
    ]


def fs_event(seq: int, seconds: float, path: str, zone: str = "workspace", **extra: Any) -> Action:
    payload = {
        "path": path,
        "zone": zone,
        "zone_relative": path.rsplit("/", 1)[-1],
        "change": "created",
        **extra,
    }
    return action(seq, seconds, "filesystem", "file_write", payload)


def target(a: Action) -> str:
    cap = capability_for(a, CTX)
    if cap is not None:
        return cap.tier3 or cap.tier2 or cap.tier1
    return ""


def order_of(actions: list[Action]) -> list[int]:
    return [a.seq for a in anchor_events(actions, normalized_target=target)]


# ---------------------------------------------------------------------------
# Epoch assignment (§11.5 step 2)
# ---------------------------------------------------------------------------


def test_an_event_inside_a_tool_call_window_follows_that_call() -> None:
    events = [*spine_with_two_calls(), fs_event(100, 12, "/work/a7f3c1/in_window.txt")]
    ordered = order_of(events)
    assert ordered.index(100) == ordered.index(2) + 1


def test_an_event_between_windows_lands_in_the_gap_before_the_next_call() -> None:
    events = [*spine_with_two_calls(), fs_event(100, 22, "/work/a7f3c1/gap.txt")]
    ordered = order_of(events)
    # After call 1's result and the intervening model turn, before call 2 opens.
    assert ordered.index(4) < ordered.index(100) < ordered.index(5)


def test_an_event_before_the_first_call_is_epoch_zero() -> None:
    events = [*spine_with_two_calls(), fs_event(100, 2, "/work/a7f3c1/early.txt")]
    ordered = order_of(events)
    assert ordered.index(100) < ordered.index(2)


def test_an_event_after_the_last_window_trails() -> None:
    events = [*spine_with_two_calls(), fs_event(100, 99, "/work/a7f3c1/late.txt")]
    ordered = order_of(events)
    assert ordered.index(100) > ordered.index(7)


def test_a_run_with_no_tool_calls_still_orders_deterministically() -> None:
    events = [
        action(0, 0, "harness", "model_turn", {}),
        action(1, 1, "harness", "final_output", {"text": "x"}),
        fs_event(100, 0.5, "/work/a7f3c1/b.txt"),
        fs_event(101, 0.4, "/work/a7f3c1/a.txt"),
    ]
    ordered = order_of(events)
    assert ordered[:2] == [0, 1]
    # Content order, not time order: a.txt before b.txt despite later timestamp.
    assert ordered[2:] == [101, 100]


# ---------------------------------------------------------------------------
# Explicit correlation (§11.5 step 3)
# ---------------------------------------------------------------------------


def test_anchor_seq_beats_the_timestamp_entirely() -> None:
    """An event whose clock says 'after everything' but whose anchor names call 1."""
    wild = fs_event(100, 9999, "/work/a7f3c1/anchored.txt")
    anchored = Action(
        seq=wild.seq,
        ts=wild.ts,
        plane=wild.plane,
        kind=wild.kind,
        action=wild.action,
        correlation=Correlation(anchor_seq=2),
    )
    ordered = order_of([*spine_with_two_calls(), anchored])
    assert ordered.index(100) == ordered.index(2) + 1


# ---------------------------------------------------------------------------
# The done-when criteria
# ---------------------------------------------------------------------------


def full_event_set() -> list[Action]:
    return [
        *spine_with_two_calls(),
        fs_event(100, 12, "/work/a7f3c1/w1.txt"),
        fs_event(101, 12, "/work/a7f3c1/w0.txt"),
        fs_event(102, 33, "/tmp/t.txt", zone="scratch"),
        fs_event(103, 22, "/work/a7f3c1/gap.txt"),
        action(104, 12, "credentials", "canary_read", {"path": "/work/a7f3c1/.env"}),
        action(105, 33, "egress", "egress_blocked", {"host": "example.com"}),
    ]


def test_100_shuffles_produce_byte_identical_ordering() -> None:
    """The first done-when. Byte-identical means byte-identical: the serialised records
    are compared, not just the seq numbers."""
    events = full_event_set()
    reference = [serialize_record(a) for a in anchor_events(events, normalized_target=target)]

    rng = random.Random(20260806)
    for _ in range(100):
        shuffled = list(events)
        rng.shuffle(shuffled)
        got = [serialize_record(a) for a in anchor_events(shuffled, normalized_target=target)]
        assert got == reference


def test_jittering_non_spine_timestamps_by_2s_leaves_the_sequence_unchanged() -> None:
    """The second done-when. Windows here are 4s and 6s wide and every non-spine event
    sits ≥2s inside its window or its gap, so ±2s of capture jitter — flush cadence,
    proxy delay — must not move anything."""
    events = full_event_set()
    reference = order_of(events)

    rng = random.Random(99)
    for _ in range(50):
        jittered = []
        for a in events:
            if a.plane == "harness":
                jittered.append(a)
                continue
            shift = rng.uniform(-2.0, 2.0)
            jittered.append(
                Action(
                    seq=a.seq,
                    ts=a.ts + dt.timedelta(seconds=shift),
                    plane=a.plane,
                    kind=a.kind,
                    action=a.action,
                    correlation=a.correlation,
                )
            )
        assert order_of(jittered) == reference


def test_canonical_traces_are_equal_across_shuffles_and_machines() -> None:
    events = full_event_set()
    reference = canonicalize(events, CTX)

    rng = random.Random(7)
    for _ in range(20):
        shuffled = list(events)
        rng.shuffle(shuffled)
        assert canonicalize(shuffled, CTX) == reference


# ---------------------------------------------------------------------------
# Normalization (§11.4)
# ---------------------------------------------------------------------------


def test_run_local_roots_are_replaced_with_placeholders() -> None:
    assert CTX.normalize_path("/work/a7f3c1/src/auth.py") == "${WORKSPACE}/src/auth.py"
    assert CTX.normalize_path("/tmp/probe.txt") == "${TMP}/probe.txt"
    assert CTX.normalize_path("/home/agent/.aws/credentials") == "${HOME}/.aws/credentials"
    assert CTX.normalize_path("/etc/passwd") == "/etc/passwd"


def test_a_prefix_that_is_not_a_path_boundary_does_not_match() -> None:
    """`/work/a7f3c1x/...` is a different directory, not the workspace."""
    assert CTX.normalize_path("/work/a7f3c1x/f.txt") == "/work/a7f3c1x/f.txt"


def test_two_runs_with_different_workspace_roots_canonicalize_identically() -> None:
    """The point of the whole exercise: run-local names must not survive."""

    def run(root: str) -> CanonicalTrace:
        ctx = NormalizationContext(workspace_root=root)
        events = [
            action(0, 0, "harness", "model_turn", {}),
            action(
                1,
                1,
                "harness",
                "tool_call",
                {"tool": "read", "tool_call_id": "t", "input": {"path": "src/auth.py"}},
            ),
            action(
                2,
                2,
                "harness",
                "tool_result",
                {"tool": "read", "tool_call_id": "t", "duration_ms": 1000},
            ),
            action(3, 3, "harness", "final_output", {"text": "d"}),
            fs_event(100, 1.5, f"{root}/notes.md"),
        ]
        return canonicalize(events, ctx)

    assert run("/work/a7f3c1") == run("/work/ffee99")


# ---------------------------------------------------------------------------
# Capability tiers (§4.1)
# ---------------------------------------------------------------------------


def test_a_read_tool_call_maps_to_the_workspace_read_class() -> None:
    cap = capability_for(
        action(0, 0, "harness", "tool_call", {"tool": "read", "input": {"path": "src/auth.py"}}),
        CTX,
    )
    assert cap is not None
    assert (cap.tier1, cap.tier2, cap.tier3) == (
        "workspace_read",
        "workspace_read:src/",
        "${WORKSPACE}/src/auth.py",
    )


def test_reading_the_workspace_root_itself_does_not_crash() -> None:
    """Regression: a skill that reads or writes the workspace root — ``.`` or the bare
    ``/work/<slug>`` — normalises to a path with no segments, which crashed
    ``_first_segment`` with an IndexError. That is trivially and adversarially
    triggerable (``read {path: "."}``), and canonicalize runs on every metrics pass, so
    the crash took the whole analysis down. It must classify, not raise."""
    for path in (".", "/work/a7f3c1", "/work/a7f3c1/"):
        cap = capability_for(
            action(0, 0, "harness", "tool_call", {"tool": "read", "input": {"path": path}}),
            CTX,
        )
        assert cap is not None, path
        assert cap.tier1 == "workspace_read", path
        assert cap.tier2 == "workspace_read:", path
    # And the full canonicalize path survives it end to end.
    events = [action(0, 0, "harness", "tool_call", {"tool": "write", "input": {"path": "."}})]
    canonical = canonicalize(events, CTX)
    assert "workspace_write" in canonical.caps_t1


def test_a_read_outside_the_workspace_is_the_outside_class() -> None:
    cap = capability_for(
        action(
            0,
            0,
            "harness",
            "tool_call",
            {"tool": "read", "input": {"path": "/home/agent/.aws/credentials"}},
        ),
        CTX,
    )
    assert cap is not None
    assert cap.tier1 == "outside_workspace_read"
    assert cap.tier2 == "outside_workspace_read:${HOME}/.aws/"
    assert cap.tier3 == "${HOME}/.aws/credentials"


def test_generic_tool_calls_are_the_tool_class() -> None:
    cap = capability_for(
        action(0, 0, "harness", "tool_call", {"tool": "bash", "input": {"command": "ls"}}),
        CTX,
    )
    assert cap is not None
    assert (cap.tier1, cap.tier3) == ("tool:bash", "ls")


def test_a_workspace_deletion_is_its_own_class() -> None:
    cap = capability_for(
        action(
            0,
            0,
            "filesystem",
            "file_delete",
            {"path": "/work/a7f3c1/doomed.txt", "zone": "workspace", "zone_relative": "doomed.txt"},
        ),
        CTX,
    )
    assert cap is not None
    assert cap.tier1 == "workspace_delete"


def test_scratch_writes_are_coarsened_to_tier_2() -> None:
    """§10.2: a temp file's exact name is noise; which directory is not."""
    cap = capability_for(
        action(
            0,
            0,
            "filesystem",
            "file_write",
            {"path": "/tmp/x8s2.tmp", "zone": "scratch", "zone_relative": "x8s2.tmp"},
        ),
        CTX,
    )
    assert cap is not None
    assert cap.tier2 == "outside_workspace_write:${TMP}"
    assert cap.tier3 is None


def test_uncorrelated_harness_state_writes_are_not_capabilities() -> None:
    """§10.2: harness state enters the capability set only via a tool call."""
    uncorrelated = action(
        0,
        0,
        "filesystem",
        "file_write",
        {"path": "/home/agent/.claude/s.json", "zone": "harness_state", "zone_relative": "s.json"},
    )
    assert capability_for(uncorrelated, CTX) is None

    correlated = action(
        1,
        0,
        "filesystem",
        "file_write",
        {"path": "/home/agent/.claude/s.json", "zone": "harness_state", "zone_relative": "s.json"},
        anchor=2,
    )
    cap = capability_for(correlated, CTX)
    assert cap is not None and cap.tier1 == "outside_workspace_write"


def test_egress_and_process_and_canary_classes() -> None:
    blocked = capability_for(action(0, 0, "egress", "egress_blocked", {"host": "evil.com"}), CTX)
    assert blocked is not None and blocked.tier1 == "egress_blocked:evil.com"

    egress = capability_for(
        action(
            1,
            0,
            "egress",
            "egress_request",
            {"host": "api.example.com", "url": "https://api.example.com/v1"},
        ),
        CTX,
    )
    assert egress is not None
    assert egress.tier1 == "egress:api.example.com"
    assert egress.tier3 == "https://api.example.com/v1"

    process = capability_for(
        action(2, 0, "process", "process_exec", {"argv": ["/usr/bin/curl", "-s", "x"]}), CTX
    )
    assert process is not None and process.tier1 == "process:curl"

    canary = capability_for(
        action(3, 0, "credentials", "canary_read", {"path": "/work/a7f3c1/.env"}), CTX
    )
    assert canary is not None
    assert (canary.tier1, canary.tier3) == ("canary_read", "${WORKSPACE}/.env")


def test_model_turns_and_results_map_to_no_capability() -> None:
    assert capability_for(action(0, 0, "harness", "model_turn", {}), CTX) is None
    assert capability_for(action(1, 0, "harness", "tool_result", {"tool": "read"}), CTX) is None
    assert capability_for(action(2, 0, "harness", "final_output", {}), CTX) is None


# ---------------------------------------------------------------------------
# Derived structures (§11.4)
# ---------------------------------------------------------------------------


def test_step_signatures_use_tier_1_not_the_exact_target() -> None:
    """Two runs reading different files produce the same step sequence — task
    variance, not capability instability."""

    def run(path: str) -> tuple[Any, ...]:
        events = [
            action(
                0,
                0,
                "harness",
                "tool_call",
                {"tool": "read", "tool_call_id": "t", "input": {"path": path}},
            ),
        ]
        return canonicalize(events, CTX).step_sequence

    assert run("src/a.py") == run("src/b.py")
    assert run("src/a.py")[0] == ("tool_call", "read", "workspace_read")


def test_capability_sets_are_sorted_and_tiered() -> None:
    canonical = canonicalize(full_event_set(), CTX)

    assert canonical.caps_t1 == tuple(sorted(canonical.caps_t1))
    assert "workspace_write" in canonical.caps_t1
    assert "egress_blocked:example.com" in canonical.caps_t1
    assert "canary_read" in canonical.caps_t1
    assert "tool:bash" in canonical.caps_t1
    # Scratch coarsening: the tier-3 set has no ${TMP} entry.
    assert not any("${TMP}" in entry for entry in canonical.caps_t3)
    assert "outside_workspace_write:${TMP}" in canonical.caps_t2


def test_sensitive_hits_fire_on_tier_2() -> None:
    events = [
        action(
            0,
            0,
            "harness",
            "tool_call",
            {"tool": "read", "input": {"path": ".git/config"}},
        ),
        action(
            1,
            0.5,
            "harness",
            "tool_call",
            {"tool": "read", "input": {"path": "/home/agent/.aws/credentials"}},
        ),
        action(2, 1, "harness", "tool_call", {"tool": "read", "input": {"path": "src/ok.py"}}),
    ]
    canonical = canonicalize(events, CTX)
    assert canonical.sensitive_hits == (
        "outside_workspace_read:${HOME}/.aws/",
        "workspace_read:.git/",
    )


def test_the_home_root_itself_is_sensitive() -> None:
    events = [
        action(
            0, 0, "harness", "tool_call", {"tool": "read", "input": {"path": "/home/agent/.bashrc"}}
        )
    ]
    canonical = canonicalize(events, CTX)
    assert canonical.sensitive_hits == ("outside_workspace_read:${HOME}",)


def test_baseline_subtraction_removes_capabilities_but_not_steps() -> None:
    """§11.4: subtract before producing capability structures; §12.6: scope runs
    against observed − baseline. The sequence still shows how the skill worked."""
    events = [
        action(
            0,
            0,
            "harness",
            "tool_call",
            {"tool": "read", "tool_call_id": "t", "input": {"path": "/etc/passwd"}},
        ),
    ]
    absorbed = canonicalize(events, CTX, platform_baseline_t3=frozenset({"/etc/passwd"}))
    kept = canonicalize(events, CTX)

    assert "outside_workspace_read" in kept.caps_t1
    assert "outside_workspace_read" not in absorbed.caps_t1
    assert absorbed.step_sequence == kept.step_sequence


def test_canon_versioning_is_recorded() -> None:
    canonical = canonicalize(full_event_set(), CTX)
    assert canonical.canon.canon_version
    assert canonical.canon.traj_planes == ["A", "C", "D", "E"]


# ---------------------------------------------------------------------------
# The golden trace canonicalizes stably
# ---------------------------------------------------------------------------


def test_the_golden_trace_canonicalizes_to_a_stable_form() -> None:
    """Ties WP-7 to WP-6's reference artifact: the committed trace's canonical form is
    pinned here, so a change to either shows up as exactly one failing expectation."""
    from bellwether.trace import read_trace
    from tests.golden_trace import GOLDEN_PATH

    trace = read_trace(GOLDEN_PATH)
    canonical = canonicalize(
        list(trace.actions), NormalizationContext(workspace_root="/work/golden")
    )

    tool_steps = [step for step in canonical.step_sequence if step[0] == "tool_call"]
    assert tool_steps == [
        ("tool_call", "skill", "tool:skill"),
        ("tool_call", "read", "workspace_read"),
        ("tool_call", "write", "workspace_write"),
    ]
    assert canonical.caps_t1 == ("tool:skill", "workspace_read", "workspace_write")
    assert canonical.sensitive_hits == ()
