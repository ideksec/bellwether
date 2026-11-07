"""The ``pids_limit`` exit reason (§9.2, §12.7), offline: where the counter is found, how it is
read, and how it is layered over the harness's own exit reason.

The container halves — a fork past the limit observed on a live container's cgroup, and the
same hit reaching the footer of a real run — are in ``test_sandbox_docker.py`` and
``test_execution_docker.py``.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest

from bellwether.cli.execution import SandboxRunExecutor
from bellwether.errors import BellwetherError
from bellwether.harness import RawHarnessEvent
from bellwether.sandbox.docker import PidsEvents, parse_pids_events, pids_cgroup_dir
from bellwether.trace import footer_exit_reason
from bellwether.trace.models import RunFooter, SandboxLimits
from bellwether.trace.writer import serialize_record

_ID = "e1db42fe6668336477753542266a63ac35ae254620f4763e50157f8094fe65a0"
#: A hybrid host, as this project's own development container reports it: every v1 controller
#: on its own hierarchy, and an empty unified hierarchy beside them.
_HYBRID = (
    f"8:pids:/docker/{_ID}\n7:blkio:/docker/{_ID}\n4:memory:/docker/{_ID}\n"
    f"1:cpu:/docker/{_ID}\n0::/docker/{_ID}\n"
)
#: A cgroup v2 host with the systemd driver, as a GitHub-hosted runner reports it.
_UNIFIED = f"0::/system.slice/docker-{_ID}.scope\n"


# ---------------------------------------------------------------------------
# Finding the counter
# ---------------------------------------------------------------------------


def test_the_v1_pids_hierarchy_wins_on_a_hybrid_host() -> None:
    assert pids_cgroup_dir(_HYBRID, Path("/sys/fs/cgroup")) == Path(
        f"/sys/fs/cgroup/pids/docker/{_ID}"
    )


def test_the_unified_hierarchy_is_the_controller_on_cgroup_v2() -> None:
    assert pids_cgroup_dir(_UNIFIED, Path("/sys/fs/cgroup")) == Path(
        f"/sys/fs/cgroup/system.slice/docker-{_ID}.scope"
    )


def test_a_process_under_no_pids_controller_is_refused() -> None:
    with pytest.raises(BellwetherError, match="no pids controller"):
        pids_cgroup_dir(f"4:memory:/docker/{_ID}\n1:cpu:/docker/{_ID}\n")
    with pytest.raises(BellwetherError):
        pids_cgroup_dir("")


def test_the_max_counter_is_read_and_nothing_else_is() -> None:
    assert parse_pids_events("max 2\n") == 2
    assert parse_pids_events("max 0\n") == 0
    # cgroup v2 on a 6.11+ kernel adds further keys; only `max` is the limit hit.
    assert parse_pids_events("max 3\nmax.local 1\n") == 3
    with pytest.raises(BellwetherError, match="no max counter"):
        parse_pids_events("current 5\n")


# ---------------------------------------------------------------------------
# The footer
# ---------------------------------------------------------------------------


def _events(*kinds: tuple[str, dict[str, Any]]) -> list[RawHarnessEvent]:
    at = dt.datetime(2026, 11, 6, tzinfo=dt.UTC)
    return [RawHarnessEvent(ts=at, kind=kind, data=data) for kind, data in kinds]  # type: ignore[arg-type]


_COMPLETED = _events(("final_output", {"text": "done"}))
_TIMEOUT = _events(("harness_error", {"exit_reason": "timeout"}))


@pytest.mark.parametrize(
    ("events", "budget_cap", "hit", "expected"),
    [
        (_COMPLETED, False, False, "completed"),
        ([], False, False, "harness_error"),
        (_TIMEOUT, False, False, "timeout"),
        (_COMPLETED, True, False, "budget_exceeded"),
        # A refused fork is the skill's, over the harness's reading and the operator's cut.
        (_COMPLETED, False, True, "pids_limit"),
        ([], False, True, "pids_limit"),
        (_TIMEOUT, False, True, "pids_limit"),
        (_COMPLETED, True, True, "pids_limit"),
    ],
)
def test_the_sandbox_observation_is_layered_over_the_harness_reading(
    events: list[RawHarnessEvent], budget_cap: bool, hit: bool, expected: str
) -> None:
    assert footer_exit_reason(events, budget_cap=budget_cap, pids_limit_hit=hit) == expected


class _Backend:
    def __init__(self, result: PidsEvents | BellwetherError) -> None:
        self.result = result

    def pids_events(self, prepared: object) -> PidsEvents:
        if isinstance(self.result, BellwetherError):
            raise self.result
        return self.result


def _executor(backend: object) -> SandboxRunExecutor:
    return SandboxRunExecutor.__new__(SandboxRunExecutor).__class__(  # type: ignore[call-arg]
        backend=backend,  # type: ignore[arg-type]
        package=None,  # type: ignore[arg-type]
        fixture=Path(),
        client_factory=None,  # type: ignore[arg-type]
        eval_id="e",
        run_root=Path(),
    )


def test_a_counter_that_is_read_lands_on_the_footer_block() -> None:
    executor = _executor(_Backend(PidsEvents(max_hits=2, limit=8, current=5, source="x")))
    limits = executor._observe_sandbox_limits(None)  # type: ignore[arg-type]
    assert limits == SandboxLimits(pids_limit_hits=2, pids_limit=8)


def test_a_counter_that_cannot_be_read_is_unobserved_not_clean() -> None:
    """§10.7, for a counter: a read that fails must not read as "the limit was never hit"."""
    executor = _executor(_Backend(BellwetherError("cannot read /proc/42/cgroup: gone")))
    limits = executor._observe_sandbox_limits(None)  # type: ignore[arg-type]
    assert limits.pids_limit_hits is None
    assert limits.unobserved == "pids limit not observed: cannot read /proc/42/cgroup: gone"
    # Unobserved is not a hit: the exit reason is the harness's.
    assert (
        footer_exit_reason(
            _COMPLETED, budget_cap=False, pids_limit_hit=bool(limits.pids_limit_hits)
        )
        == "completed"
    )


def test_a_footer_without_the_block_renders_as_before() -> None:
    """A trace written before the block existed and one written with nothing to record are
    byte-identical: the golden traces do not move."""
    footer = RunFooter(ended_at="2026-11-06T00:00:00Z", wall_clock_ms=1, exit_reason="completed")
    assert "sandbox" not in serialize_record(footer)
    with_block = footer.model_copy(
        update={"sandbox": SandboxLimits(pids_limit_hits=0, pids_limit=512)}
    )
    assert '"sandbox":{"pids_limit":512,"pids_limit_hits":0}' in serialize_record(with_block)
