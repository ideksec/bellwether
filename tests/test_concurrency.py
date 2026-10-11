"""`execution.concurrency`: parallel runs within a look, and nothing else changes (§13.1, §19.3, §24).

The setting was parsed and listed as not built ("runs execute one at a time"). It now bounds how
many runs of one *look* execute at once. These tests pin the four properties that make that safe,
each at the wiring rather than at a helper:

- the configured value travels config → ``run_evaluation`` → ``drive_evaluation`` and runs really
  overlap (observed with a fake executor that counts what is in flight);
- the output is **byte-identical** at 1 and at 4 for the same inputs, with the fake finishing runs
  in *reverse* coordinate order, so an implementation that collected results by completion would
  change the bytes (§24);
- a look boundary is respected: no run of look k+1 starts before every run of look k returned
  and the design decided (§13.1), so a parallel evaluation buys exactly the runs a serial one buys;
- retries (§13.2) behave as in serial — notes in coordinate order, the failure raised is the
  lowest coordinate's, queued runs never start, and started runs finish their own teardown.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from bellwether.cli.orchestrator import (
    ExecutedRun,
    RunPlan,
    TargetInfo,
    drive_evaluation,
    plan_matrix,
)
from bellwether.cli.run import run_evaluation
from bellwether.config.models.config import Config
from bellwether.errors import BellwetherError, InfrastructureError
from bellwether.skill import SkillPackage
from tests.test_driver import (
    _NO_SKILL_TRANSCRIPT,
    _executed_run,
    _firstlight_profile,
    _scenario,
)
from tests.test_run import _ENVIRON, _config, _policy
from tests.test_run import package as package

_TARGET = TargetInfo("api-loop", "p", "frontier")


@dataclass
class _Recorder:
    """A thread-safe fake executor that records overlap, start order, and what was in flight.

    Each run's outcome is a function of its *coordinate* (an odd repetition fails to activate the
    skill), never of call order, so a run's trace is the same whichever thread or turn ran it. The
    delay shrinks with the repetition, so later coordinates finish first — completion order is the
    reverse of plan order whenever runs overlap.
    """

    tmp_path: Path
    delay: float = 0.05
    #: repetition → (error, times to raise it) for the first attempts of that repetition.
    failures: dict[int, tuple[InfrastructureError, int]] = field(default_factory=dict)
    #: repetition → extra delay before it raises, to force a failure order.
    fail_delay: dict[int, float] = field(default_factory=dict)
    mixed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)
    active: int = 0
    peak: int = 0
    completed: int = 0
    #: (repetition, attempt, runs completed when this one started)
    starts: list[tuple[int, int, int]] = field(default_factory=list)
    #: What a real executor would hold open — a sandbox, a proxy — between start and teardown.
    open_sandboxes: set[str] = field(default_factory=set)

    def execute(self, plan: RunPlan) -> ExecutedRun:
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.starts.append((plan.repetition, plan.attempt, self.completed))
            self.open_sandboxes.add(plan.run_id)
        try:
            remaining = self.failures.get(plan.repetition)
            if remaining is not None and plan.attempt <= remaining[1]:
                time.sleep(self.fail_delay.get(plan.repetition, 0.0))
                raise remaining[0]
            time.sleep(self.delay / plan.repetition)
            transcript = _NO_SKILL_TRANSCRIPT if self.mixed and plan.repetition % 2 else None
            run_dir = self.tmp_path / f"{plan.scenario.id}-{plan.repetition}-{plan.attempt}"
            run_dir.mkdir(parents=True, exist_ok=True)
            return _executed_run(plan, run_dir, plan.repetition, transcript=transcript)
        finally:
            with self.lock:
                self.active -= 1
                self.completed += 1
                self.open_sandboxes.discard(plan.run_id)


def _plans(repetitions: int = 6) -> list[RunPlan]:
    return plan_matrix([_scenario("alpha")], [_TARGET], repetitions=repetitions)


# ---------------------------------------------------------------------------
# The driver
# ---------------------------------------------------------------------------


def test_runs_of_one_look_overlap_up_to_the_bound(tmp_path: Path) -> None:
    executor = _Recorder(tmp_path)
    (reading,) = drive_evaluation(_plans(), executor, profile=_firstlight_profile(), concurrency=4)
    assert len(reading.runs) == 6
    assert executor.peak == 4, "runs of one look did not execute in parallel up to the bound"


def test_concurrency_one_is_serial(tmp_path: Path) -> None:
    executor = _Recorder(tmp_path)
    drive_evaluation(_plans(), executor, profile=_firstlight_profile(), concurrency=1)
    assert executor.peak == 1
    # Each run started only after every earlier one finished — today's behaviour exactly.
    assert [done for _rep, _att, done in executor.starts] == list(range(6))


@pytest.mark.parametrize("value", [0, -1])
def test_a_concurrency_below_one_is_refused(tmp_path: Path, value: int) -> None:
    with pytest.raises(BellwetherError, match="at least 1"):
        drive_evaluation(
            _plans(), _Recorder(tmp_path), profile=_firstlight_profile(), concurrency=value
        )


def test_readings_are_identical_at_one_and_four(tmp_path: Path) -> None:
    """Completion order is reversed by the fake; the readings must not notice (§24)."""
    serial = drive_evaluation(
        _plans(20),
        _Recorder(tmp_path / "serial", mixed=True),
        profile=_firstlight_profile(),
        concurrency=1,
    )
    parallel_exec = _Recorder(tmp_path / "parallel", mixed=True)
    parallel = drive_evaluation(
        _plans(20), parallel_exec, profile=_firstlight_profile(), concurrency=4
    )
    assert parallel_exec.peak > 1
    assert serial == parallel
    assert [run.key.repetition for run in parallel[0].runs] == list(
        range(1, len(parallel[0].runs) + 1)
    )


def test_no_run_of_the_next_look_starts_before_the_look_is_decided(tmp_path: Path) -> None:
    """§13.1 with a bound wider than a look: a 50% set never resolves, so it runs look by look to
    n_max (6, 12, 20 under the shipped low profile). Even with eight workers, the seventh run
    starts only after all six of the first look returned, and the thirteenth after twelve."""
    executor = _Recorder(tmp_path, mixed=True)
    (reading,) = drive_evaluation(
        _plans(20), executor, profile=_firstlight_profile(), concurrency=8
    )
    looks = list(_firstlight_profile().matrix.looks)
    assert len(reading.runs) == 20, "the mixed set was expected to run to n_max"
    for repetition, _attempt, completed_before in executor.starts:
        boundary = max((look for look in looks if look < repetition), default=0)
        assert completed_before >= boundary, (
            f"repetition {repetition} started with {completed_before} run(s) complete, before "
            f"its look boundary of {boundary} was decided"
        )
    # The widest increment (12 → 20) filled all eight workers; no look ran wider than itself.
    assert executor.peak == max(b - a for a, b in zip([0, *looks], looks, strict=False)) == 8


def test_a_resolved_look_buys_no_more_runs_in_parallel_than_in_serial(tmp_path: Path) -> None:
    """The spend half of §13.1: a set that resolves at its first look stops there at any bound."""
    executor = _Recorder(tmp_path)
    (reading,) = drive_evaluation(
        _plans(20), executor, profile=_firstlight_profile(), concurrency=8
    )
    assert len(executor.starts) == 6 and reading.look == 6


def test_retries_under_concurrency_behave_as_in_serial(tmp_path: Path) -> None:
    """§13.2: transient failures in two runs of one look are retried in place; the readings and
    the retry notes — which land in the verdict — come out as a serial run's, in coordinate order,
    although the parallel retries fire in a different order."""

    def flaky(name: str) -> _Recorder:
        return _Recorder(
            tmp_path / name,
            failures={
                1: (InfrastructureError("HTTP 529", retryable=True), 2),
                3: (InfrastructureError("HTTP 503", retryable=True), 1),
            },
            # Repetition 1's failures come last in time, so completion-ordered notes would differ.
            fail_delay={1: 0.05},
        )

    def drive(executor: _Recorder, concurrency: int) -> tuple[object, list[str], list[float]]:
        notes: list[str] = []
        slept: list[float] = []
        readings = drive_evaluation(
            _plans(),
            executor,
            profile=_firstlight_profile(),
            retry_on_infra_error=2,
            sleep=slept.append,
            on_retry=notes.append,
            concurrency=concurrency,
        )
        return readings, notes, slept

    serial_readings, serial_notes, serial_slept = drive(flaky("serial"), 1)
    parallel_exec = flaky("parallel")
    parallel_readings, parallel_notes, parallel_slept = drive(parallel_exec, 4)

    assert parallel_exec.peak > 1
    assert parallel_readings == serial_readings
    assert parallel_notes == serial_notes
    assert [note.split(":", 1)[0] for note in parallel_notes] == [
        "alpha-api-loop-p-frontier-001",
        "alpha-api-loop-p-frontier-001-attempt2",
        "alpha-api-loop-p-frontier-003",
    ]
    assert sorted(parallel_slept) == sorted(serial_slept)
    attempts = sorted((rep, att) for rep, att, _ in parallel_exec.starts if rep in (1, 3))
    assert attempts == [(1, 1), (1, 2), (1, 3), (3, 1), (3, 2)]


def test_a_failure_raises_the_lowest_coordinate_and_leaks_nothing(tmp_path: Path) -> None:
    """Two runs of one look fail for good; the later coordinate fails *first* in time. The error
    raised is the earlier coordinate's — where a serial run would have stopped — the runs still
    queued never start, and every run that did start finished its own teardown before the error
    reached the caller."""
    executor = _Recorder(
        tmp_path,
        # Slow successful runs: the freed worker may pick up repetition 3 before the driver
        # cancels, but nothing after it.
        delay=0.6,
        failures={
            1: (InfrastructureError("rep one refused", retryable=False), 99),
            2: (InfrastructureError("rep two refused", retryable=False), 99),
        },
        fail_delay={1: 0.1, 2: 0.0},
    )
    with pytest.raises(InfrastructureError, match="rep one refused"):
        drive_evaluation(_plans(), executor, profile=_firstlight_profile(), concurrency=2)
    started = {rep for rep, _att, _done in executor.starts}
    assert started <= {1, 2, 3}, f"queued runs started after a failure in their look: {started}"
    assert executor.open_sandboxes == set(), "a started run was abandoned before its teardown"
    assert executor.active == 0


# ---------------------------------------------------------------------------
# The wiring: config.yaml → run_evaluation → drive_evaluation
# ---------------------------------------------------------------------------


class _WiredRecorder(_Recorder):
    """A recorder in the shape `run_evaluation`'s executor factory builds (it ignores the
    package and the client factory: the scripted trace is all the driver needs)."""


def _with_concurrency(value: int) -> Config:
    config = _config()
    return config.model_copy(
        update={"execution": config.execution.model_copy(update={"concurrency": value})}
    )


def _evaluate(package: SkillPackage, tmp_path: Path, config: Config, executor: _Recorder):  # type: ignore[no-untyped-def]
    return run_evaluation(
        config=config,
        policy=_policy(),
        package=package,
        fixture=tmp_path / "fixture",
        environ=_ENVIRON,
        make_executor=lambda _pkg, _fixture, _clients: executor,
        out_dir=tmp_path / "out",
        eval_id="concurrency",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
    )


@pytest.mark.parametrize(("value", "expected_peak"), [(1, 1), (2, 2), (4, 4)])
def test_the_configured_concurrency_reaches_the_driver(
    package: SkillPackage,
    tmp_path: Path,
    value: int,
    expected_peak: int,
) -> None:
    """The hop that makes the setting real: the value in config.yaml is the bound the runs of a
    look actually execute under. Dropping the argument in `run_evaluation` leaves the driver at
    its default of 1 and the 2 and 4 rows fail."""
    executor = _WiredRecorder(tmp_path / "exec")
    _evaluate(package, tmp_path, _with_concurrency(value), executor)
    assert executor.peak == expected_peak


def test_the_shipped_default_runs_in_parallel(package: SkillPackage, tmp_path: Path) -> None:
    """§21 ships ``concurrency: 4``; a config that does not set it gets that, not serial."""
    executor = _WiredRecorder(tmp_path / "exec")
    _evaluate(package, tmp_path, _config(), executor)
    assert Config.model_fields["execution"].default_factory is not None
    assert executor.peak == 4


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_the_artifact_tree_is_byte_identical_at_one_and_four(
    package: SkillPackage,
    tmp_path: Path,
) -> None:
    """§24 end to end: every file `run_evaluation` writes — traces, summary.json, the verdict, the
    report — is the same bytes whether the runs of a look executed one at a time or four at
    once, with the fake finishing them in reverse coordinate order and their outcomes differing by
    coordinate, so any completion-ordered collection would reorder what is written."""
    serial_exec = _WiredRecorder(tmp_path / "serial-exec", mixed=True)
    _evaluate(package, tmp_path / "serial", _with_concurrency(1), serial_exec)
    parallel_exec = _WiredRecorder(tmp_path / "parallel-exec", mixed=True)
    _evaluate(package, tmp_path / "parallel", _with_concurrency(4), parallel_exec)

    assert serial_exec.peak == 1 and parallel_exec.peak == 4
    serial = _tree(tmp_path / "serial" / "out")
    parallel = _tree(tmp_path / "parallel" / "out")
    assert any(name.endswith("summary.json") for name in serial), sorted(serial)
    assert sorted(serial) == sorted(parallel)
    differing = [name for name in serial if serial[name] != parallel[name]]
    assert differing == [], differing
