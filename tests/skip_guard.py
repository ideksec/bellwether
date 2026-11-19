"""``--skips-are-failures`` — a skipped test fails the run instead of colouring it green.

A skip is the right answer on a machine that lacks what a test needs: no daemon, no root, no
open egress to build a sidecar image. It is the wrong answer on the one machine that exists to
run every test. CI's container job went twelve merges with sixteen tests skipped and the
check green, because the runner's ``sudo`` stopped passing the ``CI`` variable the tests gate
on (see spec-notes, "the container job's silent skips"). Nothing was watching for a skip.

The switch is a command-line flag and not an environment variable on purpose: the failure it
guards against is the environment not arriving. An argument cannot be dropped that way.

An ``xfail`` is not a skip — it ran, or was declared expected-to-fail with a reason the suite
keeps visible (§24) — and is left alone.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest

FLAG = "--skips-are-failures"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        FLAG,
        action="store_true",
        default=False,
        help="report every skipped test as a failure (for the job that must run them all)",
    )


def _reason(report: pytest.TestReport) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2]).removeprefix("Skipped: ")
    return str(longrepr)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, Any, None]:
    outcome = yield
    if not item.config.getoption(FLAG):
        return
    report: pytest.TestReport = outcome.get_result()
    if report.skipped and not hasattr(report, "wasxfail"):
        report.outcome = "failed"
        report.longrepr = (
            f"{item.nodeid} was skipped, and this run was told every test must run "
            f"({FLAG}). The skip's reason: {_reason(report)}"
        )
