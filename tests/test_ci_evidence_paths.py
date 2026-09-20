"""The live workflows must address the evaluation tree, and only it.

`bellwether run --out <out>` writes two things directly under `<out>`: the evaluation tree,
`<out>/<eval_id>/`, and — when the run cache is on — `<out>/.cache/runs` beside it (§19.2).
Everything CI does after the run addresses the *first* of those: it prints `report/pr_comment.md`
into the job log, posts the verdict to the PR, removes the overlayfs scratch under `runs/`, and
uploads the evidence.

Both workflows picked it with `find <out> -maxdepth 1 -type d | head -n1`, which returns whatever
the kernel lists first. On PR #78 that was `.cache`, and every one of those four steps addressed
the wrong directory: the report read "(no report was rendered)" though one had been written,
`bellwether pr-comment` failed behind its `|| true` so no verdict reached the PR, the `rm` cleared
the run cache instead of the overlay scratch, and `upload-artifact` then died with EACCES on the
mode-000 overlayfs workdir that `rm` had been there to remove. The step's own output looked clean
throughout — a control path rendering a clean result without doing the thing, which is the failure
mode this project exists to distrust, here in this project's own CI.

It is also a §24 violation: selection by directory-walk order rather than a sorted walk. The same
evidence upload had already been fixed once for a different reason (`include-hidden-files`), which
is the argument for pinning it rather than trusting the next reading of the YAML.

These assertions are deliberately about the *wiring*: they compare what the workflows exclude
against the directory name the CLI actually creates, so renaming one without the other fails the
build rather than silently unpublishing the evidence again.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bellwether.cli.run_cache import CACHE_DIR_NAME

_ROOT = Path(__file__).resolve().parents[1]

#: Every workflow that runs a live evaluation and then publishes its evidence.
LIVE_WORKFLOWS = ["bellwether.yml", "bellwether-claude-code.yml"]


def _workflow(name: str) -> str:
    return (_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _shell(name: str) -> str:
    """The workflow with its comment lines dropped.

    The check has to read what the runner executes, not what the file says about it. The comment
    that explains this defect quotes the defective expression verbatim, so a check that greps the
    whole file fails on its own documentation — and the obvious way to quiet that is to stop
    quoting the expression, which is the wrong repair: the explanation is the durable part.
    """
    return "\n".join(
        line for line in _workflow(name).splitlines() if not line.lstrip().startswith("#")
    )


@pytest.mark.parametrize("name", LIVE_WORKFLOWS)
def test_the_evaluation_directory_is_not_chosen_by_walk_order(name: str) -> None:
    """`head -n1` over an unsorted `find` is the defect itself, whatever it is applied to."""
    body = _shell(name)
    assert not re.search(r"find[^\n]*\|\s*head\s+-n\s*1", body), (
        f"{name} selects a directory by walk order; §24 requires a sorted, deterministic walk"
    )


@pytest.mark.parametrize("name", LIVE_WORKFLOWS)
def test_the_cache_sibling_is_excluded_by_the_name_the_cli_creates(name: str) -> None:
    """The wiring assertion. `app.py` builds `<out>/<CACHE_DIR_NAME>/runs`; if the workflow
    excludes some other spelling, the selection is back to picking whichever comes first."""
    body = _shell(name)
    assert f"! -name {CACHE_DIR_NAME}" in body, (
        f"{name} does not exclude {CACHE_DIR_NAME!r}, the run-cache directory the CLI writes "
        "beside the evaluation tree"
    )


@pytest.mark.parametrize("name", LIVE_WORKFLOWS)
def test_an_ambiguous_output_tree_is_refused_rather_than_guessed(name: str) -> None:
    """Zero or two candidates means the assumption behind every later step is wrong. A wrong
    guess publishes no verdict and no evidence while the job reports success, so the tree that
    does not match is an error — the same stance §16.4 takes before spending on a run."""
    body = _shell(name)
    assert 'if [ "${#eval_dirs[@]}" -ne 1 ]; then' in body, (
        f"{name} does not assert exactly one evaluation directory under --out"
    )
    assert "expected exactly one evaluation directory" in body
