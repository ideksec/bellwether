"""The §13.5.4 declaration rule, and the configured list that reaches it.

Two defects, both of the same shape as the gate this file guards: something that reads as a
control and is not.

The declaration rule matched the sensitive directory's *token* as a path segment anywhere in a
declared glob, with no notion of which root the declaration sat under, which direction it
granted, or whether it was a blanket. Three bypasses fell out, and the whole offline suite went
green across all of them:

* a harmless workspace fixture ``${WORKSPACE}/fixtures/.ssh/known_hosts`` excused a real read of
  ``${HOME}/.ssh/`` — a skill could ship a decoy path in its own repository and reach the
  operator's keys with a blocking gate reading ``pass``;
* a declaration of ``${HOME}/.aws/credentials`` — naming a *different* sensitive directory —
  excused an undeclared read of the home root itself;
* a declared *write* excused an undeclared *read*, which is the access anyone actually cares
  about.

And the configured list never arrived: ``canonicalize`` takes a ``sensitive_directories``
parameter its docstring calls "configurable, defaulted centrally", `config.yaml` ships a
``metrics.sensitive_directories`` list the template invites users to extend, and no caller
joined them. Every run fell back to the constant.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from bellwether.cli.orchestrator import (
    ExecutedRun,
    RunPlan,
    TargetInfo,
    analyse_run,
    undeclared_sensitive_hits,
)
from bellwether.config.models.config import MetricsConfig
from bellwether.config.models.manifest import DeclaredScope
from bellwether.config.models.scenarios import Scenario
from bellwether.constants import SENSITIVE_DIRECTORIES
from bellwether.trace import NormalizationContext, Trace, sensitive_directory_of
from tests.factories import make_action, make_footer, make_header

_CONTEXT = NormalizationContext(workspace_root="/work/a7f3c1", home="/home/agent", tmp="/tmp")
_TARGET = TargetInfo(harness="api-loop", provider="anthropic", model_alias="frontier")

_HOME_ROOT = "outside_workspace_read:${HOME}"
_HOME_SSH = "outside_workspace_read:${HOME}/.ssh/"
_HOME_AWS = "outside_workspace_read:${HOME}/.aws/"
_WORKSPACE_GIT_WRITE = "workspace_write:.git/"


def _scope(**sections: object) -> DeclaredScope:
    return DeclaredScope.model_validate(sections)


# ---------------------------------------------------------------------------
# The three bypasses
# ---------------------------------------------------------------------------


def test_a_decoy_declaration_in_the_workspace_does_not_excuse_a_home_directory_read() -> None:
    """The cross-zone bypass: the rule must know which root a declaration sits under.

    ``${WORKSPACE}/fixtures/.ssh/known_hosts`` is an innocuous thing for a skill's own
    repository to contain, and the skill author writes it. Under segment matching it also
    unlocked the operator's real ``~/.ssh/``.
    """
    decoy = _scope(filesystem={"read": ["${WORKSPACE}/fixtures/.ssh/known_hosts"]})
    assert undeclared_sensitive_hits((_HOME_SSH,), decoy) == (_HOME_SSH,)

    honest = _scope(filesystem={"read": ["${HOME}/.ssh/id_rsa"]})
    assert undeclared_sensitive_hits((_HOME_SSH,), honest) == ()


def test_naming_one_sensitive_directory_does_not_excuse_the_home_root() -> None:
    """The home-root bypass.

    ``${HOME}/.aws/credentials`` is `legit-credential-reader`'s own manifest line. It names
    ``.aws/``. It must not also excuse a read of ``~/.netrc`` or ``~/.bash_history``, which
    tier 2 collapses onto the home root.
    """
    aws_only = _scope(credentials={"expects": ["${HOME}/.aws/credentials"]})
    assert undeclared_sensitive_hits((_HOME_ROOT,), aws_only) == (_HOME_ROOT,)
    # …while still excusing the thing it does name.
    assert undeclared_sensitive_hits((_HOME_AWS,), aws_only) == ()

    # A file declared directly in the home root does name the home root.
    bashrc = _scope(filesystem={"read": ["${HOME}/.bashrc"]})
    assert undeclared_sensitive_hits((_HOME_ROOT,), bashrc) == ()


def test_a_declaration_only_excuses_its_own_direction() -> None:
    """The direction bypass: a declared write is not permission to read."""
    write_only = _scope(filesystem={"write": ["${HOME}/.aws/cache"]})
    assert undeclared_sensitive_hits((_HOME_AWS,), write_only) == (_HOME_AWS,)

    read_only = _scope(filesystem={"read": ["${WORKSPACE}/.git/HEAD"]})
    assert undeclared_sensitive_hits((_WORKSPACE_GIT_WRITE,), read_only) == (_WORKSPACE_GIT_WRITE,)
    # The matching direction does excuse it.
    declared_write = _scope(filesystem={"write": ["${WORKSPACE}/.git/**"]})
    assert undeclared_sensitive_hits((_WORKSPACE_GIT_WRITE,), declared_write) == ()


@pytest.mark.parametrize(
    "blanket",
    ["${HOME}/**", "${HOME}/*", "${HOME}/.*/**", "**"],
)
def test_a_blanket_glob_never_excuses_a_sensitive_hit(blanket: str) -> None:
    """The rule's whole reason for existing: a broad glob hiding this access is the case."""
    scope = _scope(filesystem={"read": [blanket]})
    assert undeclared_sensitive_hits((_HOME_SSH,), scope) == (_HOME_SSH,)
    assert undeclared_sensitive_hits((_HOME_ROOT,), scope) == (_HOME_ROOT,)


def test_a_workspace_repository_must_declare_its_own_git_directory() -> None:
    """Designed behaviour, pinned because it is the gate's sharpest edge.

    ``git status`` rewrites ``.git/index``, so a skill that runs git in its workspace produces
    this hit on every run. A blanket ``${WORKSPACE}/**`` does not excuse it — the escape is to
    name it — and CI had no case covering the shape at all.
    """
    blanket = _scope(filesystem={"read": ["${WORKSPACE}/**"], "write": ["${WORKSPACE}/**"]})
    assert undeclared_sensitive_hits((_WORKSPACE_GIT_WRITE,), blanket) == (_WORKSPACE_GIT_WRITE,)

    named = _scope(filesystem={"write": ["${WORKSPACE}/.git/**"]})
    assert undeclared_sensitive_hits((_WORKSPACE_GIT_WRITE,), named) == ()


def test_a_neighbouring_path_that_shares_a_prefix_does_not_excuse_the_hit() -> None:
    """``.gitignore`` starts with ``.git`` and is not inside it."""
    neighbour = _scope(filesystem={"write": ["${WORKSPACE}/.gitignore"]})
    assert undeclared_sensitive_hits((_WORKSPACE_GIT_WRITE,), neighbour) == (_WORKSPACE_GIT_WRITE,)


# ---------------------------------------------------------------------------
# The configured list
# ---------------------------------------------------------------------------


def _plan() -> RunPlan:
    scenario = Scenario.model_validate(
        {
            "id": "triggers-on-direct-request",
            "expectation": "should_trigger",
            "prompt": "go",
            "assert": [{"skill_activated": True}],
        }
    )
    return RunPlan(scenario=scenario, target=_TARGET, repetition=1)


def _executed(*paths: str) -> ExecutedRun:
    actions = tuple(
        make_action(seq, action={"tool": "read", "input": {"path": path}}, capability=None)
        for seq, path in enumerate(paths)
    )
    trace = Trace(header=make_header(), actions=actions, footer=make_footer())  # type: ignore[arg-type]
    return ExecutedRun(trace=trace, context=_CONTEXT, trace_jsonl="")


def test_a_user_added_directory_reaches_the_analysis() -> None:
    """The wiring: a directory only the caller names must still become a hit.

    ``.npmrc/`` is on no default list, so the hit can only come from the configured tuple
    arriving at ``canonicalize``. Dropping the parameter from ``analyse_run`` fails this.
    """
    executed = _executed("/home/agent/.npmrc/token")

    assert analyse_run(_plan(), executed, scope=None).sensitive_hits == ()

    configured = analyse_run(_plan(), executed, scope=None, sensitive_directories=(".npmrc/",))
    assert configured.sensitive_hits == ("outside_workspace_read:${HOME}/.npmrc/",)


def test_the_shipped_config_default_is_spelled_the_way_the_matcher_reads_it() -> None:
    """The drift guard.

    Membership is exact against the token ``sensitive_directory_of`` extracts. The config
    default said ``~/`` while the matcher yields ``~``, so connecting the two without
    reconciling them would have switched the home root off and reported nothing.
    """
    configured = MetricsConfig().sensitive_directories
    assert "~" in configured
    assert "~/" not in configured
    assert sorted(configured) == sorted(SENSITIVE_DIRECTORIES)


def test_the_home_root_is_a_hit_under_the_shipped_config() -> None:
    """The drift stated as behaviour rather than as string equality."""
    analysed = analyse_run(
        _plan(),
        _executed("/home/agent/.bash_history"),
        scope=None,
        sensitive_directories=tuple(MetricsConfig().sensitive_directories),
    )
    assert analysed.sensitive_hits == (_HOME_ROOT,)
    assert sensitive_directory_of(analysed.sensitive_hits[0]) == "~"


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("~/", "home root"),
        ("${HOME}", "home root"),
        ("~/.aws/", "home root"),
        (".config/nested/", "single directory"),
        ("${WORKSPACE}/.git/", "single directory"),
    ],
)
def test_an_entry_the_matcher_could_never_produce_is_refused(entry: str, reason: str) -> None:
    """A list entry that cannot match is worse than no entry: it reads as protection."""
    with pytest.raises(ValidationError) as error:
        MetricsConfig(sensitive_directories=[entry])
    assert reason in str(error.value)


def test_a_bare_name_entry_is_accepted() -> None:
    """Not everything without a trailing slash is a mistake.

    A file at the workspace root canonicalises to a bare tier-2 token — a read of
    ``${WORKSPACE}/.npmrc`` gives ``workspace_read:.npmrc`` — so the validator must not
    demand a trailing slash.
    """
    assert MetricsConfig(sensitive_directories=[".npmrc"]).sensitive_directories == [".npmrc"]
    analysed = analyse_run(
        _plan(),
        _executed("/work/a7f3c1/.npmrc"),
        scope=None,
        sensitive_directories=(".npmrc",),
    )
    assert analysed.sensitive_hits == ("workspace_read:.npmrc",)


# ---------------------------------------------------------------------------
# The gate's pass rests on two planes, and only one of them was tested
# ---------------------------------------------------------------------------


def _executed_with_coverage(**planes: object) -> ExecutedRun:
    from bellwether.trace import Coverage, PlaneCoverage

    defaults: dict[str, object] = {
        "harness_events": PlaneCoverage(fidelity="full"),
        "filesystem_writes": PlaneCoverage(fidelity="overlay_diff"),
        "filesystem_reads": PlaneCoverage(fidelity="unavailable", reason="no read plane"),
        "process": PlaneCoverage(fidelity="unavailable", reason="no process plane"),
    }
    header = make_header(coverage=Coverage(**(defaults | planes)))  # type: ignore[arg-type]
    trace = Trace(header=header, actions=(), footer=make_footer())
    return ExecutedRun(trace=trace, context=_CONTEXT, trace_jsonl="")


def test_both_planes_must_support_the_absence_claim() -> None:
    """Replacing the conjunction with `filesystem_writes` alone left the suite fully green.

    A sensitive hit arrives from a Plane A tool call naming a path *or* a Plane B write under a
    sensitive directory, so either plane going blind makes "nothing was touched" unearned. Only
    the Plane B half had a test.
    """
    from bellwether.trace import PlaneCoverage

    assert analyse_run(_plan(), _executed_with_coverage(), scope=None).capabilities_observed

    blind_harness = _executed_with_coverage(
        harness_events=PlaneCoverage(fidelity="unavailable", reason="adapter emitted no events")
    )
    analysed = analyse_run(_plan(), blind_harness, scope=None)
    assert not analysed.capabilities_observed
    assert analysed.capabilities_unobserved_reason == "adapter emitted no events"

    blind_writes = _executed_with_coverage(
        filesystem_writes=PlaneCoverage(fidelity="unavailable", reason="no sandbox overlay")
    )
    analysed = analyse_run(_plan(), blind_writes, scope=None)
    assert not analysed.capabilities_observed
    assert analysed.capabilities_unobserved_reason == "no sandbox overlay"


def test_the_deferral_names_the_plane_that_actually_fell_short() -> None:
    """The reason was hard-coded to Plane A, and Plane A is `full` in every path that defers.

    So the committed demo artifacts told a reader the harness plane was inadequate when the
    overlay was the missing thing, and discarded the only part a reader can act on.
    """
    from bellwether.trace import PlaneCoverage

    analysed = analyse_run(
        _plan(),
        _executed_with_coverage(
            filesystem_writes=PlaneCoverage(
                fidelity="unavailable", reason="scripted demo: no sandbox overlay"
            )
        ),
        scope=None,
    )
    assert analysed.capabilities_unobserved_reason == "scripted demo: no sandbox overlay"
    assert "Plane A" not in (analysed.capabilities_unobserved_reason or "")
