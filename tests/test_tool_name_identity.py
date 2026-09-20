"""One corpus of tool-name spellings, applied to every predicate that decides tool identity.

A tool name is an identifier a harness chooses how to spell. The api-loop harness reports
``read``/``write``/``bash``; the Claude Code CLI reports ``Read``/``Write``/``Bash``. §12.1 folds
the case so a skill can be evaluated under both, which ``claude-code-live-smoke`` — run by the
api-loop *and* the claude-code live workflows — relies on.

Two places read a tool name, and they did not agree. The §12.2 assertion catalogue in
``engine`` folded case from the day it was written. The §12.5 Declared vs Observed table in
``derive`` matched with an exact dict lookup, so ``tools.deny: [bash]`` was inert on the
claude-code harness — the *manifest*, the stronger of the two statements, was the one that did
not fire, and only on the harness nobody had run it under. The allow side was worse than inert:
``allow: [Read]`` against api-loop's ``read`` produced two wrong rows at once, the declaration
``unused`` and the call ``exceeded``, blocking a portable manifest for using exactly what it
declared.

That is the shape CLAUDE.md names as *fix the class, not the instance*: where two places
implement one rule, write one corpus and apply it to both. The rule now lives once, in
``assertions.evidence.tool_name_matches``, and this file is what keeps both readers asking it.
A third reader of a tool name is added to ``READERS`` below, or it is untested by construction.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from bellwether.assertions import evaluate, evaluate_scope
from bellwether.config.models.manifest import DeclaredScope
from bellwether.config.models.scenarios import AssertionSpec
from tests.test_assertions import index_of, make_trace, tool_call

#: Pairs that name the *same* tool in two harnesses' spellings. Each is a spelling, not a
#: special case: a predicate that folds some of these and not others is enumerating.
SAME = [
    pytest.param("bash", "Bash", id="lower-declared-upper-observed"),
    pytest.param("Bash", "bash", id="upper-declared-lower-observed"),
    pytest.param("read", "Read", id="read"),
    pytest.param("Write", "write", id="write"),
    pytest.param("WebFetch", "webfetch", id="camel-case"),
    pytest.param("grep", "GREP", id="shouted"),
]

#: And pairs that name *different* tools. Half of an identity test is that it still
#: discriminates — a predicate can fold every pair above by answering ``True`` to everything,
#: and a manifest that cannot tell ``read`` from ``write`` states nothing at all.
DIFFERENT = [
    pytest.param("read", "write", id="distinct-tools"),
    pytest.param("bash", "bashful", id="prefix"),
    pytest.param("fetch", "webfetch", id="suffix"),
    pytest.param("read", "re ad", id="internal-space"),
    pytest.param("read", "", id="empty"),
]


def _deny_says_exceeded(declared: str, observed: str) -> bool:
    """The §12.5 table's deny side — what ``bellwether run`` judges by, since it passes
    ``scope=None`` and drives the ``scope`` gate off this table alone."""
    scope = DeclaredScope.model_validate(
        {
            "tools": {"allow": [], "deny": [declared]},
            "filesystem": {"read": [], "write": [], "deny_read": []},
            "network": {"egress_allow": []},
        }
    )
    table = evaluate_scope(scope, index_of(make_trace([tool_call(5, observed)])))
    return any(entry.area == "tools" for entry in table.exceeded())


def _allow_says_supported(declared: str, observed: str) -> bool:
    """The §12.5 table's allow side. Its failure mode is the mirror: a call the manifest
    declared, reported ``exceeded`` because the harness capitalised it differently."""
    scope = DeclaredScope.model_validate(
        {
            "tools": {"allow": [declared], "deny": []},
            "filesystem": {"read": [], "write": [], "deny_read": []},
            "network": {"egress_allow": []},
        }
    )
    table = evaluate_scope(scope, index_of(make_trace([tool_call(5, observed)])))
    rows = [entry for entry in table.entries if entry.area == "tools"]
    return len(rows) == 1 and rows[0].status == "supported"


def _tool_called_passes(declared: str, observed: str) -> bool:
    """The §12.2 catalogue's positive assertion, from a scenario file."""
    index = index_of(make_trace([tool_call(5, observed)]))
    return evaluate(AssertionSpec(name="tool_called", params=declared), index).status == "pass"


def _tool_not_called_fails(declared: str, observed: str) -> bool:
    """The §12.2 catalogue's prohibition — the scenario-level twin of ``tools.deny``."""
    index = index_of(make_trace([tool_call(5, observed)]))
    return evaluate(AssertionSpec(name="tool_not_called", params=declared), index).status == "fail"


#: Every predicate that answers "is this observed call the tool that was named?". Each returns
#: True exactly when it treats the two names as the same tool, so one corpus can drive them all.
READERS: list[tuple[str, Callable[[str, str], bool]]] = [
    ("scope table, tools.deny", _deny_says_exceeded),
    ("scope table, tools.allow", _allow_says_supported),
    ("assertion catalogue, tool_called", _tool_called_passes),
    ("assertion catalogue, tool_not_called", _tool_not_called_fails),
]


@pytest.mark.parametrize(("reader", "decide"), READERS, ids=[name for name, _ in READERS])
@pytest.mark.parametrize(("declared", "observed"), SAME)
def test_every_reader_folds_case(
    reader: str, decide: Callable[[str, str], bool], declared: str, observed: str
) -> None:
    assert decide(declared, observed), f"{reader}: {declared!r} did not match {observed!r}"


@pytest.mark.parametrize(("reader", "decide"), READERS, ids=[name for name, _ in READERS])
@pytest.mark.parametrize(("declared", "observed"), DIFFERENT)
def test_every_reader_still_discriminates(
    reader: str, decide: Callable[[str, str], bool], declared: str, observed: str
) -> None:
    assert not decide(declared, observed), f"{reader}: {declared!r} wrongly matched {observed!r}"
