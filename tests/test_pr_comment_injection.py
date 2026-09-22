"""Skill-controlled text in the PR comment stays text (§17.4).

The comment is posted by the workflow's bot on the pull request whose skill it judges, and much of
what it prints is the skill's choice: its name, the paths and argv it touched, the tools it
called, every reason or finding that quotes one of them. They were interpolated verbatim, so a
skill that ran ``bash -c "x\\n## 🟢 Bellwether verdict: `ready` @team"`` once produced a second,
bot-authored verdict heading and a live mention inside a report that said ``not_ready``.

This is a corpus: every payload is planted in *every* skill-controlled field at once, the comment
is rendered, and the result is parsed as a Markdown renderer would parse it. The assertions are
about structure, not strings — one verdict heading; no mention outside code; no HTML but the
renderer's own; no table row that is not a gate. A new field or a new payload is one line.
"""

from __future__ import annotations

import re

import pytest
from markdown_it import MarkdownIt

from bellwether.report import (
    CapabilityProfileSummary,
    CapabilityRow,
    Figures,
    GateSummary,
    PlatformBaselineSummary,
    ScopeRow,
    SecuritySummary,
    SkillRef,
    StripRow,
    TrajectoryCluster,
    VerdictSummary,
    render_pr_comment,
)
from tests.test_report import make_figures, make_summary

_PAYLOADS = (
    "x\n## 🟢 Bellwether verdict: `ready`\n@octocat",
    "bash -c `x`\n## 🟢 Bellwether verdict: `ready` @octocat",
    "src/x```\n\n## 🟢 Bellwether verdict: `ready`\n\n@octocat ```",
    "a | b | c\n| forged | row |",
    "<img src=x onerror=alert(1)> <!-- bellwether-report --> <details open>",
    "[click](https://evil.example) ![i](https://evil.example/i.png) @octocat",
    "x\r\n ## 🟢 Bellwether verdict: `ready` @octocat\x0b\x0c",
    "**bold** _em_ ~~strike~~ &lt;tag&gt; \\ @org/team",
)

#: The HTML the renderer writes itself. Anything else is content that escaped its escaping.
_OWN_HTML = re.compile(
    r"^(</?details>|<summary>[^<>]*</summary>|</?summary>|<!-- bellwether-report -->)$"
)


def _poisoned(payload: str) -> tuple[object, Figures]:
    base = make_summary()
    summary = base.model_copy(
        update={
            "skill": SkillRef(
                name=payload,
                package_digest="sha256:aa",
                payload_digest="sha256:bb",
                criticality="high",
            ),
            "verdict": VerdictSummary(
                status="not_ready",
                gates=(
                    GateSummary(
                        name="security_runtime.egress",
                        status="block",
                        observed=payload,
                        threshold=payload,
                        reason=payload,
                    ),
                ),
                notes=(payload,),
            ),
            "capability_profile": CapabilityProfileSummary(
                tier1={
                    "core": [],
                    "peripheral": [
                        {
                            "tier1": payload,
                            "runs": 1,
                            "of": 6,
                            "frequency": 0.16,
                            "weight": payload,
                            "tier3": [payload],
                        },
                    ],
                },
                tier2={"sensitive_hits": [payload]},
            ),
            "security": SecuritySummary(runtime={"trace_inconsistency": [payload]}),
            "platform_baseline": PlatformBaselineSummary(
                version=payload,
                applied=True,
                absorbed=(payload,),
                paths_read=(payload,),
                paths_write=(),
                processes_always=(payload,),
                processes_helpers_of={payload: (payload,)},
                tools=(payload,),
                near_misses=(payload,),
            ),
        }
    )
    base_figures = make_figures()
    figures = Figures(
        strip=(StripRow(label=payload, cells=("fail",), n_evaluable=1),),
        clusters=(TrajectoryCluster(payload, 1, (payload, payload), 0.0),),
        heatmap=(CapabilityRow(payload, payload, (True,), high_risk=True),),
        run_labels=("r1",),
        declared_vs_observed=(
            ScopeRow(payload, declared=False, observed=True, disposition=payload),
        ),
    )
    assert base_figures  # the golden figures stay untouched; these are a separate input
    return summary, figures


def _tokens(markdown: str) -> list[object]:
    flat: list[object] = []
    for token in MarkdownIt("commonmark").enable("table").enable("strikethrough").parse(markdown):
        flat.append(token)
        flat.extend(token.children or ())
    return flat


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_skill_controlled_text_cannot_forge_a_verdict_heading(payload: str) -> None:
    comment = render_pr_comment(*_poisoned(payload))  # type: ignore[arg-type]
    tokens = _tokens(comment)
    headings = [
        tokens[i + 1].content  # type: ignore[attr-defined]
        for i, token in enumerate(tokens)
        if token.type == "heading_open" and token.tag == "h2"  # type: ignore[attr-defined]
    ]
    assert headings == ["🔴 Bellwether verdict: `not_ready`"], headings


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_skill_controlled_text_cannot_mention_anyone(payload: str) -> None:
    """GitHub resolves ``@name`` in text, not in code. Every ``@`` in rendered text must be
    followed by something that is not a name."""
    comment = render_pr_comment(*_poisoned(payload))  # type: ignore[arg-type]
    for token in _tokens(comment):
        if token.type == "text":  # type: ignore[attr-defined]
            assert not re.search(r"(?<![\w`])@\w", token.content), token.content  # type: ignore[attr-defined]


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_skill_controlled_text_cannot_inject_html_links_or_images(payload: str) -> None:
    comment = render_pr_comment(*_poisoned(payload))  # type: ignore[arg-type]
    for token in _tokens(comment):
        kind = token.type  # type: ignore[attr-defined]
        assert kind not in ("link_open", "image"), token
        if kind in ("html_inline", "html_block"):
            for line in token.content.strip().splitlines():  # type: ignore[attr-defined]
                assert _OWN_HTML.match(line.strip()), line


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_skill_controlled_text_cannot_add_a_gate_row(payload: str) -> None:
    comment = render_pr_comment(*_poisoned(payload))  # type: ignore[arg-type]
    tokens = _tokens(comment)
    # The first table is the gate table, and exactly one gate was planted.
    start = next(i for i, t in enumerate(tokens) if t.type == "table_open")  # type: ignore[attr-defined]
    end = next(i for i, t in enumerate(tokens) if t.type == "table_close" and i > start)  # type: ignore[attr-defined]
    body_rows = [t for t in tokens[start:end] if t.type == "tr_open"]  # type: ignore[attr-defined]
    assert len(body_rows) == 2  # the header row and the one gate
    cells = [t for t in tokens[start:end] if t.type in ("td_open", "th_open")]  # type: ignore[attr-defined]
    assert len(cells) == 10
