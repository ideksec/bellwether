"""All output rendering: markdown, JSON, SARIF, HTML (§17).

Responsibility
    The artifact tree of §17.1, the schema-versioned ``summary.json`` of §17.2, the two
    findings containers of §17.3, the static HTML report with hand-rolled inline SVG,
    and the PR comment of §18.2.

MUST NOT
    Compute anything. Everything rendered here was decided upstream.

Built by WP-12. Presentation rules with teeth: the BCI is never rendered without the
pass rate adjacent; every figure carries ``n_evaluable`` and the look it came from; a
"consistently failing" annotation appears wherever the pass rate is below 0.5; and the
footer carries the §2 limitations verbatim. The §16.3 language lint applies to every
template in this package.
"""

from __future__ import annotations

__all__: list[str] = []
