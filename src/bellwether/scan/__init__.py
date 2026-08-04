"""Static pre-flight scanning (§15).

Responsibility
    Gate 0. Detect hidden or obfuscated directives, fetch-and-execute patterns,
    credential literals, over-broad ``allowed-tools`` declarations, and the
    instrumentation probes of §3.5, and emit SARIF.

MUST NOT
    Execute skill content. Static analysis that runs the thing it is analysing is not
    static analysis.

Built in v0.1 for the corpus cases (``fetch-and-exec``, ``obfuscated-injection``,
``eval-aware``); broadened in v0.2.
"""

from __future__ import annotations

__all__: list[str] = []
