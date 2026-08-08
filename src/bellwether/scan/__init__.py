"""Static pre-flight scanning (§15).

Responsibility
    Gate 0. Detect hidden or obfuscated directives, fetch-and-execute patterns,
    credential literals, over-broad ``allowed-tools`` declarations, and the
    instrumentation probes of §3.5, and emit SARIF.

MUST NOT
    Execute skill content. Static analysis that runs the thing it is analysing is not
    static analysis.

**Not yet implemented.** The scanner is a v0.2 work package (spec §25); this module is a
placeholder with no checks. Because ``policy.gates.static.require_scan`` defaults to true,
``doctor`` surfaces an advisory when a loaded policy requires a scan this build cannot run,
rather than letting a required-but-absent scan pass silently — a required check quietly left
out reads as a check that passed, which is the failure this project exists to distrust.
"""

from __future__ import annotations

__all__: list[str] = []
