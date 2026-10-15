"""Static pre-flight scanning (§15).

Responsibility
    Gate 0. Detect hidden or obfuscated directives, fetch-and-execute patterns,
    credential literals, over-broad ``allowed-tools`` declarations, and the
    instrumentation probes of §3.5, and emit findings anchored to a file and line
    (rendered into ``findings.sarif`` by the report layer, §17.3).

MUST NOT
    Execute skill content. Static analysis that runs the thing it is analysing is not
    static analysis.

The built-in ruleset is deliberately small (§26.2): dedicated scanners are better at this
specific job, and the docs say so. What it gives ``policy.gates.static.require_scan`` is
something real to require, with no extra dependencies.
"""

from __future__ import annotations

from bellwether.scan.external import (
    MAX_SARIF_BYTES,
    ExternalScan,
    merge_external,
    read_scanner_sarif,
    scanner_name,
)
from bellwether.scan.findings import (
    RULESET_ID,
    SEVERITIES,
    ScanFinding,
    ScanReport,
    ScanRule,
    Severity,
    UnscannedFile,
    severity_rank,
    visible_excerpt,
)
from bellwether.scan.rules import BUILTIN_RULES, RULES_BY_ID
from bellwether.scan.scanner import MAX_SCAN_BYTES, scan_package

__all__ = [
    "BUILTIN_RULES",
    "MAX_SARIF_BYTES",
    "MAX_SCAN_BYTES",
    "RULESET_ID",
    "RULES_BY_ID",
    "SEVERITIES",
    "ExternalScan",
    "ScanFinding",
    "ScanReport",
    "ScanRule",
    "Severity",
    "UnscannedFile",
    "merge_external",
    "read_scanner_sarif",
    "scan_package",
    "scanner_name",
    "severity_rank",
    "visible_excerpt",
]
