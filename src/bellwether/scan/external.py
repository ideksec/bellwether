"""Delegation to external static scanners (§15, §26.2) — by ingesting what they wrote.

§15 recommends delegating to dedicated scanners and sketches a ``scanners:`` config that names
the tools. This build reads their **output** and never runs them. The config file lives in the
evaluated checkout, which a pull request edits; the project already refuses to take a trusted
model host from it for that reason (§3.3). A command list there would be a way for a PR author to
run anything on the host that holds the API key. So the tools run in their own CI step, under the
workflow's control, and hand Bellwether a SARIF 2.1.0 file each (``--scanner-sarif``). Nearly
every scanner worth delegating to — Semgrep, Gitleaks, Trivy, Bandit, CodeQL — writes SARIF, so
SARIF is the one normaliser.

What a result becomes
    A :class:`ScanFinding` with rule id ``<tool>:<ruleId>``, at the skill-relative path and line
    the result names. Severity comes from the rule's or result's ``security-severity`` where the
    tool set one (GitHub's bands: ≥ 9.0 critical, ≥ 7.0 high, ≥ 4.0 medium, > 0 low), else from
    the result's ``level`` (``error`` high, ``warning`` medium, ``note`` low, ``none`` info).

What is never copied
    A tool's own snippet. A secret scanner's snippet is the secret, and an excerpt reaches the PR
    comment and the Security tab; the finding carries the location, and the file is one click
    away. The tool's message is kept, reduced like every excerpt, with the built-in credential
    patterns redacted from it.

What is refused rather than skipped
    A file that is not SARIF 2.1.0, is larger than the bound, or names no tool: it was supplied
    as evidence, so it is either read or the run stops. Results outside the skill directory are
    not this skill's and are counted in a note, never silently dropped.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from bellwether.errors import BellwetherError
from bellwether.scan.findings import ScanFinding, ScanReport, Severity, visible_excerpt
from bellwether.scan.rules import SECRET_PATTERNS

__all__ = [
    "MAX_SARIF_BYTES",
    "ExternalScan",
    "merge_external",
    "read_scanner_sarif",
    "scanner_name",
]

#: A SARIF file larger than this is refused, not read: the loader must not be the thing that
#: dies of an attacker-sized input (the same bound reasoning as the skill loader's).
MAX_SARIF_BYTES = 32 << 20

_LEVEL_SEVERITY: Mapping[str, Severity] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}
_TOOL_NAME = re.compile(r"[^a-z0-9._-]+")


def scanner_name(raw: str) -> str:
    """A tool's name as policy names it: lower-case, one token (``"Semgrep OSS"`` → ``semgrep-oss``)."""
    return _TOOL_NAME.sub("-", raw.strip().lower()).strip("-") or "unnamed"


@dataclass(frozen=True)
class _Result:
    tool: str
    rule_id: str
    severity: Severity
    message: str
    uri: str
    line: int


@dataclass(frozen=True)
class ExternalScan:
    """One supplied SARIF file, parsed: the tools it names and every result it carries."""

    source: str
    tools: tuple[str, ...]
    results: tuple[_Result, ...]


def _security_severity(value: object) -> Severity | None:
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> Sequence[Any]:
    return value if isinstance(value, list) else []


def _refuse(source: str, why: str) -> BellwetherError:
    return BellwetherError(
        f"scanner SARIF {source}: {why}; a scanner result supplied as evidence is read or the "
        "run stops — it is never skipped, because a skipped file reads as a scanner that found "
        "nothing"
    )


def read_scanner_sarif(path: Path) -> ExternalScan:
    """Parse one SARIF 2.1.0 file, or raise :class:`BellwetherError` saying why it cannot be."""
    source = str(path)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise _refuse(source, f"cannot be read ({type(error).__name__})") from None
    if size > MAX_SARIF_BYTES:
        raise _refuse(source, f"is {size} bytes, over the {MAX_SARIF_BYTES}-byte bound")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise _refuse(source, f"is not JSON ({type(error).__name__})") from None
    if not isinstance(document, Mapping) or document.get("version") != "2.1.0":
        raise _refuse(source, "is not a SARIF 2.1.0 log (no top-level version 2.1.0)")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise _refuse(source, "has no runs")

    tools: list[str] = []
    results: list[_Result] = []
    for run in runs:
        driver = _mapping(_mapping(_mapping(run).get("tool")).get("driver"))
        raw_name = driver.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise _refuse(source, "has a run whose tool.driver.name is missing")
        tool = scanner_name(raw_name)
        tools.append(tool)
        rules = _sequence(driver.get("rules"))
        rule_severity: dict[str, Severity] = {}
        for rule in rules:
            rule = _mapping(rule)
            rule_id = rule.get("id")
            if not isinstance(rule_id, str):
                continue
            scored = _security_severity(_mapping(rule.get("properties")).get("security-severity"))
            level = _mapping(rule.get("defaultConfiguration")).get("level")
            graded = scored or _LEVEL_SEVERITY.get(level) if isinstance(level, str) else scored
            if graded is not None:
                rule_severity[rule_id] = graded
        for result in _sequence(_mapping(run).get("results")):
            result = _mapping(result)
            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str):
                rule_id = str(_mapping(result.get("rule")).get("id", "unidentified"))
            severity = (
                _security_severity(_mapping(result.get("properties")).get("security-severity"))
                or rule_severity.get(rule_id)
                or _LEVEL_SEVERITY.get(str(result.get("level", "warning")), "medium")
            )
            message = _mapping(result.get("message")).get("text")
            locations = _sequence(result.get("locations"))
            physical = _mapping(_mapping(locations[0] if locations else {}).get("physicalLocation"))
            artifact = _mapping(physical.get("artifactLocation"))
            uri = artifact.get("uri")
            start = _mapping(physical.get("region")).get("startLine", 1)
            results.append(
                _Result(
                    tool=tool,
                    rule_id=rule_id,
                    severity=severity,
                    message=message if isinstance(message, str) else "",
                    uri=uri if isinstance(uri, str) else "",
                    line=start if isinstance(start, int) and start > 0 else 1,
                )
            )
    return ExternalScan(source=source, tools=tuple(tools), results=tuple(results))


def _skill_relative(uri: str, *, skill_root: Path, base: Path) -> str | None:
    """The result's file relative to the skill, or ``None`` when it is outside it.

    A ``file://`` URI or an absolute path is taken as it is; anything else is relative to
    ``base`` (the repository root the scanners ran from). Containment is decided on resolved
    paths, so ``..`` and symlinked parents are one question, as in the skill loader.
    """
    if not uri:
        return None
    parsed = urlparse(uri)
    if parsed.scheme == "file":
        candidate = Path(unquote(parsed.path))
    elif parsed.scheme:
        return None
    else:
        candidate = Path(unquote(uri))
        if not candidate.is_absolute():
            candidate = base / candidate
    try:
        resolved = candidate.resolve()
        root = skill_root.resolve()
    except (OSError, RuntimeError):
        return None
    if resolved != root and root not in resolved.parents:
        return None
    relative = resolved.relative_to(root).as_posix()
    return relative or None


def _message(result: _Result) -> str:
    """The tool's message, with every built-in credential pattern cut before it is stored."""
    text = result.message
    spans = tuple(span for pattern, _ in SECRET_PATTERNS for span in _spans(pattern, text))
    return visible_excerpt(text, redact=spans) or "(no message)"


def _spans(pattern: re.Pattern[str], text: str) -> list[tuple[int, int]]:
    return [match.span() for match in pattern.finditer(text)]


def merge_external(
    report: ScanReport,
    scans: Sequence[ExternalScan],
    *,
    skill_root: Path,
    base: Path,
) -> ScanReport:
    """``report`` with every in-skill result of ``scans`` added, and the tools recorded."""
    findings = set(report.findings)
    outside: dict[str, int] = {}
    for scan in scans:
        for result in scan.results:
            path = _skill_relative(result.uri, skill_root=skill_root, base=base)
            if path is None:
                outside[result.tool] = outside.get(result.tool, 0) + 1
                continue
            findings.add(
                ScanFinding(
                    path=str(PurePosixPath(path)),
                    line=result.line,
                    rule_id=f"{result.tool}:{result.rule_id}",
                    severity=result.severity,
                    message=_message(result),
                    excerpt="",
                )
            )
    notes = list(report.notes)
    notes.extend(
        f"{tool}: {count} result(s) outside this skill's directory, not attributed to it"
        for tool, count in sorted(outside.items())
    )
    tools = sorted({*report.scanners, *(tool for scan in scans for tool in scan.tools)})
    unique: dict[tuple[str, int, str], ScanFinding] = {}
    for finding in sorted(findings):
        unique.setdefault((finding.path, finding.line, finding.rule_id), finding)
    return ScanReport(
        findings=tuple(sorted(unique.values())),
        files_scanned=report.files_scanned,
        files_not_scanned=report.files_not_scanned,
        ruleset=report.ruleset,
        rule_count=report.rule_count,
        notes=tuple(sorted(notes)),
        scanners=tuple(tools),
    )
