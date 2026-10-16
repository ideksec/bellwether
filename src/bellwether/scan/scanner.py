"""Walk a loaded skill package and apply the built-in ruleset (§15).

What is scanned
    Every file of the package except ``evals/``: the payload Bellwether installs, **and** the
    files no payload pattern matched. Those are not staged into the sandbox, but they are in
    the reviewed artifact and a harness that installs the whole directory loads them, so a
    scan limited to the payload would let a skill park its instructions in ``agents/x.md`` or
    ``notes.txt`` and be read as clean. ``evals/`` is Bellwether's machinery (§6.2): it is never
    installed, and its fixtures routinely hold the very credential-shaped bait the credential
    rules would fire on, so scanning it would report the test as the skill. It is listed as
    not scanned, with that reason, rather than silently skipped.

What is never done
    Nothing is executed, imported or followed. A symlink is reported (BW703) and not read; a
    file is read only through :func:`contained_path`, the one containment rule every host read
    of skill content goes through, and only up to a fixed bound.
"""

from __future__ import annotations

from pathlib import Path

from bellwether.scan.findings import (
    MACHINERY_REASON,
    RULESET_ID,
    ScanFinding,
    ScanReport,
    UnscannedFile,
    visible_excerpt,
)
from bellwether.scan.rules import BUILTIN_RULES, RULES_BY_ID, LineHit, scan_text
from bellwether.skill.package import SKILL_FILE, SkillPackage, contained_path

__all__ = ["MAX_SCAN_BYTES", "scan_package"]

#: Bytes of one file the scan reads. A skill file past this is scanned up to it and the
#: truncation is recorded, so a padded file cannot hide its tail by being large *and* read
#: as clean — the note says the tail was not read.
MAX_SCAN_BYTES = 1 << 20

_MARKDOWN_SUFFIXES = (".md", ".markdown", ".mdx")
_BROAD_DESCRIPTION = (
    "any task",
    "all tasks",
    "every task",
    "any request",
    "every request",
    "anything",
    "everything",
    "always use",
    "use for all",
    "use this skill for any",
)


def _read(root: Path, relative: str) -> tuple[str | None, str | None]:
    """``(text, None)``, or ``(None, reason)`` for a file the scan did not read."""
    path = contained_path(root, relative)
    if path is None:
        return None, "resolves outside the skill directory; not followed"
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_SCAN_BYTES + 1)
    except OSError as error:
        return None, f"unreadable: {type(error).__name__}"
    if b"\x00" in raw[:8192]:
        return None, "binary (NUL byte in the first 8 KiB); text rules do not apply"
    truncated = len(raw) > MAX_SCAN_BYTES
    text = raw[:MAX_SCAN_BYTES].decode("utf-8", "replace")
    return (text, "truncated") if truncated else (text, None)


def _finding(path: str, hit: LineHit, lines: list[str]) -> ScanFinding:
    rule = RULES_BY_ID[hit.rule_id]
    source = lines[hit.line - 1] if 0 < hit.line <= len(lines) else ""
    return ScanFinding(
        path=path,
        line=hit.line,
        rule_id=rule.id,
        severity=rule.severity,
        message=f"{rule.short}: {visible_excerpt(hit.message)}",
        excerpt=visible_excerpt(source, redact=hit.redact),
    )


def _package_finding(rule_id: str, path: str, message: str, line: int = 1) -> ScanFinding:
    rule = RULES_BY_ID[rule_id]
    return ScanFinding(
        path=path,
        line=line,
        rule_id=rule.id,
        severity=rule.severity,
        message=f"{rule.short}: {visible_excerpt(message)}",
        excerpt="",
    )


def _frontmatter_findings(package: SkillPackage) -> list[ScanFinding]:
    parsed = package.parsed
    findings: list[ScanFinding] = []
    front = parsed.frontmatter
    if front is None:
        return [_package_finding("BW801", SKILL_FILE, "no frontmatter block")]
    description = (front.description or "").strip()
    if not description:
        findings.append(_package_finding("BW801", SKILL_FILE, "description is empty"))
    elif not 20 <= len(description) <= 1024:
        findings.append(
            _package_finding("BW802", SKILL_FILE, f"description of {len(description)} characters")
        )
    lowered = description.lower()
    broad = sorted(phrase for phrase in _BROAD_DESCRIPTION if phrase in lowered)
    if broad:
        findings.append(_package_finding("BW803", SKILL_FILE, "says " + ", ".join(broad)))
    if front.model:
        findings.append(_package_finding("BW804", SKILL_FILE, f"model: {front.model}"))
    unexpected = sorted({*front.unknown_fields, *parsed.unusable_fields})
    if unexpected:
        findings.append(_package_finding("BW805", SKILL_FILE, "fields: " + ", ".join(unexpected)))
    tools = [tool.strip() for tool in front.allowed_tools]
    if any(tool in ("*", "all") for tool in tools):
        findings.append(_package_finding("BW602", SKILL_FILE, "allowed-tools includes '*'"))
    unrestricted = sorted(
        tool for tool in tools if tool.lower() in ("bash", "bash(*)", "bash(*:*)", "shell")
    )
    if unrestricted:
        findings.append(
            _package_finding("BW601", SKILL_FILE, "allowed-tools: " + ", ".join(unrestricted))
        )
    return findings


def scan_package(package: SkillPackage) -> ScanReport:
    """Scan one loaded package with the built-in ruleset. Deterministic: same bytes, same report."""
    included = (
        set(package.payload.included) | set(package.payload.excluded_unmatched) | {SKILL_FILE}
    )
    records = {record.path: record for record in package.files}
    findings: set[ScanFinding] = set(_frontmatter_findings(package))
    scanned: list[str] = []
    unscanned: list[UnscannedFile] = [
        UnscannedFile(path, f"{MACHINERY_REASON}; never installed with the skill")
        for path in package.payload.excluded_machinery
    ]
    notes: list[str] = []

    for path in sorted(included):
        record = records.get(path)
        if record is not None and record.is_symlink:
            findings.add(
                _package_finding("BW703", path, f"links to {record.symlink_target or '?'}")
            )
            unscanned.append(UnscannedFile(path, "symbolic link; not followed"))
            continue
        if path.startswith("agents/") or "/agents/" in path:
            findings.add(_package_finding("BW604", path, "sub-agent definition"))
        text, problem = _read(package.root, path)
        if text is None:
            unscanned.append(UnscannedFile(path, problem or "not read"))
            continue
        if problem == "truncated":
            notes.append(f"{path}: scanned the first {MAX_SCAN_BYTES} bytes only")
        scanned.append(path)
        lines = text.split("\n")
        for hit in scan_text(text, markdown=path.lower().endswith(_MARKDOWN_SUFFIXES)):
            findings.add(_finding(path, hit, lines))

    machinery = set(package.payload.excluded_machinery)
    for executable in package.executables:
        if executable.path in machinery:
            continue
        interpreter = executable.interpreter or "unknown"
        findings.add(
            _package_finding("BW701", executable.path, f"{interpreter} ({executable.source})")
        )
        if executable.interpreter is None and executable.executable_bit:
            findings.add(_package_finding("BW702", executable.path, "no shebang or extension"))

    # One finding per (path, line, rule): a line matching a rule twice is one finding.
    unique: dict[tuple[str, int, str], ScanFinding] = {}
    for finding in sorted(findings):
        unique.setdefault((finding.path, finding.line, finding.rule_id), finding)
    return ScanReport(
        findings=tuple(sorted(unique.values())),
        files_scanned=tuple(sorted(scanned)),
        files_not_scanned=tuple(sorted(set(unscanned))),
        ruleset=RULESET_ID,
        rule_count=len(BUILTIN_RULES),
        notes=tuple(sorted(notes)),
    )
