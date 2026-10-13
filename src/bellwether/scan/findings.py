"""The §15 finding record, its severity scale, and the report a scan produces.

A static finding is anchored where SARIF wants it — a file and a line — because, unlike a
runtime finding (§17.3), it really has one. Everything here is plain data: the gate that turns a
report into ``pass``/``block`` lives with the other gates in the composition, so this layer never
sees a policy type (§8.1).

The excerpt is skill-authored text
    It is what a reviewer reads in the PR comment, the HTML report and the Security tab, so it is
    reduced before it is stored: whitespace collapsed, length capped, every invisible or
    direction-changing character spelled as ``<U+XXXX>`` (an excerpt that *carries* a bidi
    override re-performs the attack it reports), and a matched secret cut to its prefix (a
    scanner that copies a leaked key into a public artifact has widened the leak it found).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

__all__ = [
    "RULESET_ID",
    "SEVERITIES",
    "ScanFinding",
    "ScanReport",
    "ScanRule",
    "Severity",
    "UnscannedFile",
    "severity_rank",
    "visible_excerpt",
]

#: The §15 scale, lowest first. ``info`` is below every policy threshold: it is inventory, never
#: a reason to block.
Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")

#: Names the ruleset a report was produced by. Bumped when a rule is added, removed or re-graded,
#: so two reports are comparable exactly when they carry the same id.
RULESET_ID = "bellwether-builtin/1"

#: An excerpt longer than this is cut; the finding's line number is the way back to the rest.
_EXCERPT_CHARS = 160


def severity_rank(severity: str) -> int:
    """Position on the §15 scale; ``ValueError`` for a word that is not on it."""
    return SEVERITIES.index(severity)  # type: ignore[arg-type,unused-ignore]


@dataclass(frozen=True)
class ScanRule:
    """One built-in rule. ``id`` is the stable identity alerts are keyed on; never reused."""

    id: str
    check: str
    severity: Severity
    name: str
    short: str
    remediation: str


@dataclass(frozen=True, order=True)
class ScanFinding:
    """One static finding. Ordered by location, then rule, so a report sorts deterministically."""

    path: str
    line: int
    rule_id: str
    severity: Severity
    message: str
    excerpt: str

    def as_record(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True, order=True)
class UnscannedFile:
    """A file the scan did not read, and why — never silently left out (§10.0)."""

    path: str
    reason: str


@dataclass(frozen=True)
class ScanReport:
    """Everything one scan of one package found, and everything it did not look at."""

    findings: tuple[ScanFinding, ...]
    files_scanned: tuple[str, ...]
    files_not_scanned: tuple[UnscannedFile, ...] = ()
    ruleset: str = RULESET_ID
    rule_count: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)

    def counts(self) -> dict[str, int]:
        return {
            severity: sum(1 for f in self.findings if f.severity == severity)
            for severity in SEVERITIES
        }

    def above(self, threshold: str) -> tuple[ScanFinding, ...]:
        """The findings strictly more severe than ``threshold``, in report order."""
        limit = severity_rank(threshold)
        return tuple(f for f in self.findings if severity_rank(f.severity) > limit)

    def as_record(self) -> dict[str, object]:
        """The ``summary.json`` ``security.static`` block (§17.2). Sorted, clock-free (§24)."""
        return {
            "ruleset": self.ruleset,
            "rule_count": self.rule_count,
            "worst": self.worst,
            "counts": self.counts(),
            "files_scanned": list(self.files_scanned),
            "files_not_scanned": [
                {"path": u.path, "reason": u.reason} for u in self.files_not_scanned
            ],
            "findings": [f.as_record() for f in self.findings],
            "notes": list(self.notes),
        }

    @classmethod
    def from_record(cls, record: Mapping[str, object]) -> ScanReport:
        """Rebuild a report from its ``summary.json`` block (``bellwether report``)."""
        raw_findings = record.get("findings", [])
        findings = tuple(
            ScanFinding(
                path=str(item["path"]),
                line=int(item["line"]),
                rule_id=str(item["rule_id"]),
                severity=item["severity"],
                message=str(item["message"]),
                excerpt=str(item["excerpt"]),
            )
            for item in raw_findings  # type: ignore[attr-defined]
        )
        raw_unscanned = record.get("files_not_scanned", [])
        return cls(
            findings=findings,
            files_scanned=tuple(str(p) for p in record.get("files_scanned", [])),  # type: ignore[attr-defined]
            files_not_scanned=tuple(
                UnscannedFile(path=str(u["path"]), reason=str(u["reason"]))
                for u in raw_unscanned  # type: ignore[attr-defined]
            ),
            ruleset=str(record.get("ruleset", RULESET_ID)),
            rule_count=int(record.get("rule_count", 0)),  # type: ignore[call-overload]
            notes=tuple(str(n) for n in record.get("notes", [])),  # type: ignore[attr-defined]
        )


def _visible(char: str) -> str:
    category = unicodedata.category(char)
    # Cf: format characters (zero-width, bidi controls, BOM); Cc: controls other than tab;
    # Co/Cn: private use and unassigned. Each is spelled, never emitted.
    if category in ("Cf", "Co", "Cn") or (category == "Cc" and char != "\t"):
        return f"<U+{ord(char):04X}>"
    return char


def visible_excerpt(text: str, *, redact: tuple[tuple[int, int], ...] = ()) -> str:
    """``text`` reduced to a reduced, single-line, length-capped excerpt.

    ``redact`` spans (start, end) are cut to their first four characters plus ``…`` before
    anything else happens, so a secret never survives into the record.
    """
    for start, end in sorted(redact, reverse=True):
        text = text[:start] + text[start : min(end, start + 4)] + "…<redacted>" + text[end:]
    spelled = "".join(_visible(c) for c in text)
    collapsed = " ".join(spelled.split())
    if len(collapsed) > _EXCERPT_CHARS:
        return collapsed[: _EXCERPT_CHARS - 1] + "…"
    return collapsed
