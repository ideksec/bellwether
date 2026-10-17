"""``findings.sarif`` — the SARIF 2.1.0 container of §17.3.

§17.3 splits findings into two containers on purpose. SARIF is a static analysis format: a
result is anchored to a file and a region, which suits a static scanner (§15) and does not
suit a canary leak, whose real address is a run ID and a sequence number. So this file is not
the record of a runtime finding. It is the §17.3 *mirror*: each ``security_runtime`` gate the
verdict decided as ``block`` or ``warn`` becomes one result anchored at ``SKILL.md:1``, purely
so the GitHub Security tab is not silent about it, and every result says where the record is.

What is mirrored, and why only that
    The scored ``security_runtime`` dispositions that §10.2–§10.6, §12.5 and §13.5.4 classify
    ``critical`` or ``high`` — the ones §17.3 permits mirroring. ``egress_volume_anomaly`` is
    scored but §10.5.2 makes it a ``warn``-level signal, not a security finding, so it is not
    mirrored.
    Other gates (functional, consistency, scope, budget) are verdict gates rather than
    security findings and stay in ``summary.json`` and the reports.

Static results (§15) are the file's native content
    Every finding of the package's static scan (``summary.json`` ``security.static``) is a
    result at its real file and line, under its ``BW`` rule id. ``info`` findings are inventory
    and become ``note``s; the rest map onto ``warning``/``error`` by severity. A scan that did
    not run says so in a notification, because an empty results array would otherwise read as
    a scan that ran and found nothing. :func:`render_scan_sarif` renders the same results for
    ``bellwether scan``, with no evaluation around them.

Pure, like the other renderers
    The input is the :class:`Summary` and the persisted :class:`Figures` (which carry the skill
    directory the location is anchored under), so ``bellwether report`` can rebuild this file
    from a stored tree. The bytes go through :func:`canonical_json`: sorted keys, results in
    rule order, no clock — the only time-like value is the evaluation's own recorded id.

The skill's text is untrusted
    A gate reason can carry a path the skill chose. SARIF message text treats ``[text](uri)`` as
    an embedded link (SARIF §3.11.6), which GitHub renders, so the dynamic parts are escaped and
    a skill cannot plant a clickable link in the Security tab.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from bellwether.determinism import canonical_json, stable_hash
from bellwether.report.markdown import Figures
from bellwether.report.summary import GateSummary, Summary
from bellwether.scan import (
    BUILTIN_RULES,
    RULES_BY_ID,
    ScanFinding,
    ScanReport,
    ScanRule,
    severity_rank,
)

__all__ = [
    "SARIF_FINGERPRINT_KEY",
    "SARIF_RULES",
    "SARIF_SCHEMA_URI",
    "SARIF_STATIC_FINGERPRINT_KEY",
    "SARIF_VERSION",
    "SarifRule",
    "render_sarif",
    "render_scan_sarif",
]

SARIF_VERSION = "2.1.0"
#: The OASIS 2.1.0 schema (errata 01), the one the test suite validates against.
SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
#: The ``partialFingerprints`` key. Versioned so a change to what it hashes is a new key, not
#: a silent re-identification of every open alert.
SARIF_FINGERPRINT_KEY = "bellwetherRuntimeFinding/v1"
#: The static results' key. Hashes rule, file and excerpt — not the line — so an edit above a
#: finding moves it without re-opening it as a new alert.
SARIF_STATIC_FINGERPRINT_KEY = "bellwetherStaticFinding/v1"

_INFORMATION_URI = "https://github.com/ideksec/bellwether"
_SPEC_URI = "https://github.com/ideksec/bellwether/blob/main/docs/spec.md"

#: §17.3's anchor for a runtime finding: the skill's entry point, line 1.
_ANCHOR_FILE = "SKILL.md"

#: GitHub's numeric ``security-severity`` for each spec severity (its own bands: >= 9.0 is
#: critical, 7.0-8.9 high).
_SECURITY_SEVERITY: Mapping[str, str] = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.0",
    "info": "0.0",
}

#: §15 severity → SARIF result level for a static finding.
_STATIC_LEVEL: Mapping[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "note",
}

#: Gate status → SARIF result level. Only these two statuses are findings: ``pass`` is not one,
#: and ``not_evaluable`` is the absence of evidence, reported as a notification instead.
_LEVEL: Mapping[str, str] = {"block": "error", "warn": "warning"}


@dataclass(frozen=True)
class SarifRule:
    """One SARIF rule: a mirrored ``security_runtime`` disposition.

    ``id`` is the policy disposition name, the same word a user writes in ``policy.yaml``; it
    is the stable identity GitHub keys alerts on, so it never changes once shipped.
    """

    id: str
    gate: str
    severity: str
    name: str
    short: str
    full: str
    section: str


#: The mirrored rules, sorted by id (§24). Severities are the spec's own classifications.
SARIF_RULES: tuple[SarifRule, ...] = (
    SarifRule(
        id="canary_leak",
        gate="security_runtime.canaries",
        severity="critical",
        name="CanaryLeak",
        short="A planted canary reached a non-model destination",
        full=(
            "A planted canary marker appeared at a destination other than the model API: an "
            "egress request, a DNS query name, the final output, a written file, or tool-call "
            "arguments (spec §10.4.1)."
        ),
        section="§10.4.1",
    ),
    SarifRule(
        id="canary_without_read",
        gate="security_runtime.canary_reads",
        severity="high",
        name="CanaryWithoutRead",
        short="A planted canary reached model context with no recorded read",
        full=(
            "A planted canary appeared in a request to the model with no tool result carrying "
            "it into context, so the value arrived by a path the trace does not account for "
            "(spec §10.4.1)."
        ),
        section="§10.4.1",
    ),
    SarifRule(
        id="credential_read_undeclared",
        gate="security_runtime.credential_reads",
        severity="high",
        name="CredentialReadUndeclared",
        short="A read of a planted credential that no manifest entry declares",
        full=(
            "The skill opened a planted credential file that its manifest's "
            "credentials.expects does not declare; host-side read capture recorded the open "
            "by reference (spec §10.2, §12.5)."
        ),
        section="§12.5",
    ),
    SarifRule(
        id="dns_outside_allowlist",
        gate="security_runtime.dns",
        severity="high",
        name="DnsOutsideAllowlist",
        short="A DNS lookup outside the allowlist",
        full=(
            "The skill looked up a name outside the DNS allowlist; the controlled resolver "
            "refused it (spec §10.6)."
        ),
        section="§10.6",
    ),
    SarifRule(
        id="egress_outside_allowlist",
        gate="security_runtime.egress",
        severity="high",
        name="EgressOutsideAllowlist",
        short="Egress to a host outside the allowlist",
        full=(
            "The skill attempted network egress to a host outside the allowlist; the "
            "recording proxy refused it (spec §10.5)."
        ),
        section="§10.5",
    ),
    SarifRule(
        id="process_exec_undeclared",
        gate="security_runtime.processes",
        severity="high",
        name="ProcessExecUndeclared",
        short="A process the skill started that its manifest does not declare",
        full=(
            "A process attributed to the skill (by its process tree, not by its name) ran an "
            "executable outside the manifest's processes.allow and the platform baseline; "
            "host-side exec capture recorded its argv (spec §10.3, §12.6)."
        ),
        section="§10.3",
    ),
    SarifRule(
        id="sensitive_directory_access",
        gate="security_runtime.sensitive_directories",
        severity="high",
        name="SensitiveDirectoryAccess",
        short="An undeclared read or write under a sensitive directory",
        full=(
            "A run read or wrote under a configured sensitive directory (~/.aws/, ~/.ssh/, "
            "the home root, and the rest) that no manifest entry declares. Any single "
            "appearance is a finding, whatever its frequency (spec §13.5.4)."
        ),
        section="§13.5.4",
    ),
    SarifRule(
        id="unexpected_provider_endpoint",
        gate="security_runtime.provider_endpoint",
        severity="high",
        name="UnexpectedProviderEndpoint",
        short="A request to a provider host that was not an expected model call",
        full=(
            "A request to a model provider's host used a method, path or model the provider "
            "is not expected to receive; the proxy refused it before any key was attached "
            "(spec §10.5.2)."
        ),
        section="§10.5.2",
    ),
)

_RULE_BY_GATE: Mapping[str, tuple[int, SarifRule]] = {
    rule.gate: (index, rule) for index, rule in enumerate(SARIF_RULES)
}


def _plain(text: str) -> str:
    """Escape SARIF's embedded-link syntax (§3.11.6) so dynamic text stays plain text.

    ``[text](uri)`` in a message is a link GitHub renders; a backslash before a bracket is the
    format's own escape. The backslash itself is escaped first so the escape cannot be undone.
    """
    return text.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _anchor_uri(skill_root: str | None) -> str:
    """``<skill root>/SKILL.md``, repository-relative; bare ``SKILL.md`` for a skill at the
    repository root (``""``) or one whose root is unknown (``None``)."""
    if not skill_root:
        return _ANCHOR_FILE
    return f"{skill_root.rstrip('/')}/{_ANCHOR_FILE}"


def _rule_descriptor(rule: SarifRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.short},
        "fullDescription": {"text": rule.full},
        "help": {
            "text": (
                f"{rule.full} This result mirrors the '{rule.gate}' gate of a runtime "
                "evaluation and is anchored at SKILL.md line 1 only as a pointer; the "
                "evidence (run IDs, sequence numbers, the per-run traces) is in the "
                "evaluation's artifact tree: summary.json, verdict.json and traces/."
            )
        },
        "helpUri": _SPEC_URI,
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "bellwether-runtime"],
            "security-severity": _SECURITY_SEVERITY[rule.severity],
            "severity": rule.severity,
            "gate": rule.gate,
            "spec_section": rule.section,
        },
    }


def _fingerprint(rule: SarifRule, summary: Summary, uri: str) -> str:
    """Stable across re-runs of the same finding on the same skill, so GitHub de-duplicates.

    Deliberately excludes the eval id, the reason text and anything run-specific: a finding
    that recurs on the next push is the same alert, not a new one.
    """
    return stable_hash(f"{SARIF_FINGERPRINT_KEY}\n{rule.id}\n{summary.skill.name}\n{uri}")


def _result(
    index: int, rule: SarifRule, gate: GateSummary, summary: Summary, uri: str
) -> dict[str, Any]:
    reason = f" {_sentence(gate.reason)}" if gate.reason else ""
    observed = f" Observed: {_sentence(gate.observed)}" if gate.observed else ""
    text = (
        f"{rule.short} (gate '{gate.name}': {gate.status}).{observed}{reason} Mirrored from "
        f"runtime evaluation {_plain(summary.eval_id)} as a pointer only; the record is that "
        "evaluation's summary.json, verdict.json and traces/."
    )
    return {
        "ruleId": rule.id,
        "ruleIndex": index,
        "level": _LEVEL[gate.status],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {SARIF_FINGERPRINT_KEY: _fingerprint(rule, summary, uri)},
        "properties": {
            "eval_id": summary.eval_id,
            "gate": gate.name,
            "gate_status": gate.status,
            "required": gate.required,
            "severity": rule.severity,
        },
    }


def _notification(text: str, *, rule: tuple[int, SarifRule] | None = None) -> dict[str, Any]:
    notification: dict[str, Any] = {"level": "note", "message": {"text": text}}
    if rule is not None:
        notification["associatedRule"] = {"id": rule[1].id, "index": rule[0]}
    return notification


def _static_rule_descriptor(rule: ScanRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.short},
        "fullDescription": {"text": f"{rule.short} (§15 check: {rule.check})."},
        "help": {"text": f"{rule.short}. {rule.remediation}"},
        "helpUri": _SPEC_URI,
        "defaultConfiguration": {"level": _STATIC_LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", "bellwether-static", rule.check],
            "security-severity": _SECURITY_SEVERITY[rule.severity],
            "severity": rule.severity,
            "spec_section": "§15",
        },
    }


def _delegated_rules(*scans: ScanReport | None) -> list[tuple[str, str]]:
    """``(rule id, worst severity)`` for each external scanner's rule with a finding, sorted.

    A delegated finding's rule id is ``<tool>:<ruleId>`` (§15); the tool's own rule metadata
    is not carried over — its text is the tool's, not ours — so the descriptor says where the
    rule came from and how severe its worst result here was.
    """
    worst: dict[str, str] = {}
    for finding in (f for scan in scans if scan is not None for f in scan.findings):
        if finding.rule_id in RULES_BY_ID:
            continue
        current = worst.get(finding.rule_id)
        if current is None or severity_rank(finding.severity) > severity_rank(current):
            worst[finding.rule_id] = finding.severity
    return sorted(worst.items())


def _delegated_rule_descriptor(rule_id: str, severity: str) -> dict[str, Any]:
    tool = rule_id.split(":", 1)[0]
    short = f"Reported by the external scanner '{tool}' and merged into the static scan"
    return {
        "id": rule_id,
        "name": "Delegated" + "".join(c for c in tool.title() if c.isalnum()),
        "shortDescription": {"text": short},
        "fullDescription": {"text": f"{short} (§15 delegation)."},
        "help": {"text": f"{short}. See {tool}'s own documentation for rule '{rule_id}'."},
        "helpUri": _SPEC_URI,
        "defaultConfiguration": {"level": _STATIC_LEVEL[severity]},
        "properties": {
            "tags": ["security", "bellwether-delegated", tool],
            "security-severity": _SECURITY_SEVERITY[severity],
            "severity": severity,
            "delegated_from": tool,
            "spec_section": "§15",
        },
    }


def _static_rule_descriptors(*scans: ScanReport | None) -> list[dict[str, Any]]:
    return [
        *(_static_rule_descriptor(rule) for rule in BUILTIN_RULES),
        *(_delegated_rule_descriptor(rule_id, sev) for rule_id, sev in _delegated_rules(*scans)),
    ]


def _static_rule_index(*scans: ScanReport | None, offset: int) -> dict[str, int]:
    """Rule id → its position in the rules array :func:`_static_rule_descriptors` writes for
    the same scans, shifted by ``offset`` (the rules written before them)."""
    ids = [
        *(rule.id for rule in BUILTIN_RULES),
        *(rule_id for rule_id, _ in _delegated_rules(*scans)),
    ]
    return {rule_id: offset + i for i, rule_id in enumerate(ids)}


def _static_uri(skill_root: str | None, path: str) -> str:
    return f"{skill_root.rstrip('/')}/{path}" if skill_root else path


def _static_result(
    finding: ScanFinding, index: int, skill_name: str, skill_root: str | None
) -> dict[str, Any]:
    uri = _static_uri(skill_root, finding.path)
    fingerprint = stable_hash(
        f"{SARIF_STATIC_FINGERPRINT_KEY}\n{finding.rule_id}\n{skill_name}\n{uri}\n"
        f"{finding.excerpt}\n{finding.message}"
    )
    region: dict[str, Any] = {"startLine": max(finding.line, 1)}
    if finding.excerpt:
        region["snippet"] = {"text": finding.excerpt}
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": index,
        "level": _STATIC_LEVEL[finding.severity],
        "message": {"text": _sentence(finding.message)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {SARIF_STATIC_FINGERPRINT_KEY: fingerprint},
        "properties": {"severity": finding.severity},
    }


def _static_results(
    scan: ScanReport, *, index: Mapping[str, int], skill_name: str, skill_root: str | None
) -> list[dict[str, Any]]:
    return [
        _static_result(finding, index[finding.rule_id], skill_name, skill_root)
        for finding in scan.findings
        if finding.rule_id in index
    ]


def _static_notifications(scan: ScanReport, *, prefix: str = "") -> list[dict[str, Any]]:
    notes = [
        _notification(f"{prefix}{_plain(u.path)} was not scanned: {_plain(u.reason)}.")
        for u in scan.unscanned_outside_machinery()
    ]
    if scan.machinery_unscanned:
        notes.append(
            _notification(
                f"{prefix}{scan.machinery_unscanned} file(s) under evals/ were not scanned: "
                "evaluation machinery, never installed with the skill."
            )
        )
    notes.extend(_notification(f"{prefix}{_plain(note)}.") for note in scan.notes)
    return notes


def render_scan_sarif(scans: Sequence[tuple[str, str | None, ScanReport]], *, version: str) -> str:
    """``bellwether scan --sarif``: static results only, **one run** for every scanned skill.

    Each entry is ``(skill name, repository-relative skill root or None, report)``. One run with
    one category, rather than a run per skill: GitHub keys an analysis on tool and category,
    and the Gate 0 workflow uploads every skill's results together, so one run is the shape
    that replaces the previous upload cleanly. Each result's URI carries its skill's directory
    and each fingerprint its skill's name, so two skills' findings never merge.
    """
    reports = [scan for _, _, scan in scans]
    index = _static_rule_index(*reports, offset=0)
    results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []
    for skill_name, skill_root, scan in scans:
        results.extend(
            _static_results(scan, index=index, skill_name=skill_name, skill_root=skill_root)
        )
        prefix = f"{_plain(skill_name)}: "
        notifications.extend(_static_notifications(scan, prefix=prefix))
        if skill_root is None:
            notifications.append(
                _notification(
                    f"{prefix}the skill directory was not known relative to the repository, so "
                    "its results are anchored at paths relative to the skill."
                )
            )
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Bellwether",
                "informationUri": _INFORMATION_URI,
                "version": version,
                "rules": _static_rule_descriptors(*reports),
            }
        },
        "automationDetails": {"id": "bellwether-static/"},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
        "results": results,
        "properties": {
            "skills": [
                {
                    "name": skill_name,
                    "root": skill_root,
                    "ruleset": scan.ruleset,
                    "scanners": list(scan.scanners),
                    "worst": scan.worst,
                }
                for skill_name, skill_root, scan in scans
            ],
        },
    }
    return (
        canonical_json(
            {"$schema": SARIF_SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}, indent=2
        )
        + "\n"
    )


def render_sarif(summary: Summary, figures: Figures) -> str:
    """Render ``findings.sarif`` (SARIF 2.1.0) from a summary and its persisted figures."""
    uri = _anchor_uri(figures.skill_root)
    results: list[dict[str, Any]] = []
    unobserved: list[dict[str, Any]] = []
    for gate in summary.verdict.gates:
        entry = _RULE_BY_GATE.get(gate.name)
        if entry is None:
            continue
        index, rule = entry
        if gate.status in _LEVEL:
            results.append(_result(index, rule, gate, summary, uri))
        elif gate.status == "not_evaluable":
            unobserved.append(
                _notification(
                    f"'{gate.name}' was not evaluable in this evaluation, so the absence of any "
                    f"'{rule.id}' result here is not a clean reading:{_reason_suffix(gate)}",
                    rule=entry,
                )
            )
    results.sort(key=lambda r: (r["ruleIndex"], r["level"]))
    static = ScanReport.from_record(summary.security.static) if summary.security.static else None
    notifications = sorted(unobserved, key=lambda n: n["associatedRule"]["index"])
    if static is None:
        notifications.insert(
            0,
            _notification(
                "No static scan (§15) was recorded for this evaluation: this file carries no "
                "static results, only the runtime findings §17.3 permits mirroring."
            ),
        )
    else:
        results.extend(
            _static_results(
                static,
                index=_static_rule_index(static, offset=len(SARIF_RULES)),
                skill_name=summary.skill.name,
                skill_root=figures.skill_root,
            )
        )
        notifications.extend(_static_notifications(static))
    if figures.skill_root is None:
        notifications.append(
            _notification(
                "The skill directory was not known relative to the repository, so results are "
                "anchored at a bare SKILL.md."
            )
        )
    targets = "+".join(summary.matrix.target_slugs) or "matrix"
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Bellwether",
                "informationUri": _INFORMATION_URI,
                "version": summary.bellwether_version,
                "rules": [
                    *(_rule_descriptor(rule) for rule in SARIF_RULES),
                    *_static_rule_descriptors(static),
                ],
            }
        },
        # GitHub replaces a category's alerts on each upload; one category per skill and
        # target set keeps two skills (or two harnesses) in one PR from erasing each other.
        "automationDetails": {"id": f"bellwether/{summary.skill.name}/{targets}/"},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
        "results": results,
        "properties": {
            "eval_id": summary.eval_id,
            "verdict": summary.verdict.status,
            "policy_profile": summary.policy.profile,
            "skill": summary.skill.name,
            "payload_digest": summary.skill.payload_digest,
            "static_scan": static.ruleset if static is not None else "not recorded",
            "record": "summary.json",
        },
    }
    return (
        canonical_json(
            {"$schema": SARIF_SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}, indent=2
        )
        + "\n"
    )


def _reason_suffix(gate: GateSummary) -> str:
    return f" {_sentence(gate.reason)}" if gate.reason else " no reason was recorded."


def _sentence(text: str) -> str:
    """Dynamic text, escaped, ending in exactly one full stop."""
    return _plain(text.rstrip().rstrip(".")) + "."
