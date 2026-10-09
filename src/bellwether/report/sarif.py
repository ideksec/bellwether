"""``findings.sarif`` — the SARIF 2.1.0 container of §17.3.

§17.3 splits findings into two containers on purpose. SARIF is a static analysis format: a
result is anchored to a file and a region, which suits a static scanner (§15) and does not
suit a canary leak, whose real address is a run ID and a sequence number. So this file is not
the record of a runtime finding. It is the §17.3 *mirror*: each ``security_runtime`` gate the
verdict decided as ``block`` or ``warn`` becomes one result anchored at ``SKILL.md:1``, purely
so the GitHub Security tab is not silent about it, and every result says where the record is.

What is mirrored, and why only that
    The six scored ``security_runtime`` dispositions — the findings §10.4.1, §10.5, §10.6 and
    §13.5.4 classify ``critical`` or ``high``, which are the ones §17.3 permits mirroring.
    Other gates (functional, consistency, scope, budget) are verdict gates rather than
    security findings and stay in ``summary.json`` and the reports. The §15 static scanner is
    not built in this version, so there are no static results; the run's properties and a
    tool notification say so, because an empty results array would otherwise read as a scan
    that ran and found nothing.

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

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from bellwether.determinism import canonical_json, stable_hash
from bellwether.report.markdown import Figures
from bellwether.report.summary import GateSummary, Summary

__all__ = [
    "SARIF_FINGERPRINT_KEY",
    "SARIF_RULES",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "SarifRule",
    "render_sarif",
]

SARIF_VERSION = "2.1.0"
#: The OASIS 2.1.0 schema (errata 01), the one the test suite validates against.
SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
#: The ``partialFingerprints`` key. Versioned so a change to what it hashes is a new key, not
#: a silent re-identification of every open alert.
SARIF_FINGERPRINT_KEY = "bellwetherRuntimeFinding/v1"

_INFORMATION_URI = "https://github.com/ideksec/bellwether"
_SPEC_URI = "https://github.com/ideksec/bellwether/blob/main/docs/spec.md"

#: §17.3's anchor for a runtime finding: the skill's entry point, line 1.
_ANCHOR_FILE = "SKILL.md"

#: GitHub's numeric ``security-severity`` for each spec severity (its own bands: >= 9.0 is
#: critical, 7.0-8.9 high).
_SECURITY_SEVERITY: Mapping[str, str] = {"critical": "9.5", "high": "7.5"}

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
    notifications = [
        _notification(
            "No static scan (§15) is built in this version: this file carries no static "
            "results, only the runtime findings §17.3 permits mirroring."
        ),
        *sorted(unobserved, key=lambda n: n["associatedRule"]["index"]),
    ]
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
                "rules": [_rule_descriptor(rule) for rule in SARIF_RULES],
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
            "static_scan": "not built in this version",
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
