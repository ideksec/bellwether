"""``findings.sarif`` — the §17.3 SARIF 2.1.0 mirror of the runtime security findings.

Validated against the official OASIS SARIF 2.1.0 JSON schema, vendored at
``tests/schemas/sarif-schema-2.1.0.json`` and pinned here by sha256 so an edited or swapped
schema fails the build rather than quietly loosening the check. The wiring tests (the run
path writes or withholds the file per ``reporting.sarif``; a leaking run produces the
``canary_leak`` result) live beside the paths they wire: ``test_run.py`` and
``test_orchestrator.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from bellwether.cli.run import repository_relative_root
from bellwether.report import (
    SARIF_RULES,
    Figures,
    GateSummary,
    Summary,
    figures_from_json,
    render_figures_json,
    render_sarif,
)
from bellwether.report.sarif import SARIF_FINGERPRINT_KEY

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA_PATH = _ROOT / "tests" / "schemas" / "sarif-schema-2.1.0.json"
#: Where the vendored schema came from, and the bytes it had when vendored.
_SCHEMA_SOURCE = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
_SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
_REPORTS = _ROOT / "examples" / "reports"
_SNEAKY = _REPORTS / "demo-sneaky-exfiltrator"


def _validator() -> jsonschema.protocols.Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)  # type: ignore[no-any-return]


def assert_valid_sarif(text: str) -> dict[str, Any]:
    """Parse ``text`` and validate it against the vendored 2.1.0 schema; return the document."""
    document: dict[str, Any] = json.loads(text)
    errors = sorted(_validator().iter_errors(document), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(f"{list(e.absolute_path)}: {e.message}" for e in errors)
    return document


def _summary() -> Summary:
    return Summary.model_validate_json((_SNEAKY / "summary.json").read_text(encoding="utf-8"))


def _with_gates(summary: Summary, *gates: GateSummary) -> Summary:
    verdict = summary.verdict.model_copy(update={"gates": gates})
    return summary.model_copy(update={"verdict": verdict})


# ---------------------------------------------------------------------------
# The schema itself
# ---------------------------------------------------------------------------


def test_the_vendored_schema_is_the_pinned_one() -> None:
    digest = hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()
    assert digest == _SCHEMA_SHA256, (
        f"{_SCHEMA_PATH} is not the schema fetched from {_SCHEMA_SOURCE}"
    )
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["id"] == _SCHEMA_SOURCE
    assert "2.1.0" in schema["title"]


def test_the_validator_rejects_what_the_schema_forbids() -> None:
    """The check has teeth: a document missing a required field, or with a level the format
    does not define, is refused — so a passing validation means something."""
    document = json.loads((_SNEAKY / "findings.sarif").read_text(encoding="utf-8"))
    document["runs"][0]["results"][0]["level"] = "critical"
    with pytest.raises(AssertionError, match="level"):
        assert_valid_sarif(json.dumps(document))
    del document["runs"][0]["tool"]
    with pytest.raises(AssertionError, match="tool"):
        assert_valid_sarif(json.dumps(document))


@pytest.mark.parametrize(
    "eval_id",
    ["demo-benign-note-taker", "demo-flaky-formatter", "demo-sneaky-exfiltrator"],
)
def test_every_committed_demo_sarif_validates(eval_id: str) -> None:
    document = assert_valid_sarif((_REPORTS / eval_id / "findings.sarif").read_text("utf-8"))
    assert document["version"] == "2.1.0"


@pytest.mark.parametrize("status", ["block", "warn"])
def test_every_rule_produces_a_schema_valid_result(status: str) -> None:
    """All six mirrored rules at once, at both finding levels — the shapes the demo trees do
    not reach (the demo has no proxy, resolver or canaries)."""
    gates = tuple(
        GateSummary(name=rule.gate, status=status, observed="o", reason=f"t: {rule.id}")  # type: ignore[arg-type]
        for rule in SARIF_RULES
    )
    document = assert_valid_sarif(
        render_sarif(_with_gates(_summary(), *gates), Figures(skill_root="skills/x"))
    )
    results = document["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == [rule.id for rule in SARIF_RULES]
    assert {r["level"] for r in results} == {"error" if status == "block" else "warning"}
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    for result in results:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        anchor = result["locations"][0]["physicalLocation"]
        assert anchor["artifactLocation"]["uri"] == "skills/x/SKILL.md"
        assert anchor["region"] == {"startLine": 1}


# ---------------------------------------------------------------------------
# Rules, levels and what is (not) a finding
# ---------------------------------------------------------------------------


def test_rule_ids_are_the_policy_disposition_names_and_sorted() -> None:
    """The rule id is what GitHub keys an alert on; it is the word a user writes in policy.yaml
    and must never be renamed. Sorted, so the rules array is stable (§24)."""
    assert [rule.id for rule in SARIF_RULES] == [
        "canary_leak",
        "canary_without_read",
        "credential_read_undeclared",
        "dns_outside_allowlist",
        "egress_outside_allowlist",
        "process_exec_undeclared",
        "sensitive_directory_access",
        "unexpected_provider_endpoint",
    ]
    assert {rule.gate for rule in SARIF_RULES} == {
        "security_runtime.canaries",
        "security_runtime.canary_reads",
        "security_runtime.credential_reads",
        "security_runtime.dns",
        "security_runtime.egress",
        "security_runtime.processes",
        "security_runtime.sensitive_directories",
        "security_runtime.provider_endpoint",
    }
    severities = {rule.id: rule.severity for rule in SARIF_RULES}
    assert severities["canary_leak"] == "critical"
    assert set(severities.values()) <= {"critical", "high"}  # §17.3: only these are mirrored


def test_the_mirrored_rules_are_the_scored_security_runtime_gates() -> None:
    """A newly scored security_runtime gate must be mirrored (or deliberately excluded here):
    one list of what the verdict scores, compared with one list of what the SARIF carries."""
    from bellwether.cli.orchestrator import ENFORCED_SECURITY_RUNTIME_DISPOSITIONS

    # §10.5.2 makes volume a warn-level signal rather than a critical/high finding, and §17.3
    # mirrors only those; it is the one deliberate exclusion.
    not_mirrored = {"egress_volume_anomaly"}
    assert {
        rule.id for rule in SARIF_RULES
    } == ENFORCED_SECURITY_RUNTIME_DISPOSITIONS - not_mirrored


def test_pass_and_unmirrored_gates_are_not_results_and_not_evaluable_is_a_notification() -> None:
    summary = _with_gates(
        _summary(),
        GateSummary(name="security_runtime.canaries", status="pass"),
        GateSummary(name="security_runtime.dns", status="not_evaluable", reason="t: no resolver"),
        GateSummary(name="scope", status="block", reason="t: exceeded"),
        GateSummary(name="functional", status="block", reason="t: failing"),
    )
    document = assert_valid_sarif(render_sarif(summary, Figures(skill_root="")))
    run = document["runs"][0]
    assert run["results"] == []
    notes = run["invocations"][0]["toolExecutionNotifications"]
    texts = [n["message"]["text"] for n in notes]
    assert any("No static scan" in t for t in texts), "an empty file must not read as a clean scan"
    unobserved = [n for n in notes if "associatedRule" in n]
    assert [n["associatedRule"]["id"] for n in unobserved] == ["dns_outside_allowlist"]
    assert "not a clean reading" in unobserved[0]["message"]["text"]


# ---------------------------------------------------------------------------
# Locations, fingerprints, untrusted text, determinism
# ---------------------------------------------------------------------------


def _one_result(summary: Summary, figures: Figures) -> dict[str, Any]:
    document = assert_valid_sarif(render_sarif(summary, figures))
    results = document["runs"][0]["results"]
    assert len(results) == 1
    return results[0]  # type: ignore[no-any-return]


def _leak(reason: str = "t: leaked", observed: str = "leak") -> GateSummary:
    return GateSummary(
        name="security_runtime.canaries", status="block", observed=observed, reason=reason
    )


def test_the_anchor_is_skill_md_line_one_under_the_skill_root() -> None:
    summary = _with_gates(_summary(), _leak())
    for root, uri in (("skills/a", "skills/a/SKILL.md"), ("", "SKILL.md"), (None, "SKILL.md")):
        result = _one_result(summary, Figures(skill_root=root))
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == uri
    document = json.loads(render_sarif(summary, Figures(skill_root=None)))
    texts = [
        n["message"]["text"]
        for n in document["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    ]
    assert any("not known relative to the repository" in t for t in texts)


def test_the_fingerprint_is_stable_across_evaluations_and_distinct_per_rule() -> None:
    """GitHub de-duplicates on it: the same finding on the next push is the same alert."""
    base = _with_gates(_summary(), _leak())
    later = base.model_copy(update={"eval_id": "another-eval"})
    reworded = _with_gates(_summary(), _leak(reason="t: different words", observed="x"))
    figures = Figures(skill_root="skills/a")
    prints = {
        json.dumps(_one_result(s, figures)["partialFingerprints"]) for s in (base, later, reworded)
    }
    assert len(prints) == 1
    egress = _with_gates(
        _summary(), GateSummary(name="security_runtime.egress", status="block", reason="t: x")
    )
    other = _one_result(egress, figures)["partialFingerprints"][SARIF_FINGERPRINT_KEY]
    assert other != _one_result(base, figures)["partialFingerprints"][SARIF_FINGERPRINT_KEY]
    moved = _one_result(base, Figures(skill_root="skills/b"))["partialFingerprints"]
    assert moved != _one_result(base, figures)["partialFingerprints"]


def test_skill_controlled_text_cannot_plant_an_embedded_link() -> None:
    """SARIF message text renders ``[text](uri)`` as a link (§3.11.6); a path the skill chose
    reaches the reason, so brackets are escaped and no live link survives."""
    hostile = "t: touched [click here](https://evil.example/phish) and \\[pre-escaped\\]"
    result = _one_result(_with_gates(_summary(), _leak(reason=hostile)), Figures())
    text = result["message"]["text"]
    assert "[click here](https://evil.example" not in text
    assert "\\[click here\\](https://evil.example/phish)" in text
    # A pre-escaped bracket cannot be un-escaped by the escape: its backslash is doubled.
    assert "\\\\\\[pre-escaped\\\\\\]" in text


def test_renders_are_byte_identical() -> None:
    summary = _with_gates(_summary(), _leak())
    figures = Figures(skill_root="skills/a")
    assert render_sarif(summary, figures) == render_sarif(summary, figures)
    assert render_sarif(summary, figures).endswith("}\n")


# ---------------------------------------------------------------------------
# The skill root: where it comes from and how it persists
# ---------------------------------------------------------------------------


def test_the_skill_root_is_relative_to_the_enclosing_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    skill = repo / "skills" / "note-taker"
    skill.mkdir(parents=True)
    assert repository_relative_root(skill) is None  # no repository: say so, never guess
    (repo / ".git").mkdir()
    assert repository_relative_root(skill) == "skills/note-taker"
    assert repository_relative_root(repo) == ""
    # A worktree or submodule holds a `.git` *file*; it marks a repository root just the same.
    (skill / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
    assert repository_relative_root(skill) == ""


def test_the_skill_root_round_trips_through_figures_json() -> None:
    figures = Figures(skill_root="skills/a")
    assert figures_from_json(render_figures_json(figures)) == figures
    legacy = json.loads(render_figures_json(Figures()))
    del legacy["skill_root"]  # a tree written before the key existed
    assert figures_from_json(json.dumps(legacy)).skill_root is None
