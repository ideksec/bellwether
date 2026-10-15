"""§15 delegation: external scanners' SARIF read, attributed, graded, and required.

Bellwether reads a dedicated scanner's output and never runs the scanner (spec-notes: the config
that would name a command lives in the evaluated checkout). These tests hold the ingestion to
the same standard as the built-in rules — and, more importantly, the places it is wired: the run
refuses before spending when a required scanner is missing, a delegated finding decides the
gate, and the SARIF the evaluation writes carries it under a descriptor whose index is right.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from bellwether.cli.app import ExitCode, app
from bellwether.cli.run import scan_with_delegates
from bellwether.errors import BellwetherError
from bellwether.scan import (
    ScanReport,
    merge_external,
    read_scanner_sarif,
    scan_package,
    scanner_name,
)
from bellwether.skill import load_skill
from tests.test_sarif import assert_valid_sarif

_FAKE_AWS_KEY = "AKIA" + "Z" * 16


def _skill(root: Path) -> Path:
    skill = root / "skills" / "s"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: s\ndescription: Counts lines in the workspace's Markdown files.\n---\nbody\n",
        encoding="utf-8",
    )
    (skill / "scripts").mkdir()
    (skill / "scripts" / "run.py").write_text("print('x')\n", encoding="utf-8")
    return skill


def _result(rule: str, uri: str, *, line: int = 3, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": rule,
        "message": {"text": f"{rule} matched"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    result.update(extra)
    return result


def _sarif(
    path: Path, results: list[dict[str, Any]], *, tool: str = "Semgrep OSS", rules=()
) -> Path:  # type: ignore[no-untyped-def]
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "rules": list(rules)}}, "results": results}],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _merged(tmp_path: Path, *files: Path) -> ScanReport:
    skill = tmp_path / "skills" / "s"
    package = load_skill(skill, load_evals=False)
    return merge_external(
        scan_package(package),
        [read_scanner_sarif(f) for f in files],
        skill_root=skill,
        base=tmp_path,
    )


# ---------------------------------------------------------------------------
# Reading and grading
# ---------------------------------------------------------------------------


def test_tool_names_are_normalised_the_way_policy_names_them() -> None:
    assert scanner_name("Semgrep OSS") == "semgrep-oss"
    assert scanner_name("  Gitleaks ") == "gitleaks"
    assert scanner_name("") == "unnamed"


@pytest.mark.parametrize(
    ("extra", "rules", "severity"),
    [
        ({"properties": {"security-severity": "9.1"}}, [], "critical"),
        ({"properties": {"security-severity": "7.0"}}, [], "high"),
        ({"properties": {"security-severity": "4.5"}}, [], "medium"),
        ({"properties": {"security-severity": "0.5"}}, [], "low"),
        ({"level": "error"}, [], "high"),
        ({"level": "warning"}, [], "medium"),
        ({"level": "note"}, [], "low"),
        ({"level": "none"}, [], "info"),
        ({}, [{"id": "r", "properties": {"security-severity": "9.8"}}], "critical"),
        ({}, [{"id": "r", "defaultConfiguration": {"level": "note"}}], "low"),
        ({}, [], "medium"),  # SARIF's own default level is warning
    ],
)
def test_severity_comes_from_security_severity_then_level(
    tmp_path: Path, extra: dict[str, Any], rules: list[dict[str, Any]], severity: str
) -> None:
    _skill(tmp_path)
    sarif = _sarif(tmp_path / "x.sarif", [_result("r", "skills/s/SKILL.md", **extra)], rules=rules)
    report = _merged(tmp_path, sarif)
    delegated = [f for f in report.findings if f.rule_id == "semgrep-oss:r"]
    assert [f.severity for f in delegated] == [severity]


def test_results_are_attributed_by_resolved_path_and_the_rest_are_counted(
    tmp_path: Path,
) -> None:
    skill = _skill(tmp_path)
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "f.py").write_text("x\n", encoding="utf-8")
    sarif = _sarif(
        tmp_path / "x.sarif",
        [
            _result("relative", "skills/s/scripts/run.py", line=1),
            _result("absolute", (skill / "SKILL.md").resolve().as_uri(), line=2),
            _result("outside", "other/f.py"),
            _result("escape", "skills/s/../../other/f.py"),
            _result("remote", "https://example.com/skills/s/SKILL.md"),
            _result("nowhere", ""),
        ],
    )
    report = _merged(tmp_path, sarif)
    located = {(f.rule_id, f.path, f.line) for f in report.findings if ":" in f.rule_id}
    assert located == {
        ("semgrep-oss:relative", "scripts/run.py", 1),
        ("semgrep-oss:absolute", "SKILL.md", 2),
    }
    assert any("4 result(s) outside this skill" in note for note in report.notes)
    assert report.scanners == ("semgrep-oss",)


def test_a_tools_snippet_is_never_copied_and_its_message_is_redacted(tmp_path: Path) -> None:
    """A secret scanner's snippet *is* the secret; an excerpt reaches public reports."""
    _skill(tmp_path)
    result = _result("aws", "skills/s/SKILL.md")
    result["message"] = {"text": f"found key {_FAKE_AWS_KEY} here"}
    result["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": _FAKE_AWS_KEY}
    report = _merged(tmp_path, _sarif(tmp_path / "x.sarif", [result], tool="gitleaks"))
    finding = next(f for f in report.findings if f.rule_id == "gitleaks:aws")
    assert finding.excerpt == ""
    record = json.dumps(report.as_record())
    assert _FAKE_AWS_KEY not in record and "Z" * 8 not in record


@pytest.mark.parametrize(
    ("content", "why"),
    [
        ("not json", "is not JSON"),
        (json.dumps({"version": "2.0.0", "runs": []}), "not a SARIF 2.1.0"),
        (json.dumps({"version": "2.1.0", "runs": []}), "has no runs"),
        (json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {}}}]}), "driver.name"),
    ],
)
def test_an_unreadable_scanner_file_stops_the_run_rather_than_reading_as_clean(
    tmp_path: Path, content: str, why: str
) -> None:
    path = tmp_path / "bad.sarif"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(BellwetherError, match=why):
        read_scanner_sarif(path)


def test_an_oversized_scanner_file_is_refused_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import bellwether.scan.external as external

    monkeypatch.setattr(external, "MAX_SARIF_BYTES", 10)
    path = _sarif(tmp_path / "big.sarif", [])
    with pytest.raises(BellwetherError, match="over the 10-byte bound"):
        read_scanner_sarif(path)


def test_the_merged_report_round_trips_through_its_record(tmp_path: Path) -> None:
    _skill(tmp_path)
    report = _merged(
        tmp_path, _sarif(tmp_path / "x.sarif", [_result("r", "skills/s/SKILL.md", level="error")])
    )
    assert ScanReport.from_record(report.as_record()) == report


# ---------------------------------------------------------------------------
# Required scanners
# ---------------------------------------------------------------------------


def test_a_required_scanner_that_was_not_supplied_raises(tmp_path: Path) -> None:
    package = load_skill(_skill(tmp_path), load_evals=False)
    with pytest.raises(BellwetherError, match="gitleaks"):
        scan_with_delegates(package, (), required=["gitleaks"])
    supplied = _sarif(tmp_path / "g.sarif", [], tool="Gitleaks")
    report = scan_with_delegates(package, (supplied,), required=["GITLEAKS"])
    assert report.scanners == ("gitleaks",)


def test_the_composition_defers_when_a_required_scanner_is_absent(tmp_path: Path) -> None:
    """The second line of defence, for a composition path that skips the run's refusal."""
    from bellwether.config.models.policy import StaticGate
    from tests.test_orchestrator import _CLEAN_SCAN, _profile_with, _run_pipeline

    result = _run_pipeline(
        tmp_path,
        tmp_path / "out",
        profile=_profile_with(static=StaticGate(required_scanners=["semgrep"])),
        static_scan=_CLEAN_SCAN,
    )
    gate = next(g for g in result.verdict.gates if g.name == "static")
    assert gate.status == "not_evaluable" and gate.required
    assert "semgrep" in gate.worst_reason
    assert result.verdict.verdict == "not_ready"


# ---------------------------------------------------------------------------
# The run path
# ---------------------------------------------------------------------------


def _package_with_script(tmp_path: Path):  # type: ignore[no-untyped-def]
    from tests.test_run import package

    pkg = package.__wrapped__(tmp_path)  # type: ignore[attr-defined]
    (pkg.root / "scripts").mkdir()
    (pkg.root / "scripts" / "tool.py").write_text("import os\n", encoding="utf-8")
    return load_skill(pkg.root)


def _evaluate_with(tmp_path: Path, pkg, sarif: tuple[Path, ...], policy=None, built=None):  # type: ignore[no-untyped-def]
    from bellwether.cli.run import run_evaluation
    from tests.test_run import _config, _policy, _ScriptedExecutor

    built = built if built is not None else []

    def make_executor(p, fixture, client_factory):  # type: ignore[no-untyped-def]
        built.append(p)
        return _ScriptedExecutor(p, tmp_path, client_factory)

    result = run_evaluation(
        config=_config(),
        policy=policy if policy is not None else _policy(),
        package=pkg,
        fixture=tmp_path / "fixture",
        environ={"ANTHROPIC_API_KEY": "sk-real-value"},
        make_executor=make_executor,
        out_dir=tmp_path / "out",
        eval_id="delegated",
        created_at="2026-08-05T12:00:00Z",
        bellwether_version="0.1.0",
        scanner_sarif=sarif,
    )
    return result, built


def test_a_delegated_finding_decides_the_gate_and_reaches_the_sarif(tmp_path: Path) -> None:
    pkg = _package_with_script(tmp_path)
    sarif = _sarif(
        tmp_path / "semgrep.sarif",
        [
            _result(
                "python.lang.security.audit.exec",
                str((pkg.root / "scripts" / "tool.py").resolve()),
                line=1,
                level="error",
            )
        ],
        tool="Semgrep",
    )
    result, _ = _evaluate_with(tmp_path, pkg, (sarif,))
    gate = next(g for g in result.verdict.gates if g.name == "static")
    assert gate.status == "block"
    assert "semgrep:python.lang.security.audit.exec" in gate.worst_reason
    assert "scripts/tool.py:1" in gate.worst_reason

    document = assert_valid_sarif(
        (result.artifacts.summary_json.parent / "findings.sarif").read_text(encoding="utf-8")
    )
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    delegated = [r for r in run["results"] if r["ruleId"].startswith("semgrep:")]
    assert len(delegated) == 1
    assert rules[delegated[0]["ruleIndex"]]["id"] == delegated[0]["ruleId"]
    assert rules[delegated[0]["ruleIndex"]]["properties"]["delegated_from"] == "semgrep"
    assert all(rules[r["ruleIndex"]]["id"] == r["ruleId"] for r in run["results"])
    summary = json.loads(result.artifacts.summary_json.read_text(encoding="utf-8"))
    assert summary["security"]["static"]["scanners"] == ["semgrep"]


def test_the_run_refuses_a_missing_required_scanner_before_building_an_executor(
    tmp_path: Path,
) -> None:
    from bellwether.config.models.policy import Policy
    from tests.test_run import _policy

    policy = _policy()
    low = policy.profile("low")
    gates = low.gates.model_copy(
        update={"static": low.gates.static.model_copy(update={"required_scanners": ["gitleaks"]})}
    )
    profiles = {**policy.profiles, "low": low.model_copy(update={"gates": gates})}
    strict = policy.model_copy(update={"profiles": profiles})
    assert isinstance(strict, Policy)

    pkg = _package_with_script(tmp_path)
    built: list[object] = []
    with pytest.raises(BellwetherError, match="gitleaks"):
        _evaluate_with(tmp_path, pkg, (), policy=strict, built=built)
    assert built == [], "the executor was built: the refusal came after money could be spent"


# ---------------------------------------------------------------------------
# `bellwether scan --scanner-sarif`
# ---------------------------------------------------------------------------

_runner = CliRunner()


def test_scan_merges_supplied_sarif_and_refuses_a_broken_one(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    good = _sarif(
        tmp_path / "s.sarif",
        [_result("rce", str((skill / "SKILL.md").resolve()), level="error")],
        tool="Semgrep",
    )
    result = _runner.invoke(app, ["scan", "--scanner-sarif", str(good), str(skill)])
    assert result.exit_code == ExitCode.NOT_READY, result.output
    assert "semgrep:rce" in result.output

    broken = tmp_path / "broken.sarif"
    broken.write_text("{", encoding="utf-8")
    refused = _runner.invoke(app, ["scan", "--scanner-sarif", str(broken), str(skill)])
    assert refused.exit_code == ExitCode.INFRASTRUCTURE
