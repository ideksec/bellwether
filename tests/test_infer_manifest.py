"""`bellwether init-manifest` — a scope inferred from an observed run (§6.2, §20).

The inference reads the evaluation's capability profile: every tier-1 class the matrix
exercised, with the exact tier-3 things it touched. Permission classes become declarations;
finding classes (a canary read, a blocked egress, a DNS lookup) are listed in the header as
observed-but-not-declared and never laundered into an allowlist. The written file is parsed
back through the manifest loader before it lands, and an existing manifest is never
overwritten without --force.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from bellwether.cli import ExitCode, app
from bellwether.cli.diff import load_summary
from bellwether.cli.infer_manifest import (
    infer_scope,
    render_manifest_yaml,
    write_inferred_manifest,
)
from bellwether.config.loader import parse_manifest
from bellwether.errors import BellwetherError
from bellwether.report import Summary
from bellwether.skill import load_skill

_ROOT = Path(__file__).resolve().parent.parent
_REPORTS = _ROOT / "examples" / "reports"
_SKILLS = _ROOT / "examples" / "skills"
_SNEAKY = "demo-sneaky-exfiltrator"
_BENIGN = "demo-benign-note-taker"

runner = CliRunner()


def _summary(eval_id: str) -> Summary:
    return load_summary(_REPORTS / eval_id / "summary.json")


def _with_expansions(summary: Summary, expansions: dict[str, list[str]]) -> Summary:
    profile = summary.capability_profile.model_copy(update={"tier3": {"expansions": expansions}})
    return summary.model_copy(update={"capability_profile": profile})


def _skill_copy(tmp_path: Path, name: str, *, drop_manifest: bool = True) -> Path:
    target = tmp_path / name
    shutil.copytree(_SKILLS / name, target)
    if drop_manifest:
        (target / "evals" / "manifest.yaml").unlink()
    return target


def test_the_exfiltrators_run_infers_what_it_did_and_flags_the_credential_read() -> None:
    """The workspace read and write are declared; the `~/.aws/credentials` read sits under a
    §13.5.4 sensitive-directory hit and is listed for the reviewer, never allowlisted."""
    scope = infer_scope(_summary(_SNEAKY))
    assert scope.tools == ("skill",)
    assert scope.read == ("${WORKSPACE}/notes/2026-01-01-standup.md",)
    assert scope.write == ("${WORKSPACE}/summary.md",)
    assert scope.egress == ()
    assert scope.processes == ()
    assert [tier1 for tier1, _ in scope.undeclared] == ["outside_workspace_read"]
    assert "${HOME}/.aws/credentials" in scope.undeclared[0][1]
    assert "sensitive directory" in scope.undeclared[0][1]


def test_finding_classes_are_listed_not_declared() -> None:
    summary = _with_expansions(
        _summary(_BENIGN),
        {
            "tool:bash": ["curl"],
            "egress:api.example.com": ["/v1"],
            "egress_blocked:evil.example": ["/x"],
            "dns_query:evil.example": [],
            "canary_read": ["${HOME}/.aws/credentials"],
            "process:git": ["git"],
            "harness_state_write": ["${HOME}/.claude/settings.json"],
            "mystery_class": ["?"],
        },
    )
    scope = infer_scope(summary)
    assert scope.tools == ("bash",)
    assert scope.egress == ("api.example.com",)
    assert scope.processes == ("git",)
    assert scope.write == ("${HOME}/.claude/settings.json",)
    undeclared = dict(scope.undeclared)
    assert set(undeclared) == {
        "egress_blocked:evil.example",
        "dns_query:evil.example",
        "canary_read",
        "mystery_class",
    }
    assert "never declared" in undeclared["canary_read"]
    assert "no manifest area" in undeclared["mystery_class"]
    # The canary path never reaches an allowlist.
    assert "${HOME}/.aws/credentials" not in scope.read


def test_the_rendered_file_is_marked_inferred_and_parses_as_a_manifest() -> None:
    scope = infer_scope(_summary(_SNEAKY))
    text = render_manifest_yaml(
        scope,
        skill_name="sneaky-exfiltrator",
        eval_id=_SNEAKY,
        payload_digest="sha256:abc",
        criticality="high",
    )
    assert text.startswith("# INFERRED, NOT REVIEWED")
    assert _SNEAKY in text and "sha256:abc" in text
    manifest = parse_manifest(yaml.safe_load(text))
    assert manifest.metadata.criticality == "high"
    assert manifest.declared_scope.filesystem.read == list(scope.read)
    assert manifest.declared_scope.tools.allow == ["skill"]
    assert manifest.declared_scope.network.egress_allow == []


def test_write_infers_into_the_skill_and_load_skill_sees_it(tmp_path: Path) -> None:
    skill_dir = _skill_copy(tmp_path, "sneaky-exfiltrator")
    package = load_skill(skill_dir)
    assert package.manifest is None
    path, _scope = write_inferred_manifest(package, _summary(_SNEAKY))
    assert path == skill_dir / "evals" / "manifest.yaml"
    reloaded = load_skill(skill_dir)
    assert reloaded.manifest is not None
    assert reloaded.manifest.declared_scope.filesystem.write == ["${WORKSPACE}/summary.md"]
    # Without a prior manifest the criticality defaults to medium.
    assert reloaded.manifest.metadata.criticality == "medium"


def test_an_existing_manifest_is_kept_unless_forced(tmp_path: Path) -> None:
    skill_dir = _skill_copy(tmp_path, "sneaky-exfiltrator", drop_manifest=False)
    package = load_skill(skill_dir)
    original = (skill_dir / "evals" / "manifest.yaml").read_text(encoding="utf-8")
    with pytest.raises(BellwetherError, match="already exists"):
        write_inferred_manifest(package, _summary(_SNEAKY))
    assert (skill_dir / "evals" / "manifest.yaml").read_text(encoding="utf-8") == original
    path, _ = write_inferred_manifest(package, _summary(_SNEAKY), force=True)
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# INFERRED")
    # --force keeps the reviewed criticality the old manifest carried.
    assert parse_manifest(yaml.safe_load(text)).metadata.criticality == "high"


def test_another_skills_evaluation_is_refused(tmp_path: Path) -> None:
    skill_dir = _skill_copy(tmp_path, "sneaky-exfiltrator")
    with pytest.raises(BellwetherError, match="benign-note-taker"):
        write_inferred_manifest(load_skill(skill_dir), _summary(_BENIGN))
    assert not (skill_dir / "evals" / "manifest.yaml").exists()


def test_init_manifest_command_end_to_end(tmp_path: Path) -> None:
    skill_dir = _skill_copy(tmp_path, "sneaky-exfiltrator")
    result = runner.invoke(
        app,
        ["init-manifest", str(skill_dir), "--from", _SNEAKY, "--out", str(_REPORTS), "--json"],
    )
    assert result.exit_code == ExitCode.OK, result.output
    payload = json.loads(result.output)
    assert payload["declared_scope"]["filesystem"]["read"] == [
        "${WORKSPACE}/notes/2026-01-01-standup.md"
    ]
    assert payload["undeclared"][0]["class"] == "outside_workspace_read"
    again = runner.invoke(
        app, ["init-manifest", str(skill_dir), "--from", _SNEAKY, "--out", str(_REPORTS)]
    )
    assert again.exit_code == ExitCode.INFRASTRUCTURE
    assert "already exists" in again.output


def test_the_harnesss_own_egress_is_never_declared_as_the_skills() -> None:
    """The worst inference this module could make, and it was making it.

    Under `claude-code` the CLI's model calls leave through the same proxy the skill's would,
    so `api.anthropic.com` appeared in the capability profile of every run. Written into the
    skill's own `network.egress_allow`, a later genuine exfiltration to the model API would
    read as declared-and-allowed — the laundering this module's docstring says it prevents,
    performed on the one host where it matters most.
    """
    summary = _with_expansions(
        _summary(_BENIGN),
        {
            "egress:api.example.com": ["/v1"],
            "egress_infrastructure:api.anthropic.com": ["/v1/messages"],
            "egress_infrastructure:statsig.anthropic.com": ["/v1/i"],
        },
    )
    scope = infer_scope(summary)

    # The skill's own host still is declared — the guard must not cost the inference.
    assert scope.egress == ("api.example.com",)
    undeclared = dict(scope.undeclared)
    assert set(undeclared) == {
        "egress_infrastructure:api.anthropic.com",
        "egress_infrastructure:statsig.anthropic.com",
    }
    assert "the harness's own egress" in undeclared["egress_infrastructure:api.anthropic.com"]


def test_no_harness_host_reaches_the_rendered_manifest() -> None:
    """Asserted against the rendered bytes, not the intermediate structure: the file is what a
    reviewer reads and what `load_skill` later enforces."""
    from bellwether.cli.infer_manifest import render_manifest_yaml

    summary = _with_expansions(
        _summary(_BENIGN),
        {
            "egress:api.example.com": ["/v1"],
            "egress_infrastructure:api.anthropic.com": ["/v1/messages"],
        },
    )
    rendered = render_manifest_yaml(
        infer_scope(summary),
        skill_name="benign-note-taker",
        eval_id=_BENIGN,
        payload_digest="sha256:abc",
        criticality="low",
    )

    manifest = parse_manifest(yaml.safe_load(rendered))
    assert manifest.declared_scope.network.egress_allow == ["api.example.com"]
    assert not any("anthropic.com" in host for host in manifest.declared_scope.network.egress_allow)
