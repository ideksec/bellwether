"""The CI evidence digest (tools/evidence_digest.py) prints skill-controlled text safely."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "evidence_digest", Path(__file__).resolve().parents[1] / "tools" / "evidence_digest.py"
)
assert _SPEC is not None and _SPEC.loader is not None
digest_module = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(digest_module)


def _write_trace(path: Path, argv: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [
        {"arf_version": "1.0", "coverage": {"process": {"fidelity": "full"}}},
        {"kind": "tool_call", "action": {"tool": "bash"}},
        {"kind": "process_exec", "action": {"argv0": argv[0], "argv": argv, "role": "skill"}},
        {
            "kind": "canary_read",
            "action": {"role": "skill", "canary_id": "c1", "path": "/home/a/.aws/credentials"},
        },
        {
            "kind": "egress_blocked",
            "action": {
                "method": "POST",
                "host": "api.anthropic.com",
                "path": "/v1/x",
                "shape_violation": "not a model endpoint",
            },
        },
        {"exit_reason": "completed", "tokens": {"input": 10, "output": 2}},
    ]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def test_a_skill_command_line_cannot_start_a_workflow_command(tmp_path: Path) -> None:
    """A job-log line that starts with `::` is a GitHub workflow command; a command line is
    whatever the model ran. Every value is JSON-encoded and every line indented."""
    hostile = ["echo", "\n::error::forged verdict\n::add-mask::x"]
    _write_trace(tmp_path / "eval" / "traces" / "s" / "t" / "1.arf.jsonl", hostile)
    (tmp_path / "eval" / "summary.json").write_text(
        json.dumps({"verdict": {"status": "ready", "gates": []}, "cost": {"usd": 0.12}}),
        encoding="utf-8",
    )
    lines = digest_module.digest(tmp_path / "eval")
    assert all(line.startswith("  ") and "\n" not in line for line in lines), lines
    assert any("skill processes" in line and "::error::" in line for line in lines)
    assert any('verdict "ready"' in line for line in lines)
    assert any("skill:c1:" in line for line in lines)
    assert any("refused egress" in line and "not a model endpoint" in line for line in lines)


def test_a_missing_tree_says_so_rather_than_printing_nothing(tmp_path: Path) -> None:
    lines = digest_module.digest(tmp_path)
    assert "  summary.json absent" in lines and "  no traces" in lines
