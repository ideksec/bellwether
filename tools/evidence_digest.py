"""Print a compact, per-run digest of an evaluation's evidence into a CI job log.

The live workflows upload the whole artifact tree, but a reader of the job log — or anyone without
access to the artifact — still needs to see *why* a run landed where it did: which processes the
process plane put on the skill, which planted credentials were opened, how complete each capture
plane was, and what the evaluation spent. This reads ``<eval_dir>/summary.json`` and every
``<eval_dir>/traces/**/*.jsonl`` and prints exactly that.

Trace content is partly skill-controlled (a command line is whatever the model ran), and a job log
line that starts with ``::`` is a GitHub workflow command. So every value is printed JSON-encoded
and every line indented: nothing the skill wrote can start a line.

Usage: ``python tools/evidence_digest.py <eval_dir>``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _q(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def _run_lines(path: Path) -> list[str]:
    records: list[dict[str, Any]] = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line
    ]
    header: dict[str, Any] = next(
        (r for r in records if r.get("record") == "header" or "coverage" in r), {}
    )
    footer: dict[str, Any] = next((r for r in reversed(records) if "exit_reason" in r), {})
    actions = [r for r in records if "kind" in r and "action" in r]
    coverage = header.get("coverage", {})
    skill_processes = [
        a["action"].get("argv") or [a["action"].get("argv0")]
        for a in actions
        if a["kind"] == "process_exec" and a["action"].get("role") == "skill"
    ]
    harness_processes = sorted(
        {
            f"{a['action'].get('argv0')}:{a['action'].get('attribution')}"
            for a in actions
            if a["kind"] == "process_exec" and a["action"].get("role") == "harness"
        }
    )
    credential_reads = [
        f"{a['action'].get('role')}:{a['action'].get('canary_id')}:{a['action'].get('path')}"
        for a in actions
        if a["kind"] == "canary_read"
    ]
    tools = [a["action"].get("tool") for a in actions if a["kind"] == "tool_call"]
    return [
        f"  run {_q(path.name)}",
        f"    exit_reason {_q(footer.get('exit_reason'))} tokens {_q(footer.get('tokens'))}",
        f"    tools {_q(tools)}",
        f"    coverage process {_q((coverage.get('process') or {}).get('fidelity'))}"
        f" reads {_q((coverage.get('filesystem_reads') or {}).get('fidelity'))}"
        f" egress {_q((coverage.get('egress') or {}).get('fidelity'))}",
        f"    skill processes {_q(skill_processes)}",
        f"    harness processes {_q(harness_processes)}",
        f"    canary reads {_q(credential_reads)}",
    ]


def digest(eval_dir: Path) -> list[str]:
    lines = [f"  evaluation {_q(eval_dir.name)}"]
    summary_path = eval_dir / "summary.json"
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        verdict = summary.get("verdict") or {}
        lines.append(f"  verdict {_q(verdict.get('status'))}")
        lines.append(
            "  not passing "
            + _q(
                [
                    [gate.get("name"), gate.get("status"), gate.get("observed")]
                    for gate in verdict.get("gates", [])
                    if gate.get("status") != "pass"
                ]
            )
        )
        lines.append(f"  cost {_q(summary.get('cost'))}")
    else:
        lines.append("  summary.json absent")
    traces = (
        sorted((eval_dir / "traces").rglob("*.jsonl")) if (eval_dir / "traces").is_dir() else []
    )
    if not traces:
        lines.append("  no traces")
    for trace in traces:
        try:
            lines.extend(_run_lines(trace))
        except (OSError, ValueError) as error:
            lines.append(f"  run {_q(trace.name)} unreadable {_q(type(error).__name__)}")
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: evidence_digest.py <eval_dir>", file=sys.stderr)
        return 2
    for line in digest(Path(argv[1])):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
