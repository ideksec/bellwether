"""Builders for ARF records.

Shared rather than local to one test file: WP-9 commits golden traces so that the
metrics → verdict → report path is runnable with no API key, and those traces are built
from the same helpers.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from bellwether.trace import (
    Action,
    Capability,
    Coverage,
    PlaneCoverage,
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
)

START = dt.datetime(2026, 8, 4, 9, 12, 33, 104000, tzinfo=dt.UTC)


def make_header(**overrides: Any) -> RunHeader:
    defaults: dict[str, Any] = {
        "run_id": "01JRUN0000000000000000000A",
        "eval_id": "01JEVAL000000000000000000B",
        "scenario_id": "triggers-on-direct-request",
        "scenario_digest": "sha256:" + "1" * 64,
        "repetition": 1,
        "look": 1,
        "skill": SkillRef(
            name="security-review",
            package_digest="sha256:" + "2" * 64,
            payload_digest="sha256:" + "3" * 64,
            source="skills/security-review",
            files=[{"path": "SKILL.md", "sha256": "sha256:" + "4" * 64, "bytes": 4211}],
        ),
        "target": TargetRef(
            harness="api-loop",
            harness_version="0.1.0",
            provider="anthropic",
            model_alias="frontier",
            model_id_requested="configured-frontier",
            model_id_reported="configured-frontier",
        ),
        "sandbox": SandboxRef(
            image="ghcr.io/example/bellwether-sandbox@sha256:" + "5" * 64,
            fixture="python-repo",
            fixture_digest="sha256:" + "6" * 64,
            workspace_root="/work/a7f3c1",
        ),
        "coverage": Coverage(
            harness_events=PlaneCoverage(fidelity="full"),
            filesystem_writes=PlaneCoverage(fidelity="overlay_diff"),
            filesystem_reads=PlaneCoverage(
                fidelity="unavailable",
                reason="fanotify unavailable: runner kernel lacks FAN_REPORT_FID",
            ),
            process=PlaneCoverage(
                fidelity="unavailable",
                reason="eBPF load denied: runner does not grant CAP_BPF to the host agent",
            ),
        ),
        "started_at": START,
    }
    return RunHeader(**(defaults | overrides))


def make_action(seq: int, **overrides: Any) -> Action:
    defaults: dict[str, Any] = {
        "seq": seq,
        "ts": START + dt.timedelta(seconds=seq),
        "plane": "harness",
        "kind": "tool_call",
        "action": {"tool": "Read", "input": {"file_path": "/work/a7f3c1/src/auth.py"}},
        "capability": Capability(
            tier1="workspace_read",
            tier2="workspace_read:src/",
            tier3="workspace_read:src/auth.py",
        ),
    }
    return Action(**(defaults | overrides))


def make_footer(**overrides: Any) -> RunFooter:
    defaults: dict[str, Any] = {
        "ended_at": START + dt.timedelta(seconds=42),
        "wall_clock_ms": 42_000,
        "exit_reason": "completed",
        "tokens": {"input": 8000, "output": 1200, "cache_read": 6000, "cache_write": 2000},
        "estimated_cost_usd": 0.0431,
    }
    return RunFooter(**(defaults | overrides))
