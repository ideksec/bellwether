"""``bellwether trace`` — locate one ARF trace in an artifact tree and pretty-print it (§20, §17.1).

A trace is filed under ``<out>/<eval_id>/traces/<scenario>/<target>/<repetition>.arf.jsonl``
(§17.1) and carries its own ``run_id`` in the header, which is what the report's evidence
links name. This module finds a trace by that id — or takes a path — and renders it as one
line per action, so a reviewer following a gate's evidence can read what the run did without
parsing JSONL by hand. It renders; it decides nothing.

Deterministic: the search walks files in sorted order, every listing is sorted, and the
rendering is a pure function of the trace. An ambiguous id (the same ``run_id`` under two
evaluations) is refused with the candidates named rather than silently picking one.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bellwether.errors import BellwetherError, TraceError
from bellwether.trace import Action, Trace, read_trace

__all__ = [
    "SHOW_ALL",
    "TraceFilter",
    "iter_trace_files",
    "load_trace",
    "locate_trace",
    "render_trace_lines",
    "summarise_action",
    "trace_record",
]

#: How much of a free-form value the one-line rendering shows before eliding.
_PREVIEW = 80


def iter_trace_files(out_dir: Path, *, eval_id: str | None = None) -> Iterator[Path]:
    """Every ``.arf.jsonl`` under the artifact tree, sorted, optionally within one evaluation."""
    if eval_id is not None:
        yield from sorted((out_dir / eval_id).glob("traces/**/*.arf.jsonl"))
    else:
        yield from sorted(out_dir.glob("*/traces/**/*.arf.jsonl"))


def _header_run_id(path: Path) -> str | None:
    """The ``run_id`` from a trace file's first line, or ``None`` where it is not a header."""
    try:
        with path.open(encoding="utf-8") as handle:
            first = handle.readline()
        record = json.loads(first)
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict) or record.get("type") != "run_header":
        return None
    run_id = record.get("run_id")
    return run_id if isinstance(run_id, str) else None


def locate_trace(ref: str, *, out_dir: Path, eval_id: str | None = None) -> Path:
    """Resolve ``ref`` — a trace file path, or a ``run_id`` to search ``out_dir`` for.

    Refuses, naming what was searched, when nothing matches; refuses naming every candidate
    when more than one trace carries the id (the same ``run_id`` under two evaluations),
    since picking one silently would show the reviewer the wrong run's evidence.
    """
    candidate = Path(ref)
    if candidate.is_file():
        return candidate
    searched = out_dir / eval_id if eval_id is not None else out_dir
    if not searched.is_dir():
        raise BellwetherError(
            f"{ref!r} is not a trace file, and the artifact directory {searched} does not exist; "
            "pass the path to an .arf.jsonl, or --out DIR (and --eval EVAL_ID) to search"
        )
    files = list(iter_trace_files(out_dir, eval_id=eval_id))
    matches = [path for path in files if _header_run_id(path) == ref]
    if not matches:
        raise BellwetherError(
            f"no trace with run_id {ref!r} under {searched} ({len(files)} trace file(s) searched); "
            "run ids are recorded in each trace's run_header and in the report's evidence links"
        )
    if len(matches) > 1:
        listed = "\n  - ".join(str(path) for path in matches)
        raise BellwetherError(
            f"run_id {ref!r} matches {len(matches)} traces under {searched}; narrow with "
            f"--eval EVAL_ID or pass the path:\n  - {listed}"
        )
    return matches[0]


@dataclass(frozen=True)
class TraceFilter:
    """Which actions to show: any of ``planes`` and any of ``kinds``; empty means all."""

    planes: frozenset[str] = frozenset()
    kinds: frozenset[str] = frozenset()

    def keep(self, action: Action) -> bool:
        if self.planes and action.plane not in self.planes:
            return False
        return not self.kinds or action.kind in self.kinds


#: The no-filter default: every action shown.
SHOW_ALL = TraceFilter()


def _compact(value: object) -> str:
    text = (
        value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)
    )
    text = text.replace("\n", "\\n")
    return text if len(text) <= _PREVIEW else text[: _PREVIEW - 1] + "…"


def summarise_action(action: Action) -> str:
    """One line of what an action did, by kind — the fields a reviewer looks for first."""
    payload = action.action
    kind = action.kind
    if kind == "tool_call":
        return f"{payload.get('tool', '?')}({_compact(payload.get('input', {}))})"
    if kind == "tool_result":
        duration = payload.get("duration_ms")
        tail = f" ({duration} ms)" if duration is not None else ""
        return f"{payload.get('tool', '?')} → {payload.get('outcome', '?')}{tail}"
    if kind == "model_turn":
        tokens = payload.get("tokens") or {}
        return (
            f"stop={payload.get('stop_reason', '?')} "
            f"tokens in={tokens.get('input', 0)} out={tokens.get('output', 0)} "
            f"cache_read={tokens.get('cache_read', 0)}"
        )
    if kind in {"skill_offered", "skill_activated", "skill_body_loaded"}:
        return str(payload.get("skill", "?"))
    if kind == "final_output":
        return _compact(payload.get("text", ""))
    if "path" in payload:
        return str(payload["path"])
    if "host" in payload:
        return f"{payload.get('method', '')} {payload['host']}{payload.get('path', '')}".strip()
    if "name" in payload:
        return str(payload["name"])
    scalars = {
        key: value
        for key, value in sorted(payload.items())
        if isinstance(value, (str, int, float, bool)) or value is None
    }
    return _compact(" ".join(f"{key}={_compact(value)}" for key, value in scalars.items()))


def _coverage_line(trace: Trace) -> str:
    planes = trace.header.coverage.model_dump()
    parts: list[str] = []
    for name in sorted(planes):
        plane = planes[name]
        if not isinstance(plane, dict):
            continue
        fidelity = plane.get("fidelity", "?")
        reason = plane.get("reason")
        parts.append(f"{name}={fidelity}" + (f" ({reason})" if reason else ""))
    return ", ".join(parts) if parts else "none recorded"


def render_trace_lines(trace: Trace, filt: TraceFilter = SHOW_ALL) -> list[str]:
    """The human rendering: a header block, one line per kept action, and the footer."""
    header = trace.header
    target = header.target
    lines = [
        f"run      {header.run_id}",
        f"eval     {header.eval_id}  scenario {header.scenario_id}  repetition {header.repetition}",
        f"target   {target.harness} / {target.provider} / {target.model_alias} "
        f"(requested {target.model_id_requested}, reported {target.model_id_reported})",
        f"skill    {header.skill.name}  payload {header.skill.payload_digest}",
        f"started  {header.started_at.isoformat()}",
        f"coverage {_coverage_line(trace)}",
        "",
        f"{'seq':>5}  {'time':<25}  {'plane':<14}  {'kind':<22}  summary",
    ]
    shown = 0
    for action in trace.actions:
        if not filt.keep(action):
            continue
        shown += 1
        lines.append(
            f"{action.seq:>5}  {action.ts.isoformat():<25}  {action.plane:<14}  "
            f"{action.kind:<22}  {summarise_action(action)}"
        )
    lines.append("")
    hidden = len(trace.actions) - shown
    if hidden:
        lines.append(f"({shown} of {len(trace.actions)} actions shown; {hidden} filtered out)")
    footer = trace.footer
    if footer is None:
        lines.append(f"INCOMPLETE: {trace.incomplete_reason or 'no run_footer'}")
    else:
        tokens = footer.tokens
        lines.append(
            f"ended    {footer.ended_at.isoformat()}  exit {footer.exit_reason}  "
            f"wall {footer.wall_clock_ms} ms  tokens in={tokens.input} out={tokens.output} "
            f"cache_read={tokens.cache_read} cache_write={tokens.cache_write}"
        )
    return lines


def trace_record(trace: Trace, filt: TraceFilter = SHOW_ALL) -> dict[str, Any]:
    """The machine-readable rendering for ``--json``: the same header, actions, and footer."""
    header = trace.header
    footer = trace.footer
    return {
        "run_id": header.run_id,
        "eval_id": header.eval_id,
        "scenario_id": header.scenario_id,
        "repetition": header.repetition,
        "target": {
            "harness": header.target.harness,
            "provider": header.target.provider,
            "model_alias": header.target.model_alias,
            "model_id_requested": header.target.model_id_requested,
            "model_id_reported": header.target.model_id_reported,
        },
        "skill": {"name": header.skill.name, "payload_digest": header.skill.payload_digest},
        "coverage": header.coverage.model_dump(),
        "complete": trace.is_complete,
        "incomplete_reason": trace.incomplete_reason,
        "actions": [
            {
                "seq": action.seq,
                "ts": action.ts.isoformat(),
                "plane": action.plane,
                "kind": action.kind,
                "summary": summarise_action(action),
                "action": action.action,
                "capability": (
                    action.capability.model_dump() if action.capability is not None else None
                ),
            }
            for action in trace.actions
            if filt.keep(action)
        ],
        "actions_total": len(trace.actions),
        "footer": (
            None
            if footer is None
            else {
                "ended_at": footer.ended_at.isoformat(),
                "exit_reason": footer.exit_reason,
                "wall_clock_ms": footer.wall_clock_ms,
                "tokens": footer.tokens.model_dump(),
            }
        ),
    }


def load_trace(path: Path) -> Trace:
    """Read a trace file, turning a reader error into a :class:`BellwetherError`."""
    try:
        return read_trace(path)
    except (OSError, TraceError) as error:
        raise BellwetherError(f"cannot read {path}: {error}") from None
