"""The run cache (§19.2): a stored trace is reused instead of a repetition being paid for again.

The run cache stores **traces, not verdicts**. Its key is what the spec names — ``(payload_digest,
scenario_content_digest, target, fixture_digest, harness_version, sandbox_image,
platform_baseline_version)`` — plus the model id, because the spec is explicit that a changed
model id must never hit even under an unchanged alias, and plus the **repetition index**, which the
spec's key omits and this build adds: a repetition set exists to observe variance, so replaying one
cached run N times would produce a set that agrees with itself by construction. Entries expire after
``execution.cache_ttl_days`` so drift is still detected.

``policy_digest`` and ``canon_version`` are deliberately absent from the key: a policy or
canonicaliser change re-derives verdicts from cached traces without re-running anything (§19.2).

A hit is written into the new evaluation's run directory with the header's ``run_id``,
``eval_id`` and ``scenario_id`` set for this evaluation and ``cached_from`` naming the original
run, so the artifact tree stays consistent and the provenance is never lost. Only complete traces
whose run reached an observed end are stored: an infrastructure failure is retried, never replayed.
"""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from bellwether.cli.orchestrator import ExecutedRun, RunExecutor, RunPlan
from bellwether.config.models.scenarios import Scenario
from bellwether.determinism import canonical_json, stable_hash
from bellwether.errors import BellwetherError, TraceError
from bellwether.trace import NormalizationContext, read_trace, write_trace

__all__ = [
    "CACHE_FORMAT",
    "CacheKeyInputs",
    "CachingExecutor",
    "RunCache",
    "cache_key",
    "scenario_content_digest",
]

#: Bumped on any change to what an entry holds or how the key is formed.
CACHE_FORMAT = "1"

#: Exit reasons that are infrastructure failures (§13.2): retried on the next run, never cached.
_NEVER_CACHED_EXITS = frozenset({"sandbox_error", "harness_error", "cancelled"})


@dataclass(frozen=True)
class CacheKeyInputs:
    """Everything the key is formed from. ``scenario_id`` rides along for the header rewrite
    but is **not** part of the key (§19.2: content, not id)."""

    payload_digest: str
    scenario_id: str
    scenario_digest: str
    target_slug: str
    fixture_digest: str
    harness: str
    harness_version: str
    model_id: str
    sandbox_image: str
    platform_baseline_version: str
    repetition: int


def scenario_content_digest(scenario: Scenario) -> str:
    """The digest of a scenario's *content* — everything but its id (§19.2, §7.2)."""
    payload = scenario.model_dump(mode="json", exclude={"id"})
    return stable_hash(canonical_json(payload))


def cache_key(inputs: CacheKeyInputs) -> str:
    material = {k: v for k, v in asdict(inputs).items() if k != "scenario_id"}
    material["cache_format"] = CACHE_FORMAT
    return stable_hash(canonical_json(material))


@dataclass(frozen=True)
class CachedRun:
    trace_path: Path
    context: NormalizationContext
    stored_at: dt.datetime
    inputs: dict[str, object]


@dataclass
class RunCache:
    """An on-disk run cache under ``root``: one directory per key."""

    root: Path
    ttl_days: int
    clock: Callable[[], dt.datetime] = field(default=lambda: dt.datetime.now(dt.UTC), repr=False)

    def _entry_dir(self, key: str) -> Path:
        return self.root / key.removeprefix("sha256:")

    def lookup(self, key: str) -> CachedRun | None:
        """The live entry for ``key``, or ``None`` (absent, expired, or unreadable)."""
        entry = self._entry_dir(key)
        meta_path = entry / "meta.json"
        trace_path = entry / "trace.arf.jsonl"
        if not meta_path.is_file() or not trace_path.is_file():
            return None
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            stored_at = dt.datetime.fromisoformat(str(meta["stored_at"]))
            context = NormalizationContext(**meta["context"])
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if meta.get("cache_format") != CACHE_FORMAT:
            return None
        if self.ttl_days >= 0 and self.clock() - stored_at > dt.timedelta(days=self.ttl_days):
            return None
        return CachedRun(
            trace_path=trace_path,
            context=context,
            stored_at=stored_at,
            inputs=dict(meta.get("inputs", {})),
        )

    def store(self, key: str, executed: ExecutedRun, inputs: CacheKeyInputs) -> Path | None:
        """Store a completed run; return the entry, or ``None`` where the run is not cacheable."""
        trace = executed.trace
        if not trace.is_complete or trace.exit_reason in _NEVER_CACHED_EXITS:
            return None
        entry = self._entry_dir(key)
        entry.mkdir(parents=True, exist_ok=True)
        (entry / "trace.arf.jsonl").write_text(executed.trace_jsonl, encoding="utf-8")
        meta = {
            "cache_format": CACHE_FORMAT,
            "stored_at": self.clock().isoformat(),
            "context": {
                "workspace_root": executed.context.workspace_root,
                "home": executed.context.home,
                "tmp": executed.context.tmp,
            },
            "inputs": asdict(inputs),
            "run_id": trace.header.run_id,
            "eval_id": trace.header.eval_id,
        }
        (entry / "meta.json").write_text(canonical_json(meta, indent=2) + "\n", encoding="utf-8")
        return entry


@dataclass
class CachingExecutor:
    """A :class:`RunExecutor` that serves a plan from the cache where it can, and fills it otherwise."""

    inner: RunExecutor
    cache: RunCache
    inputs_for: Callable[[RunPlan], CacheKeyInputs]
    eval_id: str
    run_root: Path
    served_from_cache: list[str] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)

    def execute(self, plan: RunPlan) -> ExecutedRun:
        inputs = self.inputs_for(plan)
        key = cache_key(inputs)
        hit = self.cache.lookup(key)
        coordinate = f"{plan.scenario.id}/{plan.target.slug}/{plan.repetition}"
        if hit is not None:
            replayed = self._replay(plan, hit)
            if replayed is not None:
                self.served_from_cache.append(coordinate)
                return replayed
        result = self.inner.execute(plan)
        self.executed.append(coordinate)
        self.cache.store(key, result, inputs)
        return result

    def _replay(self, plan: RunPlan, hit: CachedRun) -> ExecutedRun | None:
        """Rewrite the cached trace's identity for this evaluation and file it under the run."""
        try:
            cached = read_trace(hit.trace_path)
        except (OSError, TraceError):
            return None
        if cached.footer is None:
            return None
        header = cached.header.model_copy(
            update={
                "run_id": f"{self.eval_id}-{plan.scenario.id}-{plan.target.slug}-{plan.repetition:03d}",
                "eval_id": self.eval_id,
                "scenario_id": plan.scenario.id,
                "repetition": plan.repetition,
                "cached_from": f"{cached.header.eval_id}/{cached.header.run_id}",
            }
        )
        run_dir = (
            self.run_root / plan.scenario.id / plan.target.slug / str(plan.repetition)
        ).resolve()
        run_dir.mkdir(parents=True, exist_ok=True)
        path = write_trace(run_dir / "trace.arf.jsonl", header, list(cached.actions), cached.footer)
        return ExecutedRun(
            trace=read_trace(path),
            context=hit.context,
            trace_jsonl=path.read_text(encoding="utf-8"),
        )


def require_cache_root(root: Path) -> Path:
    """Create the cache root, refusing where it exists as something other than a directory."""
    if root.exists() and not root.is_dir():
        raise BellwetherError(f"run cache path {root} exists and is not a directory")
    root.mkdir(parents=True, exist_ok=True)
    return root
