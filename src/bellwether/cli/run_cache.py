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
Three more things *are* in the key because they change what a run is: the **sampling** pinned on
the request (a temperature-default trace must never stand in for a ``--deterministic-sampling``
run, or the reverse), the **companion payload digests** — a companion's content reaches the run
(offered on api-loop, staged on claude-code) while only its *name* is in the scenario's content —
and the **observability fingerprint**: which planes the run could watch and the limits it ran
under. A trace captured with no proxy is not the same observation as one captured behind it, and
replaying the networkless one after the operator wires egress would report an unwatched plane as
though it had been watched, which is the one thing this project must never do.

A plan whose harness version cannot be known before the run — a ``claude-code`` target with no
``version_pin``, where the CLI version is observed only once it has run — is **not cached**: a
key that read "unpinned" would serve a trace across a CLI upgrade. ``cache_version_for`` says
which, and the executor records the bypass so the evaluation can disclose it.

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
from bellwether.config.models.config import Config, HarnessConfig
from bellwether.config.models.scenarios import Scenario
from bellwether.determinism import canonical_json, stable_hash
from bellwether.errors import BellwetherError, TraceError
from bellwether.harness import SamplingSpec
from bellwether.trace import NormalizationContext, read_trace, write_trace

__all__ = [
    "CACHE_FORMAT",
    "CacheKeyInputs",
    "CachingExecutor",
    "RunCache",
    "cache_key",
    "cache_version_for",
    "observability_key",
    "render_sampling",
    "scenario_content_digest",
]

#: Bumped on any change to what an entry holds or how the key is formed.
CACHE_FORMAT = "3"

#: Exit reasons never cached. Infrastructure failures (§13.2) are retried on the next run. The
#: rest are *operator-limit* outcomes (§12.7): each is decided by a bound — the token cap, the
#: scenario or suite timeout, the sandbox memory and process limits — that the key cannot carry
#: (the suite's ``defaults`` are outside ``scenario_content_digest``, and ``evals/`` is outside
#: ``payload_digest``), so a cached one would be replayed unchanged after the operator raised the
#: very limit that produced it.
_NEVER_CACHED_EXITS = frozenset(
    {
        "sandbox_error",
        "harness_error",
        "cancelled",
        "budget_exceeded",
        "timeout",
        "oom",
        "pids_limit",
    }
)


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
    #: The sampling pinned on the request, rendered (``""`` for the provider's defaults).
    sampling: str = ""
    #: Payload digests of the scenario's §7.4 companions, in plan order.
    companion_digests: tuple[str, ...] = ()
    #: Which planes the run could observe, and the limits it ran under (:func:`observability_key`).
    observability: str = ""


def render_sampling(sampling: SamplingSpec | None) -> str:
    """The key's rendering of a pinned sampling spec; empty for the provider's defaults."""
    if sampling is None:
        return ""
    return f"temperature={sampling.temperature},seed={sampling.seed}"


def observability_key(config: Config) -> str:
    """What this configuration lets a run *observe*, and the limits it runs under (§19.2).

    §19.2's key names the sandbox image, which fixes what is inside the container but says
    nothing about what watches it from outside. Wiring the recording proxy, pointing the sandbox
    at the controlled resolver, or turning canary planting on changes which planes the trace
    carries — a cached networkless run replayed afterwards would leave egress, DNS or credentials
    reading ``not_evaluable`` while the operator believed the plane was watched. The capture
    settings and the sandbox's resource limits ride along for the same reason: they decide what
    is recorded and when a run is killed.

    Rendered as a digest of the settings themselves, so adding a field here is a key change and
    an old entry simply misses rather than being served under a new meaning.
    """
    material = {
        "capture": config.capture.model_dump(mode="json"),
        "egress": config.egress.model_dump(mode="json"),
        "dns": config.dns.model_dump(mode="json"),
        "canaries": config.canaries.model_dump(mode="json"),
        "sandbox_limits": {
            "backend": config.sandbox.backend,
            "memory": config.sandbox.memory,
            "cpus": config.sandbox.cpus,
            "pids_limit": config.sandbox.pids_limit,
            "timeout_seconds": config.sandbox.timeout_seconds,
            "writable_paths": sorted(config.sandbox.writable_paths),
        },
    }
    return stable_hash(canonical_json(material))


def cache_version_for(
    harness: str, entry: HarnessConfig | None, bellwether_version: str
) -> str | None:
    """The harness version the key uses, or ``None`` where the plan must not be cached.

    ``harness`` is the target's harness name; ``entry`` its ``harnesses.<name>`` config, where
    one exists. The api-loop adapter ships with this package, so its version is Bellwether's
    own whatever the config says. A ``claude-code`` harness runs the CLI the sandbox image
    carries: pinned, the pin is the version; unpinned (or unconfigured), the version is only
    observable after the run, and a key cannot be formed honestly before it — so such plans
    bypass the cache rather than hit across an upgrade.
    """
    if harness == "api-loop":
        return bellwether_version
    if entry is None:
        return None
    return entry.version_pin


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
    #: The key inputs for a plan, or ``None`` where the plan must not be cached (the harness
    #: version is unknowable before the run — see :func:`cache_version_for`).
    inputs_for: Callable[[RunPlan], CacheKeyInputs | None]
    eval_id: str
    run_root: Path
    served_from_cache: list[str] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)
    #: Plans executed with the cache neither consulted nor filled, by coordinate.
    bypassed: list[str] = field(default_factory=list)

    def execute(self, plan: RunPlan) -> ExecutedRun:
        coordinate = f"{plan.scenario.id}/{plan.target.slug}/{plan.repetition}"
        inputs = self.inputs_for(plan)
        if inputs is None:
            self.bypassed.append(coordinate)
            return self.inner.execute(plan)
        key = cache_key(inputs)
        hit = self.cache.lookup(key)
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
