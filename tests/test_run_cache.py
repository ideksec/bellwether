"""The run cache (§19.2): traces reused instead of repetitions paid for again.

The key is the spec's — payload digest, scenario *content* (not id), target, fixture digest,
harness version, sandbox image, platform baseline version — plus the model id (never cache across
a changed model id) and the repetition index (a set exists to observe variance; one run replayed
N times would agree with itself by construction). Entries expire by TTL; only complete,
non-infrastructure-failure runs are stored; a hit is re-filed under the new evaluation with
`cached_from` naming the original.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from bellwether.cli.orchestrator import ExecutedRun, RunPlan, TargetInfo
from bellwether.cli.run_cache import (
    CACHE_FORMAT,
    CacheKeyInputs,
    CachingExecutor,
    RunCache,
    cache_key,
    cache_version_for,
    observability_key,
    render_sampling,
    scenario_content_digest,
)
from bellwether.config.models.config import Config, HarnessConfig
from bellwether.config.models.scenarios import Scenario
from bellwether.harness import SamplingSpec
from bellwether.trace import NormalizationContext, read_trace, write_trace
from tests.factories import make_action, make_footer, make_header


def _scenario(**overrides: object) -> Scenario:
    data: dict[str, object] = {
        "id": "s",
        "expectation": "should_trigger",
        "prompt": "go",
        "assert": [{"skill_activated": True}],
    }
    data.update(overrides)
    return Scenario.model_validate(data)


def _inputs(**overrides: object) -> CacheKeyInputs:
    data: dict[str, object] = {
        "payload_digest": "sha256:" + "a" * 64,
        "scenario_id": "s",
        "scenario_digest": "sha256:" + "b" * 64,
        "target_slug": "api-loop-anthropic-frontier",
        "fixture_digest": "sha256:" + "c" * 64,
        "harness": "api-loop",
        "harness_version": "0.1.0",
        "model_id": "model-1",
        "sandbox_image": "img@sha256:" + "d" * 64,
        "platform_baseline_version": "",
        "repetition": 1,
    }
    data.update(overrides)
    return CacheKeyInputs(**data)  # type: ignore[arg-type]


def test_the_scenario_digest_is_content_not_id() -> None:
    assert scenario_content_digest(_scenario()) == scenario_content_digest(_scenario(id="renamed"))
    assert scenario_content_digest(_scenario()) != scenario_content_digest(
        _scenario(prompt="other")
    )


def test_the_key_ignores_the_scenario_id_and_follows_the_spec_components() -> None:
    base = cache_key(_inputs())
    assert cache_key(_inputs(scenario_id="renamed")) == base
    for change in (
        {"scenario_digest": "sha256:" + "e" * 64},
        {"payload_digest": "sha256:" + "e" * 64},
        {"model_id": "model-2"},
        {"repetition": 2},
        {"fixture_digest": "sha256:" + "e" * 64},
        {"sandbox_image": "other@sha256:" + "e" * 64},
        {"platform_baseline_version": "2026.09.1"},
        {"harness_version": "0.2.0"},
        {"target_slug": "api-loop-anthropic-small"},
        # A temperature-default trace must never stand in for a pinned-sampling run.
        {"sampling": "temperature=0.0,seed=0"},
        # A companion's content reaches the run; only its name is in the scenario digest.
        {"companion_digests": ("sha256:" + "f" * 64,)},
        # What the run could watch, and the limits it ran under.
        {"observability": "sha256:" + "0" * 64},
        # The bundle's content outside the skill's own directory reaches the container, and
        # `payload_digest` does not cover it — so editing a shared file a skill reads, or
        # switching between a bare and a --plugin-dir run, must miss (§5/§6/§18).
        {"plugin_digest": "sha256:" + "9" * 64},
    ):
        assert cache_key(_inputs(**change)) != base, change


def _config(**overrides: object) -> Config:
    data: dict[str, object] = {
        "apiVersion": "bellwether/v1",
        "kind": "Config",
        "sandbox": {"image": "img@sha256:" + "d" * 64},
    }
    data.update(overrides)
    return Config.model_validate(data)


def test_wiring_a_plane_changes_the_observability_key() -> None:
    """The spec's key names the sandbox image, which says what is *inside* the container and
    nothing about what watches it. Turning a plane on must miss: replaying a networkless trace
    afterwards would leave egress or DNS not_evaluable while the operator believed otherwise."""
    base = observability_key(_config())
    for change in (
        {"egress": {"image": "proxy@sha256:" + "e" * 64}},
        {"egress": {"allowlist": ["example.test"]}},
        {"dns": {"image": "resolver@sha256:" + "e" * 64}},
        {"dns": {"allowlist": ["example.test"]}},
        {"canaries": {"enabled": False}},
        {"capture": {"filesystem_writes": "off"}},
        {"capture": {"process": "off"}},
        {"sandbox": {"image": "img@sha256:" + "d" * 64, "memory": "4g"}},
        {"sandbox": {"image": "img@sha256:" + "d" * 64, "pids_limit": 256}},
        {"sandbox": {"image": "img@sha256:" + "d" * 64, "timeout_seconds": 120}},
    ):
        assert observability_key(_config(**change)) != base, change
    # Stable for an unchanged configuration (§24): the same settings key the same way.
    assert observability_key(_config()) == base


@pytest.mark.parametrize("exit_reason", ["timeout", "oom", "pids_limit", "budget_exceeded"])
def test_an_operator_limit_outcome_is_never_stored(exit_reason: str, tmp_path: Path) -> None:
    """Each of these is decided by a bound the key cannot carry — the token cap, the suite's
    timeout defaults, the sandbox memory and process limits — so a cached one would be replayed
    unchanged after the operator raised the very limit that produced it (§12.7, §19.2)."""
    cache = RunCache(root=tmp_path / "cache", ttl_days=14)
    key = cache_key(_inputs())
    assert cache.store(key, _executed(exit_reason, tmp_path), _inputs()) is None
    assert cache.lookup(key) is None


def test_a_completed_run_is_still_stored(tmp_path: Path) -> None:
    cache = RunCache(root=tmp_path / "cache", ttl_days=14)
    key = cache_key(_inputs())
    assert cache.store(key, _executed("completed", tmp_path), _inputs()) is not None
    assert cache.lookup(key) is not None


def test_sampling_renders_empty_for_provider_defaults_and_pinned_otherwise() -> None:
    assert render_sampling(None) == ""
    assert render_sampling(SamplingSpec(temperature=0.0, seed=0)) == "temperature=0.0,seed=0"
    assert render_sampling(SamplingSpec(temperature=0.0)) == "temperature=0.0,seed=None"


def test_the_harness_version_is_bellwethers_for_api_loop_and_the_pin_for_claude_code() -> None:
    # The api-loop adapter ships with this package: its version is Bellwether's, configured or not.
    assert cache_version_for("api-loop", None, "0.1.0") == "0.1.0"
    assert cache_version_for("api-loop", HarnessConfig(type="api-loop"), "0.1.0") == "0.1.0"
    pinned = HarnessConfig(type="claude-code", version_pin="2.1.257")
    assert cache_version_for("claude-code", pinned, "0.1.0") == "2.1.257"
    # Unpinned: the CLI version is observable only after the run, so no key can be formed.
    assert cache_version_for("claude-code", HarnessConfig(type="claude-code"), "0.1.0") is None
    assert cache_version_for("claude-code", None, "0.1.0") is None


def _executed(exit_reason: str, tmp_path: Path) -> ExecutedRun:
    path = write_trace(
        tmp_path / f"{exit_reason}.arf.jsonl",
        make_header(),
        [make_action(0)],
        make_footer(exit_reason=exit_reason),
    )
    return ExecutedRun(
        trace=read_trace(path),
        context=NormalizationContext(workspace_root="/work/ws", home="/home/agent", tmp="/tmp"),
        trace_jsonl=path.read_text(encoding="utf-8"),
    )


class _CountingExecutor:
    def __init__(self, tmp_path: Path) -> None:
        self.calls = 0
        self.tmp_path = tmp_path

    def execute(self, plan: RunPlan) -> ExecutedRun:
        self.calls += 1
        return _executed("completed", self.tmp_path / str(self.calls))


def test_an_uncacheable_plan_bypasses_the_cache_and_is_recorded(tmp_path: Path) -> None:
    """A plan whose key cannot be formed (an unpinned claude-code harness) is executed with the
    cache neither consulted nor filled, and the bypass is recorded for disclosure."""
    (tmp_path / "1").mkdir()
    (tmp_path / "2").mkdir()
    cache = RunCache(root=tmp_path / "cache", ttl_days=14)
    inner = _CountingExecutor(tmp_path)
    caching = CachingExecutor(
        inner, cache, lambda _plan: None, eval_id="e", run_root=tmp_path / "runs"
    )
    plan = RunPlan(
        scenario=_scenario(),
        target=TargetInfo("claude-code", "anthropic", "frontier"),
        repetition=1,
    )
    caching.execute(plan)
    caching.execute(plan)
    assert inner.calls == 2
    assert caching.bypassed == ["s/claude-code-anthropic-frontier/1"] * 2
    assert caching.served_from_cache == [] and caching.executed == []
    assert not (tmp_path / "cache").exists()  # never consulted, never filled


def test_lookup_returns_none_for_a_missing_or_malformed_entry(tmp_path: Path) -> None:
    cache = RunCache(root=tmp_path, ttl_days=14)
    assert cache.lookup("sha256:" + "0" * 64) is None
    entry = tmp_path / ("1" * 64)
    entry.mkdir()
    (entry / "meta.json").write_text("{not json", encoding="utf-8")
    (entry / "trace.arf.jsonl").write_text("", encoding="utf-8")
    assert cache.lookup("sha256:" + "1" * 64) is None


def test_an_entry_of_another_format_or_past_its_ttl_is_not_served(tmp_path: Path) -> None:
    import json

    now = dt.datetime(2026, 9, 17, tzinfo=dt.UTC)
    cache = RunCache(root=tmp_path, ttl_days=14, clock=lambda: now)
    entry = tmp_path / ("2" * 64)
    entry.mkdir()
    (entry / "trace.arf.jsonl").write_text("", encoding="utf-8")
    meta = {
        "cache_format": CACHE_FORMAT,
        "stored_at": (now - dt.timedelta(days=13)).isoformat(),
        "context": {"workspace_root": "/work/x", "home": "/home/agent", "tmp": "/tmp"},
        "inputs": {},
    }
    (entry / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    assert cache.lookup("sha256:" + "2" * 64) is not None
    meta["stored_at"] = (now - dt.timedelta(days=15)).isoformat()
    (entry / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    assert cache.lookup("sha256:" + "2" * 64) is None
    meta["stored_at"] = now.isoformat()
    meta["cache_format"] = "0"
    (entry / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    assert cache.lookup("sha256:" + "2" * 64) is None


def test_a_replayed_retry_is_not_reported_as_a_retry_of_this_evaluation(tmp_path: Path) -> None:
    """§13.2: a trace stored from a run that succeeded on its second attempt carries
    ``attempt: 2`` and a ``retry_of`` naming a run of *that* evaluation. Served to a later
    evaluation, nothing was retried there — the replayed header says attempt 1, no retry_of, and
    ``cached_from`` still points at the original."""

    class _RetriedExecutor:
        def execute(self, plan: RunPlan) -> ExecutedRun:
            path = write_trace(
                tmp_path / "retried.arf.jsonl",
                make_header(attempt=2, retry_of="old-s-api-loop-anthropic-frontier-001"),
                [make_action(0)],
                make_footer(exit_reason="completed"),
            )
            return ExecutedRun(
                trace=read_trace(path),
                context=NormalizationContext(
                    workspace_root="/work/ws", home="/home/agent", tmp="/tmp"
                ),
                trace_jsonl=path.read_text(encoding="utf-8"),
            )

    cache = RunCache(root=tmp_path / "cache", ttl_days=14)
    plan = RunPlan(
        scenario=_scenario(), target=TargetInfo("api-loop", "anthropic", "frontier"), repetition=1
    )
    first = CachingExecutor(
        _RetriedExecutor(), cache, lambda _p: _inputs(), eval_id="old", run_root=tmp_path / "a"
    )
    first.execute(plan)
    later = CachingExecutor(
        _RetriedExecutor(), cache, lambda _p: _inputs(), eval_id="new", run_root=tmp_path / "b"
    )
    replayed = later.execute(plan)
    assert later.served_from_cache == ["s/api-loop-anthropic-frontier/1"]
    header = replayed.trace.header
    assert (header.attempt, header.retry_of) == (1, None)
    assert header.cached_from is not None and header.cached_from.startswith("01JEVAL")
