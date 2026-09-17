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

from bellwether.cli.run_cache import (
    CACHE_FORMAT,
    CacheKeyInputs,
    RunCache,
    cache_key,
    scenario_content_digest,
)
from bellwether.config.models.scenarios import Scenario


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
    ):
        assert cache_key(_inputs(**change)) != base, change


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
