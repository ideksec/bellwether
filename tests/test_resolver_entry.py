"""WP-15: what runs inside the controlled-resolver sidecar (§10.6), offline.

The dnslib UDP server and the upstream forward are the container half, proven by the CI docker
test. Everything else — the config round-trip, the recording decision, the empty-log-at-t0
readiness proof, and the fail-loud config load — is pure and tested here, the same split the
recording proxy's ``sidecar_entry`` gets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bellwether.capture import DnsAllowlist, ResolverConfig, build_allowlist, read_query_records
from bellwether.capture.resolver_entry import (
    RESOLVER_CONFIG_ENV_VAR,
    _RecordingResolver,
    load_resolver_from_env,
)


def _resolver(tmp_path: Path, *allowed: str) -> _RecordingResolver:
    return _RecordingResolver(
        DnsAllowlist(frozenset(allowed)),
        str(tmp_path / "queries.jsonl"),
        clock=lambda: "1970-01-01T00:00:00+00:00",
    )


# ---------------------------------------------------------------------------
# Config round-trip
# ---------------------------------------------------------------------------


def test_config_round_trips() -> None:
    config = ResolverConfig(
        allowed=("api.anthropic.com", "eu.api.anthropic.com"),
        query_log_path="/bw/queries.jsonl",
        upstream="127.0.0.11",
        listen_port=53,
    )
    assert ResolverConfig.from_json(config.to_json()) == config


def test_config_json_is_canonical_and_byte_stable() -> None:
    config = ResolverConfig(allowed=("b.example", "a.example"), query_log_path="/bw/q.jsonl")
    assert config.to_json() == config.to_json()
    # Sorted keys — the host writes it and the resolver reads it, so it must not churn (§24).
    assert config.to_json().startswith('{"allowed":')


def test_build_allowlist_reconstructs_the_run_allowlist() -> None:
    config = ResolverConfig(allowed=("anthropic.com",), query_log_path="/bw/q.jsonl")
    allowlist = build_allowlist(config)
    assert allowlist.permits("eu.api.anthropic.com")
    assert not allowlist.permits("evil.example")


# ---------------------------------------------------------------------------
# The recording decision (the pure half of the dnslib resolve hook)
# ---------------------------------------------------------------------------


def test_record_resolves_an_allowlisted_name_and_logs_it(tmp_path: Path) -> None:
    resolver = _resolver(tmp_path, "api.anthropic.com")
    query = resolver.record("api.anthropic.com")
    assert query.resolved and not query.blocked
    assert resolver.recorded() == [query]


def test_record_blocks_and_logs_an_outside_allowlist_name(tmp_path: Path) -> None:
    resolver = _resolver(tmp_path, "api.anthropic.com")
    query = resolver.record("exfil.attacker.example")
    assert query.blocked
    assert "NXDOMAIN" in query.reason
    # The refused query is ground truth — recorded, not dropped.
    assert resolver.recorded() == [query]


def test_every_query_reaches_the_shared_log_immediately(tmp_path: Path) -> None:
    log = tmp_path / "queries.jsonl"
    resolver = _RecordingResolver(
        DnsAllowlist(frozenset({"api.anthropic.com"})),
        str(log),
        clock=lambda: "1970-01-01T00:00:00+00:00",
    )
    resolver.record("api.anthropic.com")
    resolver.record("exfil.attacker.example")
    # Read it back from disk (not the in-memory list): the log is flushed after each query.
    on_disk = read_query_records(log)
    assert [q.name for q in on_disk] == ["api.anthropic.com", "exfil.attacker.example"]
    assert [q.resolved for q in on_disk] == [True, False]


def test_an_empty_log_is_written_at_construction(tmp_path: Path) -> None:
    """'the resolver ran' must be true from t=0, so an empty log exists before any query — a
    zero-query run reads as observed-clean, never as a missing plane."""
    log = tmp_path / "queries.jsonl"
    _resolver(tmp_path, "api.anthropic.com")
    assert log.exists()
    assert read_query_records(log) == []


# ---------------------------------------------------------------------------
# The env-driven load (fail-loud)
# ---------------------------------------------------------------------------


def test_load_resolver_from_env_reads_the_config(tmp_path: Path) -> None:
    config = ResolverConfig(
        allowed=("api.anthropic.com",), query_log_path=str(tmp_path / "queries.jsonl")
    )
    config_file = tmp_path / "resolver-config.json"
    config_file.write_text(config.to_json(), encoding="utf-8")

    resolver = load_resolver_from_env({RESOLVER_CONFIG_ENV_VAR: str(config_file)})
    # It came up ready (empty log) and honours the loaded allowlist.
    assert resolver.recorded() == []
    assert resolver.record("api.anthropic.com").resolved
    assert resolver.record("evil.example").blocked


def test_load_resolver_without_config_refuses_to_run() -> None:
    """A resolver that cannot find its config must fail to start, not run open or silently empty."""
    with pytest.raises(RuntimeError, match=RESOLVER_CONFIG_ENV_VAR):
        load_resolver_from_env({})
