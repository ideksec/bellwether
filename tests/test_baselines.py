"""Stored baselines and the regression gate (§17.5, §16.2).

A baseline is an evaluation's summary filed under the §17.5 key — skill, payload digest at
capture, canon version, target set, platform baseline version — with the per-component
metadata beside it. The regression gate compares the current readings against it under the
comparability table: a different canon version or target set refuses the whole comparison
and says so; a different platform baseline skips the capability sets; a different weights
digest skips the weighted figures; tier-1 expansion and a lower-bound drop are what block.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from bellwether import CANON_VERSION
from bellwether.cli import ExitCode, app
from bellwether.cli.baselines import (
    BASELINE_RECORD_VERSION,
    BaselineRecord,
    baseline_from_summary,
    baseline_path,
    load_baseline,
    read_baseline_for,
    render_baseline_json,
    target_set_digest,
    write_baseline,
)
from bellwether.cli.diff import load_summary
from bellwether.cli.orchestrator import (
    RegressionReading,
    SetReading,
    TargetInfo,
    _regression_result,
    regression_reading,
    regression_summary,
)
from bellwether.config import template_path
from bellwether.config.models.policy import ProfileSpec
from bellwether.config.policy_loader import parse_policy
from bellwether.errors import BellwetherError
from bellwether.report import Summary

_REPORTS = Path(__file__).resolve().parent.parent / "examples" / "reports"
_BENIGN = "demo-benign-note-taker"
_SNEAKY = "demo-sneaky-exfiltrator"
_TARGET = TargetInfo(harness="api-loop", provider="scripted", model_alias="frontier")

runner = CliRunner()


def _summary(eval_id: str = _BENIGN) -> Summary:
    return load_summary(_REPORTS / eval_id / "summary.json")


def _profile(**regression: object) -> ProfileSpec:
    policy = parse_policy(yaml.safe_load(template_path("policy.yaml").read_text(encoding="utf-8")))
    base = policy.profile("low")
    gate = base.gates.regression.model_copy(update=regression)
    return base.model_copy(update={"gates": base.gates.model_copy(update={"regression": gate})})


# ---------------------------------------------------------------------------
# the record
# ---------------------------------------------------------------------------


def test_the_key_is_derived_from_the_summary_and_the_target_set_is_order_free() -> None:
    record = baseline_from_summary(_summary())
    assert record.key.skill_name == "benign-note-taker"
    assert record.key.canon_version == CANON_VERSION
    assert record.key.target_set_digest == target_set_digest(["api-loop-scripted-frontier"])
    assert target_set_digest(["b", "a"]) == target_set_digest(["a", "b"])
    assert record.metadata.policy_profile == "low"


def test_the_record_round_trips_and_its_digest_is_the_bytes(tmp_path: Path) -> None:
    record = baseline_from_summary(_summary())
    path = write_baseline(record, tmp_path / "baselines")
    assert path.name == "benign-note-taker.baseline.json"
    loaded = load_baseline(path)
    assert loaded == record
    assert loaded.digest == record.digest
    assert render_baseline_json(loaded) == path.read_text(encoding="utf-8")
    # §17.5: the merge rule ships beside the baselines.
    assert "merge=ours" in (tmp_path / "baselines" / ".gitattributes").read_text(encoding="utf-8")


def test_read_baseline_for_returns_none_where_none_is_set(tmp_path: Path) -> None:
    assert read_baseline_for(tmp_path, "nothing") is None
    record = baseline_from_summary(_summary())
    write_baseline(record, tmp_path)
    assert read_baseline_for(tmp_path, "benign-note-taker") == record


def test_a_record_of_another_version_is_refused(tmp_path: Path) -> None:
    record = baseline_from_summary(_summary())
    payload = json.loads(render_baseline_json(record))
    payload["baseline_version"] = "0"
    path = tmp_path / "x.baseline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BellwetherError, match="version '0'"):
        load_baseline(path)


def test_a_malformed_record_is_refused_naming_the_file(tmp_path: Path) -> None:
    path = tmp_path / "x.baseline.json"
    path.write_text('{"eval_id": "x"}', encoding="utf-8")
    with pytest.raises(BellwetherError, match="not a valid baseline record"):
        load_baseline(path)


def test_baseline_path_refuses_a_name_that_escapes_the_directory(tmp_path: Path) -> None:
    with pytest.raises(BellwetherError):
        baseline_path(tmp_path, "../escape")
    with pytest.raises(BellwetherError):
        baseline_path(tmp_path, "")


# ---------------------------------------------------------------------------
# the comparison
# ---------------------------------------------------------------------------


def _reading(
    *,
    caps: tuple[str, ...] = ("tool:skill", "workspace_read", "workspace_write"),
    lower_bound: float = 0.6,
    bci: float = 100.0,
    sensitive: tuple[str, ...] = (),
    weights_digest: str = "sha256:w",
) -> SetReading:
    from bellwether.cli.artifacts import RunKey
    from bellwether.cli.orchestrator import AnalysedRun

    run = AnalysedRun(
        key=RunKey("s", _TARGET.slug, 1),
        outcome="pass",
        caps_t1=frozenset(caps),
        caps_t2=frozenset(),
        caps_t3=frozenset(),
        sensitive_hits=sensitive,
        steps=(),
        tier3_by_class={},
        scope_exceeded=(),
        trace_jsonl="",
        canonical_json="",
    )
    return SetReading(
        scenario_id="s",
        target=_TARGET,
        n_completed=6,
        n_evaluable=6,
        pass_rate=1.0,
        lower_bound=lower_bound,
        functional_threshold=0.5,
        look=6,
        look_outcome="pass",
        bci=bci,
        consistently_failing=False,
        jaccard_weighted=1.0,
        jaccard_plain=1.0,
        modal_trajectory_share=1.0,
        mean_pairwise_distance=0.0,
        rare_capability_risk="none",
        rare_capability_blocking=False,
        tier1_agreement=True,
        scope_exceeded=(),
        egress_observed=True,
        egress_blocked=False,
        weights_digest=weights_digest,
        runs=(run,),
        sensitive_hits=sensitive,
    )


def _baseline(summary: Summary | None = None, **updates: object) -> BaselineRecord:
    record = baseline_from_summary(summary or _summary())
    if updates:
        record = record.model_copy(update={"key": record.key.model_copy(update=updates)})
    return record


def _benign_weights_digest() -> str:
    return _summary().consistency.weights_digest


def test_an_unchanged_skill_reads_no_regression() -> None:
    base = _baseline()
    reading = regression_reading(
        [
            _reading(
                lower_bound=base.summary.functional.lower_bound,
                weights_digest=_benign_weights_digest(),
            )
        ],
        base,
        skill_name="benign-note-taker",
        platform_baseline_version="",
    )
    assert reading.composed
    assert reading.capabilities_added == ()
    assert reading.sensitive_hits_added == ()
    assert reading.lower_bound_drop == 0.0
    assert reading.bci_before is not None  # same weights digest: BCI compared
    result = _regression_result(reading, _profile())
    assert result.status == "pass"
    assert "no regression" in result.reason


def test_tier1_expansion_blocks_under_the_default_policy_and_warns_otherwise() -> None:
    base = _baseline()
    reading = regression_reading(
        [_reading(caps=("tool:skill", "workspace_read", "workspace_write", "process_exec"))],
        base,
        skill_name="benign-note-taker",
        platform_baseline_version="",
    )
    assert reading.capabilities_added == ("process_exec",)
    assert (
        _regression_result(reading, _profile(block_on_capability_expansion=True)).status == "block"
    )
    warn = _regression_result(reading, _profile(block_on_capability_expansion=False))
    assert warn.status == "warn"
    assert "process_exec" in warn.reason


def test_a_lower_bound_drop_beyond_the_threshold_blocks() -> None:
    base = _baseline()
    before = base.summary.functional.lower_bound
    reading = regression_reading(
        [_reading(lower_bound=round(before - 0.2, 6))],
        base,
        skill_name="benign-note-taker",
        platform_baseline_version="",
    )
    assert reading.lower_bound_drop == pytest.approx(0.2)
    assert _regression_result(reading, _profile(max_pass_rate_drop=0.1)).status == "block"
    assert _regression_result(reading, _profile(max_pass_rate_drop=0.3)).status == "pass"


def test_a_new_sensitive_hit_is_always_a_finding() -> None:
    base = _baseline()
    reading = regression_reading(
        [
            _reading(
                sensitive=("outside_workspace_read:${HOME}/.aws/",),
                lower_bound=base.summary.functional.lower_bound,
            )
        ],
        base,
        skill_name="benign-note-taker",
        platform_baseline_version="",
    )
    assert reading.sensitive_hits_added == ("outside_workspace_read:${HOME}/.aws/",)
    assert _regression_result(reading, _profile()).status == "warn"


def test_a_different_canon_version_refuses_the_comparison() -> None:
    reading = regression_reading(
        [_reading()],
        _baseline(canon_version="0.9"),
        skill_name="benign-note-taker",
        platform_baseline_version="",
    )
    assert not reading.composed
    assert "canon_version" in reading.notes[0]


def test_a_different_target_set_refuses_the_comparison() -> None:
    reading = regression_reading(
        [_reading()],
        _baseline(target_set_digest="sha256:other"),
        skill_name="benign-note-taker",
        platform_baseline_version="",
    )
    assert not reading.composed
    assert "target set" in reading.notes[0]


def test_another_skills_baseline_refuses_the_comparison() -> None:
    reading = regression_reading(
        [_reading()], _baseline(), skill_name="someone-else", platform_baseline_version=""
    )
    assert not reading.composed
    assert "someone-else" in reading.notes[0]


def test_a_different_platform_baseline_skips_capability_sets_but_compares_the_rate() -> None:
    base = _baseline(platform_baseline_version="2026.08.1")
    reading = regression_reading(
        [_reading(caps=("tool:skill", "process_exec"))],
        base,
        skill_name="benign-note-taker",
        platform_baseline_version="2026.09.1",
    )
    assert reading.composed
    assert reading.capabilities_added == ()  # not compared, not "nothing changed"
    assert any("platform_baseline_version" in item for item in reading.skipped)
    assert reading.lower_bound_after == 0.6
    result = _regression_result(reading, _profile())
    assert "not compared" in result.reason


def test_a_different_weights_digest_skips_the_bci() -> None:
    reading = regression_reading(
        [_reading(weights_digest="sha256:different")],
        _baseline(),
        skill_name="benign-note-taker",
        platform_baseline_version="",
    )
    assert reading.bci_before is None
    assert any("weights_digest" in item for item in reading.skipped)
    summary = regression_summary(reading)
    assert "bci" not in summary.deltas
    assert summary.baseline_eval_id == _BENIGN
    assert summary.skipped == reading.skipped


def test_regression_summary_carries_the_deltas() -> None:
    reading = RegressionReading(
        composed=True,
        notes=(),
        capabilities_added=("process_exec",),
        lower_bound_before=0.7,
        lower_bound_after=0.5,
        bci_before=90.0,
        bci_after=80.0,
        baseline_digest="sha256:b",
        baseline_eval_id="e",
    )
    summary = regression_summary(reading)
    assert summary.baseline_digest == "sha256:b"
    assert summary.deltas["capabilities_added"] == ["process_exec"]
    assert summary.deltas["lower_bound"] == {"before": 0.7, "after": 0.5, "drop": 0.2}
    assert summary.deltas["bci"] == {"before": 90.0, "after": 80.0, "drop": 10.0}


# ---------------------------------------------------------------------------
# the CLI
# ---------------------------------------------------------------------------


def test_baseline_set_show_clear_end_to_end(tmp_path: Path) -> None:
    baselines = tmp_path / "baselines"
    result = runner.invoke(
        app,
        [
            "baseline",
            "set",
            "benign-note-taker",
            "--from",
            _BENIGN,
            "--out",
            str(_REPORTS),
            "--baselines",
            str(baselines),
            "--json",
        ],
    )
    assert result.exit_code == ExitCode.OK, result.output
    payload = json.loads(result.output)
    assert payload["eval_id"] == _BENIGN
    assert (baselines / "benign-note-taker.baseline.json").is_file()

    shown = runner.invoke(
        app, ["baseline", "show", "benign-note-taker", "--baselines", str(baselines)]
    )
    assert shown.exit_code == ExitCode.OK, shown.output
    assert "canon_version" in shown.output and _BENIGN in shown.output

    cleared = runner.invoke(
        app, ["baseline", "clear", "benign-note-taker", "--baselines", str(baselines)]
    )
    assert cleared.exit_code == ExitCode.OK
    assert not (baselines / "benign-note-taker.baseline.json").exists()
    missing = runner.invoke(
        app, ["baseline", "show", "benign-note-taker", "--baselines", str(baselines)]
    )
    assert missing.exit_code == ExitCode.INFRASTRUCTURE


def test_baseline_set_refuses_an_evaluation_of_another_skill(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "baseline",
            "set",
            "benign-note-taker",
            "--from",
            _SNEAKY,
            "--out",
            str(_REPORTS),
            "--baselines",
            str(tmp_path),
        ],
    )
    assert result.exit_code == ExitCode.INFRASTRUCTURE
    assert "sneaky-exfiltrator" in result.output
    assert not list(tmp_path.glob("*.baseline.json"))


def test_baseline_record_version_constant_is_stamped() -> None:
    assert baseline_from_summary(_summary()).baseline_version == BASELINE_RECORD_VERSION
