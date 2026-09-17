"""Stored baselines for regression comparison (§17.5, §18.4).

``bellwether baseline set <skill>`` writes ``.bellwether/baselines/<skill>.baseline.json``: the
evaluation's ``summary.json`` wrapped with the §17.5 **baseline key** — ``(skill_name,
payload_digest_at_capture, canon_version, target_set_digest, platform_baseline_version)`` —
and the metadata the comparability table reads per component (``weights_digest``, the policy
profile and digest). The policy digest is context, never key: a baseline records
*observations*, and policy is applied at comparison time, so a threshold tweak must not
invalidate every baseline in the repository.

The record carries the whole summary rather than a hand-trimmed subset so that the same
:func:`bellwether.cli.diff.diff_summaries` comparison the ad-hoc ``diff`` command uses is
what the regression gate reads — one comparison, two callers, no drift between them.

Everything here is deterministic: the record is canonical JSON, and its digest (what the
summary's ``regression.baseline_digest`` names) is the hash of exactly those bytes.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from bellwether.config.document import CONFIG_FILE
from bellwether.determinism import canonical_json, stable_hash
from bellwether.errors import BellwetherError
from bellwether.report import Summary

__all__ = [
    "BASELINE_RECORD_VERSION",
    "DEFAULT_BASELINES_DIR",
    "BaselineKey",
    "BaselineRecord",
    "baseline_from_summary",
    "baseline_path",
    "load_baseline",
    "read_baseline_for",
    "render_baseline_json",
    "target_set_digest",
    "write_baseline",
]

#: The record's own schema version, bumped on any change to its shape.
BASELINE_RECORD_VERSION = "1"

#: ``.bellwether/baselines/`` — beside the config, committed to git (§17.5).
DEFAULT_BASELINES_DIR = CONFIG_FILE.parent / "baselines"

#: The ``.gitattributes`` line §17.5 asks a skills repository to ship beside its baselines:
#: concurrent PRs re-baselining the same skill conflict, and the resolution is to regenerate
#: on ``main``, never to merge two baselines by hand.
GITATTRIBUTES_LINE = "*.baseline.json merge=ours\n"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, protected_namespaces=())


class BaselineKey(_Frozen):
    """The §17.5 key. Two baselines with different keys describe different things."""

    skill_name: str
    payload_digest: str
    canon_version: str
    target_set_digest: str
    platform_baseline_version: str


class BaselineMetadata(_Frozen):
    """Recorded beside the key, never in it: each invalidates only individual components."""

    weights_digest: str
    policy_profile: str
    policy_digest: str
    bellwether_version: str
    captured_at: str


class BaselineRecord(_Frozen):
    baseline_version: str = BASELINE_RECORD_VERSION
    eval_id: str
    key: BaselineKey
    metadata: BaselineMetadata
    summary: Summary

    @property
    def digest(self) -> str:
        """The digest of the record's canonical bytes — what a comparison names."""
        return stable_hash(render_baseline_json(self))


def target_set_digest(target_slugs: Sequence[str]) -> str:
    """The digest of the sorted target slugs — order-free, so the same matrix hashes alike."""
    return stable_hash("\n".join(sorted(target_slugs)))


def baseline_from_summary(summary: Summary) -> BaselineRecord:
    """Wrap an evaluation's summary as a baseline record under its §17.5 key."""
    return BaselineRecord(
        eval_id=summary.eval_id,
        key=BaselineKey(
            skill_name=summary.skill.name,
            payload_digest=summary.skill.payload_digest,
            canon_version=summary.canon_version,
            target_set_digest=target_set_digest(summary.matrix.target_slugs),
            platform_baseline_version=summary.platform_baseline_version,
        ),
        metadata=BaselineMetadata(
            weights_digest=summary.consistency.weights_digest,
            policy_profile=summary.policy.profile,
            policy_digest=summary.policy.digest,
            bellwether_version=summary.bellwether_version,
            captured_at=summary.created_at,
        ),
        summary=summary,
    )


def render_baseline_json(record: BaselineRecord) -> str:
    return canonical_json(record.model_dump(mode="json"), indent=2) + "\n"


def baseline_path(baselines_dir: Path, skill_name: str) -> Path:
    """``<baselines_dir>/<skill>.baseline.json`` — one file per skill (§17.5)."""
    if "/" in skill_name or skill_name in {"", ".", ".."}:
        raise BellwetherError(f"{skill_name!r} is not a skill name that can file a baseline")
    return baselines_dir / f"{skill_name}.baseline.json"


def write_baseline(record: BaselineRecord, baselines_dir: Path) -> Path:
    """Write the record and the ``.gitattributes`` merge rule beside it; return the path."""
    baselines_dir.mkdir(parents=True, exist_ok=True)
    attributes = baselines_dir / ".gitattributes"
    if not attributes.exists():
        attributes.write_text(GITATTRIBUTES_LINE, encoding="utf-8")
    path = baseline_path(baselines_dir, record.key.skill_name)
    path.write_text(render_baseline_json(record), encoding="utf-8")
    return path


def load_baseline(path: Path) -> BaselineRecord:
    """Parse a baseline record, refusing with the file named on any shape problem."""
    try:
        record = BaselineRecord.model_validate_json(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise BellwetherError(f"cannot read baseline {path}: {error}") from None
    except ValidationError as error:
        raise BellwetherError(f"{path} is not a valid baseline record: {error}") from None
    if record.baseline_version != BASELINE_RECORD_VERSION:
        raise BellwetherError(
            f"{path} is a baseline record of version {record.baseline_version!r}; this build "
            f"reads version {BASELINE_RECORD_VERSION!r} — re-set the baseline from a current "
            "evaluation"
        )
    return record


def read_baseline_for(baselines_dir: Path, skill_name: str) -> BaselineRecord | None:
    """The stored baseline for ``skill_name``, or ``None`` where none has been set."""
    path = baseline_path(baselines_dir, skill_name)
    if not path.is_file():
        return None
    return load_baseline(path)
