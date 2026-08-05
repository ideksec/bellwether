"""Loading a skill package (§6).

A skill directory is read, never executed. Everything here is static: hashing, parsing,
inventory. If loading a skill could run any of it, the sandbox would already have been
bypassed before it started.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

# Imported from the submodules rather than from the `bellwether.config` facade: the
# facade re-exports policy types, and §8.1 allows only verdict, report and cli to see
# those. `.importlinter` enforces it, which is how this import list came to be precise.
from bellwether.config.loader import load_manifest, load_scenarios
from bellwether.config.models.manifest import LastHumanReview, SkillManifest
from bellwether.config.models.scenarios import ScenarioSuite
from bellwether.determinism import stable_hash
from bellwether.errors import SkillError
from bellwether.skill.digests import (
    RECORDED_REVIEW_PLACEHOLDER,
    FileRecord,
    description_digest,
    has_unusual_path_characters,
    merkle_digest,
    read_file_records,
)
from bellwether.skill.frontmatter import ParsedSkillMarkdown, parse_skill_markdown
from bellwether.skill.inventory import Executable, build_inventory, estimate_tokens
from bellwether.skill.payload import PayloadAllowlist, PayloadSplit

__all__ = ["SKILL_FILE", "ReviewState", "SkillPackage", "load_skill", "slugify_name"]

#: Characters allowed in the identifier used to build paths. Everything else is replaced.
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_LEADING_JUNK = re.compile(r"^[.\-]+")


def slugify_name(name: str) -> str:
    """Derive an identifier usable as a path segment and a command-line argument.

    A skill's ``name`` is written by whoever wrote the skill, and in external mode that is
    a third party. It reaches a container mount target, so it is attacker-controlled input
    to the trusted docker command line: ``name: /etc`` relocates the payload mount, because
    joining an absolute path *discards* the prefix it was joined to, and a name containing
    ``:`` injects extra fields into a ``-v`` spec.

    The declared name is still reported verbatim — it is what the skill claims to be. It is
    simply never the thing that builds a path.
    """
    slug = _SAFE_NAME.sub("-", name).strip("-")
    slug = _LEADING_JUNK.sub("", slug)[:64].rstrip(".-")
    # `.` and `..` are legal under the character rule and catastrophic as path segments.
    if slug in ("", ".", ".."):
        return "unnamed-skill"
    return slug


SKILL_FILE = "SKILL.md"
MANIFEST_PATH = "evals/manifest.yaml"
SCENARIOS_PATH = "evals/scenarios.yaml"

#: ``current`` — the recorded digest matches what is on disk.
#: ``stale`` — a review exists but was performed against different bytes. Treated as
#: ``not_evaluable`` by the verdict engine, which blocks a required gate (§6.3).
#: ``absent`` — no review recorded.
ReviewState = Literal["current", "stale", "absent"]


@dataclass(frozen=True)
class SkillPackage:
    """A parsed skill package and everything derived from it."""

    root: Path
    name: str
    parsed: ParsedSkillMarkdown
    files: tuple[FileRecord, ...]
    payload: PayloadSplit

    #: The full directory including ``evals/``. Binds review attestations (§6.3) and keys
    #: the library coexistence baseline (§7.4).
    package_digest: str
    #: Only what is installed into the container. Keys the run cache and the per-skill
    #: baseline, so editing a scenario does not invalidate cached runs of an unchanged
    #: skill, and editing the skill does.
    payload_digest: str
    #: The normalized description alone. Scopes coexistence re-runs (§7.4, §19.3).
    description_digest: str
    #: What a human review binds to (§6.3): the package with the recorded review digest
    #: blanked, so that writing the digest into the manifest does not change it. Equal to
    #: ``package_digest`` where no review is recorded. This is the value to write into
    #: ``metadata.review.last_human_review.package_digest``.
    attestation_digest: str

    executables: tuple[Executable, ...]
    #: Estimated tokens for ``SKILL.md``'s body and each progressive-disclosure file.
    #: Estimates, and labelled as such wherever shown.
    token_estimates: dict[str, int]

    manifest: SkillManifest | None = None
    scenarios: ScenarioSuite | None = None
    #: Non-fatal observations worth reporting: missing frontmatter, a pinned model, files
    #: the payload allowlist did not match.
    problems: tuple[str, ...] = field(default_factory=tuple)

    @property
    def slug(self) -> str:
        """The identifier used to build paths and command-line arguments.

        Never :attr:`name`: that is attacker-controlled in external mode.
        """
        return slugify_name(self.name)

    @property
    def description(self) -> str:
        if self.parsed.frontmatter is None:
            return ""
        return self.parsed.frontmatter.description or ""

    @property
    def declared_tools(self) -> tuple[str, ...]:
        if self.parsed.frontmatter is None:
            return ()
        return tuple(self.parsed.frontmatter.allowed_tools)

    @property
    def body_tokens(self) -> int:
        return self.token_estimates.get(SKILL_FILE, 0)

    def payload_records(self) -> list[FileRecord]:
        included = set(self.payload.included)
        return [record for record in self.files if record.path in included]

    def review_state(self) -> ReviewState:
        """Compare the recorded review digest against the package as it is now (§6.3).

        A review is bound to the bytes it was performed against. Editing a skill after
        review does not carry the approval forward.
        """
        review = self._review()
        if review is None:
            return "absent"
        if review.is_wellformed() and review.package_digest == self.attestation_digest:
            return "current"
        return "stale"

    def review_age_days(self, today: dt.date) -> int | None:
        """Age of the recorded review, against a date the caller supplies.

        Deliberately not defaulted to "now": the age feeds the ``human_review.max_age_days``
        gate, and a gate whose input is read from the clock inside the function is a gate
        whose result cannot be reproduced from the artifacts of the run that produced it.
        """
        review = self._review()
        if review is None:
            return None
        return review.age_days(today)

    def _review(self) -> LastHumanReview | None:
        if self.manifest is None or self.manifest.metadata.review is None:
            return None
        return self.manifest.metadata.review.last_human_review


def load_skill(
    root: Path,
    *,
    allowlist: PayloadAllowlist | None = None,
    load_evals: bool = True,
) -> SkillPackage:
    """Read a skill package from ``root``.

    Args:
        root: The skill directory — the one containing ``SKILL.md``.
        allowlist: Which files are installed into the container. Defaults to the
            shipped allowlist; an explicit one is recorded in the run header so a trace
            says exactly what was installed.
        load_evals: Whether to load ``evals/manifest.yaml`` and ``evals/scenarios.yaml``.
            External mode (§5) reads a third-party skill that has neither.
    """
    if not root.is_dir():
        raise SkillError(f"{root} is not a directory")

    skill_file = root / SKILL_FILE
    if not skill_file.is_file():
        raise SkillError(
            f"{root} has no {SKILL_FILE}; a skill package is a directory containing one"
        )

    records = read_file_records(root)
    parsed = parse_skill_markdown(skill_file.read_text(encoding="utf-8"))

    split = (allowlist or PayloadAllowlist()).split([record.path for record in records])
    included = set(split.included)

    problems = list(parsed.problems)
    unusual = [record.path for record in records if has_unusual_path_characters(record.path)]
    if unusual:
        problems.append(
            "file name(s) containing control characters, which is worth a look: "
            + ", ".join(repr(path) for path in unusual)
        )
    if split.has_unmatched():
        problems.append(
            "not installed into the container because the payload allowlist did not match: "
            + ", ".join(split.excluded_unmatched)
        )

    name = (parsed.frontmatter.name if parsed.frontmatter else None) or root.name
    if slugify_name(name) != name:
        problems.append(
            f"declared name {name!r} is not usable as a path or an argument; "
            f"{slugify_name(name)!r} is used wherever one is needed"
        )
    manifest = _load_manifest(root) if load_evals else None

    package = SkillPackage(
        root=root,
        name=name,
        parsed=parsed,
        files=tuple(records),
        payload=split,
        package_digest=merkle_digest(records),
        payload_digest=merkle_digest([r for r in records if r.path in included]),
        description_digest=description_digest(
            parsed.frontmatter.description if parsed.frontmatter else None
        ),
        attestation_digest=_attestation_digest(root, records, _recorded_review_digest(manifest)),
        executables=tuple(build_inventory(root, records, included)),
        token_estimates=_token_estimates(root, parsed, split),
        manifest=manifest,
        scenarios=_load_scenarios(root) if load_evals else None,
        problems=tuple(problems),
    )
    return package


def _recorded_review_digest(manifest: SkillManifest | None) -> str | None:
    if manifest is None or manifest.metadata.review is None:
        return None
    review = manifest.metadata.review.last_human_review
    return review.package_digest if review else None


def _attestation_digest(root: Path, records: list[FileRecord], recorded: str | None) -> str:
    """Digest the package with the recorded review digest blanked (§6.3).

    Without this the attestation is self-referential — the digest is recorded inside a
    file the digest covers — and no review could ever evaluate to ``current``.
    """
    if not recorded:
        return merkle_digest(records)

    rewritten: list[FileRecord] = []
    for record in records:
        if record.path != MANIFEST_PATH:
            rewritten.append(record)
            continue
        text = (root / record.path).read_text(encoding="utf-8")
        blanked = text.replace(recorded, RECORDED_REVIEW_PLACEHOLDER)
        rewritten.append(replace(record, sha256=stable_hash(blanked), size_bytes=len(blanked)))
    return merkle_digest(rewritten)


def _token_estimates(
    root: Path, parsed: ParsedSkillMarkdown, split: PayloadSplit
) -> dict[str, int]:
    """Estimate tokens for the body and each progressive-disclosure file.

    ``SKILL.md`` is measured as its *body*: the frontmatter is metadata the harness reads,
    not context the model pays for.
    """
    estimates = {SKILL_FILE: estimate_tokens(parsed.body)}
    for path in split.included:
        if path == SKILL_FILE or not path.endswith((".md", ".txt")):
            continue
        try:
            estimates[path] = estimate_tokens((root / path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
    return estimates


def _load_manifest(root: Path) -> SkillManifest | None:
    path = root / MANIFEST_PATH
    return load_manifest(path) if path.is_file() else None


def _load_scenarios(root: Path) -> ScenarioSuite | None:
    path = root / SCENARIOS_PATH
    return load_scenarios(path) if path.is_file() else None
