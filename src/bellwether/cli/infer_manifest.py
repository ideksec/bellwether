"""``bellwether init-manifest`` — infer ``evals/manifest.yaml`` from an observed run (§6.2, §20).

§6.2: where a manifest is absent, Bellwether infers a scope from observed behaviour and
offers to write the file, *clearly marked as inferred-not-reviewed*. The observation is the
evaluation's ``summary.json`` — its ``capability_profile.tier3.expansions`` map every tier-1
class the matrix exercised to the exact things it touched (§13.5) — so the inferred scope is
what the skill *did*, spelled out as globs a reviewer then tightens.

Two rules keep the inference honest. Classes that are findings, not permissions, are never
declared: a ``canary_read`` is a leak class, a blocked egress or a refused DNS name was
*denied*, and writing either into an allowlist would launder a finding into a declaration.
They are listed in the file's header as observed-but-not-declared instead. And the written
file is parsed back through the manifest loader before it is kept, so an inference the
loader would reject never lands.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bellwether.config.loader import parse_manifest
from bellwether.errors import BellwetherError
from bellwether.report import Summary
from bellwether.skill import SkillPackage

__all__ = [
    "MANIFEST_RELATIVE",
    "InferredScope",
    "infer_scope",
    "render_manifest_yaml",
    "write_inferred_manifest",
]

MANIFEST_RELATIVE = Path("evals") / "manifest.yaml"

#: Tier-1 classes whose tier-3 targets are declarations of the named area.
_READ_CLASSES = frozenset({"workspace_read", "outside_workspace_read"})
_WRITE_CLASSES = frozenset(
    {"workspace_write", "outside_workspace_write", "workspace_delete", "harness_state_write"}
)
#: Classes that are findings or denials and must never be laundered into an allowlist.
_NEVER_DECLARED_PREFIXES = ("egress_blocked:", "dns:", "dns_query:")
_NEVER_DECLARED = frozenset({"canary_read", "subagent_spawn"})


@dataclass(frozen=True)
class InferredScope:
    """What the run showed, split into the manifest's areas plus what was left undeclared."""

    tools: tuple[str, ...] = ()
    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    egress: tuple[str, ...] = ()
    processes: tuple[str, ...] = ()
    #: ``class → targets`` observed but deliberately not declared, with the reason each carries.
    undeclared: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def as_declared_scope(self) -> dict[str, Any]:
        return {
            "tools": {"allow": list(self.tools)},
            "filesystem": {"read": list(self.read), "write": list(self.write)},
            "network": {"egress_allow": list(self.egress)},
            "processes": {"allow": list(self.processes)},
            "credentials": {"expects": []},
        }


def _targets(expansions: Mapping[str, object], key: str) -> list[str]:
    value = expansions.get(key)
    if isinstance(value, (list, tuple)):
        return sorted({str(item) for item in value})
    return []


def _sensitive_prefixes(summary: Summary) -> dict[str, list[str]]:
    """The §13.5.4 sensitive-directory hits, as ``class → [top-level dir, ...]``."""
    hits = summary.capability_profile.tier2.get("sensitive_hits")
    out: dict[str, list[str]] = {}
    if isinstance(hits, (list, tuple)):
        for hit in hits:
            text = str(hit)
            if ":" in text:
                cls, prefix = text.split(":", 1)
                out.setdefault(cls, []).append(prefix)
    return out


def infer_scope(summary: Summary) -> InferredScope:
    """Read the capability profile into an :class:`InferredScope` (§13.5 → §6.2).

    A path under a §13.5.4 sensitive-directory hit is *not* declared even though the skill
    read or wrote it: that access is a finding the report surfaces, and writing it into the
    allowlist would launder it. It is listed in the header for the reviewer to declare
    deliberately (with ``credentials.expects``) if the skill legitimately needs it.
    """
    expansions = summary.capability_profile.tier3.get("expansions")
    if not isinstance(expansions, Mapping):
        expansions = {}
    sensitive = _sensitive_prefixes(summary)

    def split_sensitive(tier1: str, targets: list[str]) -> tuple[list[str], list[str]]:
        prefixes = sensitive.get(tier1, [])
        flagged = [t for t in targets if any(t.startswith(p) for p in prefixes)]
        return [t for t in targets if t not in flagged], flagged

    tools: set[str] = set()
    read: set[str] = set()
    write: set[str] = set()
    egress: set[str] = set()
    processes: set[str] = set()
    undeclared: list[tuple[str, str]] = []
    for tier1 in sorted(expansions):
        targets = _targets(expansions, tier1)
        listed = ", ".join(targets) if targets else "(no tier-3 target recorded)"
        if tier1.startswith("tool:"):
            tools.add(tier1.removeprefix("tool:"))
        elif tier1 in _READ_CLASSES or tier1 in _WRITE_CLASSES:
            plain, flagged = split_sensitive(tier1, targets)
            (read if tier1 in _READ_CLASSES else write).update(plain)
            if flagged:
                undeclared.append(
                    (
                        tier1,
                        f"{', '.join(flagged)}: under a sensitive directory (§13.5.4) — a "
                        "finding the report surfaces, not a permission; declare it only if the "
                        "skill legitimately needs it, and name the credential under "
                        "credentials.expects",
                    )
                )
        elif tier1.startswith("egress:"):
            egress.add(tier1.removeprefix("egress:"))
        elif tier1.startswith("process:"):
            processes.add(tier1.removeprefix("process:"))
        elif tier1.startswith(_NEVER_DECLARED_PREFIXES):
            undeclared.append(
                (
                    tier1,
                    f"{listed}: a blocked egress or a DNS lookup is a denial or a finding, "
                    "not a permission; declare the host under network.egress_allow only if it is "
                    "legitimately needed",
                )
            )
        elif tier1 in _NEVER_DECLARED:
            undeclared.append(
                (tier1, f"{listed}: a finding class (§10.4.1, §13.5.1); never declared")
            )
        else:
            undeclared.append((tier1, f"{listed}: no manifest area maps this class"))
    return InferredScope(
        tools=tuple(sorted(tools)),
        read=tuple(sorted(read)),
        write=tuple(sorted(write)),
        egress=tuple(sorted(egress)),
        processes=tuple(sorted(processes)),
        undeclared=tuple(undeclared),
    )


def render_manifest_yaml(
    scope: InferredScope,
    *,
    skill_name: str,
    eval_id: str,
    payload_digest: str,
    criticality: str,
    owner: str = "<fill in: the owning team>",
) -> str:
    """The manifest file text: an inferred-not-reviewed header, then the document."""
    header = [
        "# INFERRED, NOT REVIEWED (bellwether init-manifest, §6.2).",
        f"# Skill {skill_name!s}, from evaluation {eval_id} (payload {payload_digest}).",
        "# This declares exactly what that run observed the skill doing. Tighten each list to",
        "# the intent (globs, not the literal paths), set `owner`, review `criticality`, and",
        "# remove this header once a human has reviewed it. Every entry compiles to an",
        "# assertion on every scenario (§12.5); an over-broad declaration is a privilege.",
    ]
    if scope.undeclared:
        header.append("#")
        header.append("# Observed but deliberately NOT declared:")
        for tier1, why in scope.undeclared:
            header.append(f"#   - {tier1}: {why}")
    document: dict[str, Any] = {
        "apiVersion": "bellwether/v1",
        "kind": "SkillManifest",
        "metadata": {"owner": owner, "criticality": criticality},
        "declared_scope": scope.as_declared_scope(),
    }
    body = yaml.safe_dump(document, sort_keys=False, default_flow_style=False, allow_unicode=True)
    return "\n".join(header) + "\n\n" + body


def write_inferred_manifest(
    package: SkillPackage, summary: Summary, *, force: bool = False
) -> tuple[Path, InferredScope]:
    """Infer and write ``evals/manifest.yaml`` for ``package`` from ``summary``, or refuse.

    Refuses where the evaluation is of another skill, where a manifest already exists
    (unless ``force``), and where the rendered file does not parse back through the
    manifest loader — the last so an inference the loader rejects never lands on disk.
    """
    if summary.skill.name != package.name:
        raise BellwetherError(
            f"the evaluation {summary.eval_id!r} is of skill {summary.skill.name!r}, not "
            f"{package.name!r}; a manifest is inferred from the skill's own run"
        )
    target = package.root / MANIFEST_RELATIVE
    if target.exists() and not force:
        raise BellwetherError(
            f"{target} already exists; pass --force to overwrite it with the inferred scope "
            "(the existing declaration is a reviewed artefact and is not replaced silently)"
        )
    scope = infer_scope(summary)
    criticality = (
        package.manifest.metadata.criticality if package.manifest is not None else "medium"
    )
    text = render_manifest_yaml(
        scope,
        skill_name=package.name,
        eval_id=summary.eval_id,
        payload_digest=summary.skill.payload_digest,
        criticality=criticality,
    )
    parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise BellwetherError("the inferred manifest did not render as a mapping")
    parse_manifest(parsed, source=target)  # refuses before writing if the loader would
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target, scope


def describe(scope: InferredScope) -> Sequence[str]:
    """Human lines for the CLI: what was declared and what was left out."""
    lines = [
        f"  tools.allow            {list(scope.tools)}",
        f"  filesystem.read        {list(scope.read)}",
        f"  filesystem.write       {list(scope.write)}",
        f"  network.egress_allow   {list(scope.egress)}",
        f"  processes.allow        {list(scope.processes)}",
    ]
    for tier1, why in scope.undeclared:
        lines.append(f"  not declared: {tier1} — {why}")
    return lines
