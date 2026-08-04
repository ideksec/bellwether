"""Loading the two documents that live beside a skill (§6.2, §7).

``evals/manifest.yaml`` and ``evals/scenarios.yaml`` are read by :mod:`bellwether.skill`
and everything above it, so this module deliberately imports neither policy types nor
provider types.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bellwether.config.document import load_yaml_mapping, validate_document
from bellwether.config.models.manifest import SkillManifest
from bellwether.config.models.scenarios import ScenarioSuite

__all__ = ["load_manifest", "load_scenarios", "parse_manifest", "parse_scenarios"]


def parse_manifest(data: dict[str, Any], source: Path | str = "manifest.yaml") -> SkillManifest:
    return validate_document(SkillManifest, data, source)


def load_manifest(path: Path) -> SkillManifest:
    return parse_manifest(load_yaml_mapping(path), path)


def parse_scenarios(data: dict[str, Any], source: Path | str = "scenarios.yaml") -> ScenarioSuite:
    return validate_document(ScenarioSuite, data, source)


def load_scenarios(path: Path) -> ScenarioSuite:
    return parse_scenarios(load_yaml_mapping(path), path)
