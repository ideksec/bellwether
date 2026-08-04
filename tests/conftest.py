"""Shared fixtures. Everything here runs offline, with no API key."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = REPO_ROOT / "src" / "bellwether" / "config" / "templates"
EXAMPLE_SKILL = REPO_ROOT / "examples" / "skills" / "security-review"

# The language lint is development tooling rather than shipped code, so it lives outside
# the package and is imported here by path.
sys.path.insert(0, str(REPO_ROOT / "tools"))


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


@pytest.fixture
def config_document() -> dict[str, Any]:
    """The shipped config template, as a fresh mutable dict."""
    return load_yaml(TEMPLATES / "config.yaml")


@pytest.fixture
def policy_document() -> dict[str, Any]:
    return load_yaml(TEMPLATES / "policy.yaml")


@pytest.fixture
def manifest_document() -> dict[str, Any]:
    return load_yaml(EXAMPLE_SKILL / "evals" / "manifest.yaml")


@pytest.fixture
def scenarios_document() -> dict[str, Any]:
    return load_yaml(EXAMPLE_SKILL / "evals" / "scenarios.yaml")
