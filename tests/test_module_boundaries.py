"""§8.1 module boundaries, enforced mechanically rather than by convention.

The build plan requires the import-linter contract to go in with WP-1, not later: a
dependency graph is easy to keep acyclic and expensive to make acyclic.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = REPO_ROOT / "src" / "bellwether"

#: The §8.1 stack, lowest first. Each module may import those before it and nothing after.
LAYERS = (
    "config",
    "skill",
    "scan",
    "sandbox",
    "harness",
    "capture",
    "trace",
    "assertions",
    "metrics",
    "verdict",
    "report",
    "cli",
)


def test_every_module_in_the_specification_exists() -> None:
    for name in LAYERS:
        assert (PACKAGE_ROOT / name / "__init__.py").is_file(), f"missing module: {name}"


def test_the_assertions_module_is_not_named_assert() -> None:
    """``assert`` is a Python keyword and cannot be a module name (§8.1)."""
    assert not (PACKAGE_ROOT / "assert").exists()
    assert (PACKAGE_ROOT / "assertions").is_dir()


def test_import_linter_contracts_hold() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "importlinter.cli", "lint-imports"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"import-linter contracts broken:\n{result.stdout}\n{result.stderr}")


def test_config_does_not_reach_the_network() -> None:
    """The bottom layer must not touch the network (§8.1). Checked here too because a
    missing tool would silently skip the contract above."""
    banned = ("import socket", "import httpx", "import requests", "import docker")
    for path in sorted((PACKAGE_ROOT / "config").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for statement in banned:
            assert statement not in source, f"{path} imports the network: {statement}"
