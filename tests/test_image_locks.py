"""The images install from locks that record each package's bytes, and the locks stay current.

``tools/pin_lint.py`` rule 4 makes every install go through a lock; this file holds each lock to
what it is meant to lock. A hash-locked requirements file that no longer satisfies
``pyproject.toml`` would build an image whose Bellwether cannot import its own dependencies (or
silently runs older ones), and a package-lock whose CLI version drifted from the golden session's
would run a CLI whose stream format the adapter was never checked against. Both are offline
checks: the network-dependent half — that pip and npm accept the hashes — runs where the images
are built, on CI.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPO_ROOT = Path(__file__).resolve().parent.parent
SIDECARS = ("proxy", "resolver")
CLI_DIR = REPO_ROOT / "sandbox" / "claude-code" / "cli"
CLI_PACKAGE = "@anthropic-ai/claude-code"

#: A locked requirement line: ``name==version [; marker] \``, then one ``--hash`` per line.
_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;\\]+)")


def _lock(sidecar: str) -> dict[str, tuple[str, int]]:
    """``{canonical name: (version, number of hashes)}`` for one sidecar's requirements.txt."""
    pins: dict[str, tuple[str, int]] = {}
    current = ""
    for line in (REPO_ROOT / "sidecar" / sidecar / "requirements.txt").read_text().splitlines():
        match = _PIN.match(line)
        if match:
            current = canonicalize_name(match["name"])
            assert current not in pins, f"{sidecar}: {current} is pinned twice"
            pins[current] = (match["version"], 0)
        elif line.strip().startswith("--hash=sha256:"):
            version, hashes = pins[current]
            pins[current] = (version, hashes + 1)
        elif line.strip() and not line.lstrip().startswith("#"):
            pytest.fail(f"{sidecar}/requirements.txt: unexpected line {line!r}")
    return pins


def _requirements(path: Path) -> list[Requirement]:
    lines = (line.split("#", 1)[0].strip() for line in path.read_text().splitlines())
    return [Requirement(line) for line in lines if line]


def _project_requirements() -> list[Requirement]:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    return [Requirement(spec) for spec in project["project"]["dependencies"]]


@pytest.mark.parametrize("sidecar", SIDECARS)
def test_every_locked_package_carries_a_hash(sidecar: str) -> None:
    pins = _lock(sidecar)
    assert pins, f"{sidecar}: the lock is empty"
    assert [name for name, (_, hashes) in pins.items() if hashes == 0] == []


@pytest.mark.parametrize("sidecar", SIDECARS)
def test_the_lock_satisfies_bellwether_and_the_sidecar_requirements(sidecar: str) -> None:
    """Every runtime dependency of the package, and every line of the sidecar's requirements.in,
    is pinned in the lock at a version that satisfies it. Bumping either without recompiling
    fails here, not in an image build on CI."""
    pins = _lock(sidecar)
    wanted = _project_requirements() + _requirements(
        REPO_ROOT / "sidecar" / sidecar / "requirements.in"
    )
    unmet = []
    for requirement in wanted:
        locked = pins.get(canonicalize_name(requirement.name))
        if locked is None or not requirement.specifier.contains(locked[0], prereleases=True):
            unmet.append(f"{requirement} (locked: {locked[0] if locked else 'absent'})")
    assert unmet == []


@pytest.mark.parametrize("sidecar", SIDECARS)
def test_the_dockerfile_installs_the_lock_it_copies(sidecar: str) -> None:
    dockerfile = (REPO_ROOT / "sidecar" / sidecar / "Dockerfile").read_text()
    assert f"COPY sidecar/{sidecar}/requirements.txt /app/requirements.txt" in dockerfile
    assert "--require-hashes --only-binary :all: -r /app/requirements.txt" in dockerfile


def test_the_cli_lock_pins_the_golden_session_version() -> None:
    """The sandbox and the offline suite run the CLI the golden session was taken from."""
    first = (REPO_ROOT / "tests" / "golden" / "claude-code" / "stream.jsonl").read_text()
    golden = json.loads(first.splitlines()[0])["claude_code_version"]
    manifest = json.loads((CLI_DIR / "package.json").read_text())
    lock = json.loads((CLI_DIR / "package-lock.json").read_text())
    assert manifest["dependencies"] == {CLI_PACKAGE: golden}
    assert lock["packages"][""]["dependencies"] == {CLI_PACKAGE: golden}
    assert lock["packages"][f"node_modules/{CLI_PACKAGE}"]["version"] == golden
    assert (
        f"claude_code_version: {golden}"
        in (REPO_ROOT / "sandbox" / "claude-code" / "Dockerfile").read_text()
    )


def test_every_cli_package_records_its_integrity() -> None:
    """``npm ci`` checks a tarball against ``integrity`` — but only where the lock records one,
    and only from where it says it came."""
    lock = json.loads((CLI_DIR / "package-lock.json").read_text())
    packages = {path: entry for path, entry in lock["packages"].items() if path}
    assert packages
    for path, entry in packages.items():
        assert entry.get("integrity", "").startswith("sha512-"), path
        assert entry.get("resolved", "").startswith("https://registry.npmjs.org/"), path
