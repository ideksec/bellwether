#!/usr/bin/env python3
"""Fail the build if a supply-chain input is not pinned to an immutable digest.

Bellwether's whole thesis is that a supply-chain artifact is trustworthy only when what
you review is what runs. A CI that pulls ``actions/checkout@v5`` or ``alpine:3.20`` violates
that in the project's own plumbing: a tag is mutable, so the bytes that ran yesterday are
not guaranteed to run today, and a compromised tag is the classic CI supply-chain attack.

This lint enforces two rules mechanically, the way §16.3's language rule and §8.1's module
graph are enforced — by failing the build, not by convention:

1. **Every third-party GitHub Action is pinned to a full 40-hex commit SHA.** ``@v5`` is a
   tag; ``@fbc6f39…`` is a commit. Local actions (``./…``) and this repo's own reusable
   workflows are exempt. A ``# v5`` trailing comment is encouraged (Dependabot reads it to
   bump the pin) and ignored here.
2. **Every container image named in a workflow is pinned by digest** (``@sha256:…``). This
   covers the ``*_IMAGE`` env vars and ``docker pull`` lines the CI uses.
3. **Every Dockerfile ``FROM`` is pinned by digest.** The sidecar image builds from a base; a
   floating base tag is the same mutable-input hole as a floating action, one layer down.

Run: ``uv run python tools/pin_lint.py`` (CI runs it on every push).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

#: A pinned action ref: owner/repo (optionally with a /subdir) @ 40 hex chars.
_SHA = re.compile(r"^[0-9a-f]{40}$")
_USES = re.compile(r"""^\s*-?\s*uses:\s*["']?(?P<ref>[^"'\s]+)["']?""")
#: An image reference in a workflow value: something like ``repo/name:tag`` — we flag it
#: when it carries a tag but no ``@sha256:`` digest.
_IMAGE_ENV = re.compile(r"""(?P<key>[A-Z0-9_]*IMAGE)\s*:\s*["']?(?P<val>\S+?)["']?\s*$""")
_DOCKER_PULL = re.compile(r"""docker\s+pull\s+(?:-q\s+)?["']?(?P<val>[^"'\s]+)""")
#: A Dockerfile ``FROM`` line: ``FROM image[:tag][@sha256:...] [AS stage]``. A ``FROM`` of a
#: previous build stage (``FROM builder``) carries no registry ref and is exempt.
_FROM = re.compile(r"""^\s*FROM\s+(?P<val>\S+)""", re.IGNORECASE)
#: Directories whose contents are not this project's own supply-chain inputs.
_IGNORED_DIRS = frozenset({".venv", ".git", "node_modules", ".mypy_cache", ".ruff_cache"})


def _uses_is_pinned(ref: str) -> bool:
    """True if a ``uses:`` ref is exempt (local / reusable) or SHA-pinned."""
    if ref.startswith((".", "docker://")):
        # Local composite actions and this repo's own workflows are reviewed as source;
        # docker:// refs are checked by the image rule below where they carry a digest.
        return "docker://" not in ref or "@sha256:" in ref
    if "@" not in ref:
        return False
    return bool(_SHA.match(ref.rsplit("@", 1)[1]))


def _image_is_pinned(value: str) -> bool:
    """True if an image reference carries a digest (or is a ``$VAR`` we check at its source)."""
    if value.startswith("$") or value.startswith("${"):
        return True  # a variable reference; the definition is linted where it is set
    return "@sha256:" in value


def check_workflow(path: Path) -> list[str]:
    problems: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        uses = _USES.match(line)
        if uses and not _uses_is_pinned(uses.group("ref")):
            problems.append(
                f"{path}:{number}: action {uses.group('ref')!r} is not pinned to a "
                f"40-hex commit SHA (a tag is mutable — pin it, keep the version in a "
                f"trailing '# vN' comment)"
            )
        env = _IMAGE_ENV.search(line)
        if env and not _image_is_pinned(env.group("val")):
            problems.append(
                f"{path}:{number}: image {env.group('val')!r} is not pinned by digest; "
                f"append '@sha256:...'"
            )
        pull = _DOCKER_PULL.search(line)
        if pull and not _image_is_pinned(pull.group("val")):
            problems.append(
                f"{path}:{number}: 'docker pull {pull.group('val')}' is not digest-pinned"
            )
    return problems


def check_dockerfile(path: Path) -> list[str]:
    """A Dockerfile is clean when every ``FROM`` that names a registry image carries a digest.

    A ``FROM <earlier-stage>`` in a multi-stage build names no registry image (it has no ``/``,
    ``:`` or ``.``) and is exempt — it inherits the pin of the stage it refers to.
    """
    problems: list[str] = []
    stages: set[str] = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = _FROM.match(line)
        if not match:
            continue
        ref = match.group("val")
        tokens = line.split()
        # `FROM x AS y` — record the stage name so a later `FROM y` is recognised as internal.
        if len(tokens) >= 4 and tokens[2].upper() == "AS":
            stages.add(tokens[3])
        if ref in stages or ref == "scratch":
            continue
        if "@sha256:" not in ref:
            problems.append(
                f"{path}:{number}: base image {ref!r} is not pinned by digest; append "
                f"'@sha256:...' (a base tag is mutable — pin it, keep the version in a comment)"
            )
    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path()
    workflow_root = root / ".github" / "workflows" if root == Path() else root
    workflows = sorted(workflow_root.rglob("*.yml")) + sorted(workflow_root.rglob("*.yaml"))
    dockerfiles = [
        path
        for pattern in ("Dockerfile", "*.Dockerfile")
        for path in sorted(root.rglob(pattern))
        # Skip vendored / build trees: a Dockerfile inside an installed dependency or the git
        # object store is not this project's supply-chain input.
        if not any(part in _IGNORED_DIRS for part in path.parts)
    ]
    if not workflows and not dockerfiles:
        print(f"pin-lint: no workflow or Dockerfile inputs under {root}", file=sys.stderr)
        return 0

    problems: list[str] = []
    for path in workflows:
        problems.extend(check_workflow(path))
    for path in dockerfiles:
        problems.extend(check_dockerfile(path))

    if problems:
        print("\n".join(problems), file=sys.stderr)
        print(
            f"\n{len(problems)} unpinned supply-chain input(s). Bellwether pins every action "
            f"by commit SHA and every image by digest; see tools/pin_lint.py.",
            file=sys.stderr,
        )
        return 1

    print(
        f"pin-lint: {len(workflows)} workflow + {len(dockerfiles)} Dockerfile input(s) — "
        f"every action and image is pinned."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
