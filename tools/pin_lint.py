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
   covers the ``*_IMAGE`` env vars and ``docker pull`` lines the CI uses, and also the other
   ways a mutable image slips into a workflow: a job/step ``container:`` (inline or its
   ``image:`` mapping), a ``services:`` entry's ``image:``, and a ``docker run`` in a step. A
   value that carries a tag but no ``@sha256:`` digest (and is not a ``$VAR``) is flagged.
3. **Every Dockerfile ``FROM`` is pinned by digest.** The sidecar image builds from a base; a
   floating base tag is the same mutable-input hole as a floating action, one layer down.
4. **Every package a Dockerfile, workflow or shell script installs comes from a lock that
   records its bytes.** A version pin (``mitmproxy==12.2.3``, ``pkg@2.1.257``) names a release,
   not its contents. The check is an allowlist of *locked forms*, not a list of bad ones: ``pip
   install`` must carry ``--require-hashes`` (or ``--no-index``, which fetches nothing), and
   ``npm`` may run only subcommands that install nothing from a manifest (``npm ci`` installs
   exactly ``package-lock.json`` and checks each ``integrity``). Any other package manager is
   refused until its locked form is added here. OS packages (``apt-get``) are out of scope:
   they come from a signed distribution archive, which pins their origin but not their version.

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
#: A GitHub Actions ``container:`` with an *inline* image value. The job-/step-defining
#: ``container:`` whose value is a nested mapping carries no inline value, so it is not matched
#: (its image, if any, is caught by ``_IMAGE_KEY`` on the nested ``image:`` line instead). This
#: is what keeps a job whose id happens to be ``container`` from being read as an image.
_CONTAINER_INLINE = re.compile(r"""^\s*container:\s+["']?(?P<val>[^"'\s#]+)""")
#: An ``image:`` mapping key — used under ``container:`` and under each ``services:`` entry.
_IMAGE_KEY = re.compile(r"""^\s*image:\s+["']?(?P<val>[^"'\s#]+)""")
#: A ``docker run`` invocation; the image is the first positional token after its flags.
_DOCKER_RUN = re.compile(r"""docker\s+run\s+(?P<rest>\S.*)$""")
#: ``docker run`` options that consume the *following* token as their value, so a value such as
#: ``-v host:/c`` or ``-p 8080:80`` is not mistaken for (nor scanned as) the image argument.
_DOCKER_RUN_VALUE_FLAGS = frozenset(
    {
        "-v", "--volume", "-e", "--env", "--env-file", "-p", "--publish", "--name",
        "-w", "--workdir", "-u", "--user", "--entrypoint", "--network", "--net",
        "--platform", "-l", "--label", "--mount", "--add-host", "--device", "-h",
        "--hostname", "--restart", "-m", "--memory", "--cpus", "--security-opt",
        "--cap-add", "--cap-drop", "--tmpfs", "--pull", "--gpus", "--link", "--expose",
    }
)  # fmt: skip
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


def _has_tag(value: str) -> bool:
    """True if an image reference carries a ``:tag`` — a colon in its *final* path segment, so a
    ``registry:5000/name`` port is not misread as a tag. Used to flag only things that actually
    look like a tagged image, which keeps the ``container:``/``image:``/``docker run`` scans from
    tripping over non-image tokens."""
    return ":" in value.rsplit("/", 1)[-1]


def _docker_run_image(rest: str) -> str | None:
    """The image positional argument of a ``docker run <rest>``, or None if none is found.

    Flags are skipped: an ``--opt=value`` is self-contained, a bare option from
    :data:`_DOCKER_RUN_VALUE_FLAGS` consumes the next token, and any other ``-``-prefixed token
    is treated as a boolean flag. The first surviving token is the image. This is a heuristic —
    it does not parse shell quoting — so callers pair it with :func:`_has_tag`, flagging only a
    token that genuinely looks like a tagged image.
    """
    tokens = rest.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("-"):
            return token
        if "=" not in token and token in _DOCKER_RUN_VALUE_FLAGS:
            index += 2  # the flag plus the value token it consumes
        else:
            index += 1
    return None


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
        container = _CONTAINER_INLINE.match(line)
        if container:
            val = container.group("val")
            if _has_tag(val) and not _image_is_pinned(val):
                problems.append(
                    f"{path}:{number}: container image {val!r} is not pinned by digest; "
                    f"append '@sha256:...'"
                )
        image = _IMAGE_KEY.match(line)
        if image:
            val = image.group("val")
            if _has_tag(val) and not _image_is_pinned(val):
                problems.append(
                    f"{path}:{number}: image {val!r} is not pinned by digest; append '@sha256:...'"
                )
        run = _DOCKER_RUN.search(line)
        if run:
            val = _docker_run_image(run.group("rest"))
            if val is not None and _has_tag(val) and not _image_is_pinned(val):
                problems.append(
                    f"{path}:{number}: 'docker run' image {val!r} is not digest-pinned; "
                    f"append '@sha256:...'"
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


#: A shell command boundary. Splitting on these isolates each simple command, so ``cd x && npm
#: install`` is judged on ``npm install``. A heuristic, not a shell parser — it is paired with an
#: allowlist, so a spelling it fails to split is flagged rather than passed.
_SHELL_BOUNDARY = re.compile(r"&&|\|\||[;|()`]|\$\(")
#: Leading tokens that wrap a command without changing which program runs.
_COMMAND_WRAPPERS = frozenset({"sudo", "-E", "exec", "command", "env", "time", "nohup"})
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PIP = re.compile(r"^pip[0-9.]*$")
_PYTHON = re.compile(r"^python[0-9.]*$")
#: The npm subcommands that install nothing from a manifest. ``ci`` installs ``package-lock.json``
#: exactly and refuses a tarball whose ``integrity`` differs; the rest read or clean. Everything
#: else — ``install`` and its many aliases (``i``, ``add``, ``isntall``...), ``update``, ``exec``
#: — is refused, which is why this is an allowlist: npm's alias table is longer than any
#: denylist would stay.
_NPM_LOCKED = frozenset({"ci", "cache", "view", "ls", "run", "test", "config"})
#: Package managers with no locked form recognised here yet: refused outright, not passed.
_UNRECOGNISED_INSTALLERS = frozenset({"npx", "yarn", "pnpm", "bun", "pipx", "gem", "cargo"})


def _subcommand(args: list[str]) -> str | None:
    """The first non-flag argument (``pip --no-cache-dir install`` → ``install``), or None."""
    return next((arg for arg in args if not arg.startswith("-")), None)


def install_problems(command: str) -> list[str]:
    """Each package install in a shell command line that does not install from a lock (rule 4)."""
    problems: list[str] = []
    for segment in _SHELL_BOUNDARY.split(command):
        tokens = segment.replace('"', " ").replace("'", " ").replace(",", " ").split()
        # Exec-form RUN (`RUN ["pip", "install", ...]`) and a YAML list item / `run:` key.
        tokens = [token.strip("[]") for token in tokens if token.strip("[]")]
        while tokens and (
            tokens[0] in _COMMAND_WRAPPERS
            or tokens[0] in {"-", "run:", "RUN"}
            or _ENV_ASSIGNMENT.match(tokens[0])
        ):
            tokens.pop(0)
        if not tokens:
            continue
        tool, args = tokens[0].rsplit("/", 1)[-1], tokens[1:]
        if _PYTHON.match(tool) and args[:2] == ["-m", "pip"]:
            tool, args = "pip", args[2:]
        elif tool == "uv" and args[:1] == ["pip"]:
            tool, args = "pip", args[1:]
        if _PIP.match(tool):
            if _subcommand(args) == "install" and not (
                "--require-hashes" in args or "--no-index" in args
            ):
                problems.append(
                    f"'{' '.join(tokens)}' installs without --require-hashes; install from a "
                    f"hash-locked requirements file (or --no-index for a local build)"
                )
        elif tool == "npm":
            sub = _subcommand(args)
            if sub is not None and sub not in _NPM_LOCKED:
                problems.append(
                    f"'{' '.join(tokens)}' is not a locked npm install; commit a "
                    f"package-lock.json and install it with 'npm ci'"
                )
        elif tool in _UNRECOGNISED_INSTALLERS:
            problems.append(
                f"'{' '.join(tokens)}' uses {tool}, which has no locked form recognised by "
                f"tools/pin_lint.py; add one there or install through a lock it accepts"
            )
    return problems


def _logical_lines(path: Path) -> list[tuple[int, str]]:
    """Non-comment lines with ``\\`` continuations joined, each with its first line number."""
    lines: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        if not pending:
            start = number
        if raw.rstrip().endswith("\\"):
            pending.append(raw.rstrip()[:-1])
            continue
        pending.append(raw)
        lines.append((start, " ".join(pending)))
        pending = []
    if pending:
        lines.append((start, " ".join(pending)))
    return lines


def check_installs(path: Path) -> list[str]:
    """Rule 4 over one Dockerfile, workflow or shell script."""
    return [
        f"{path}:{number}: {problem}"
        for number, line in _logical_lines(path)
        for problem in install_problems(line)
    ]


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
    scripts = [
        path
        for path in sorted(root.rglob("*.sh"))
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
    for path in [*workflows, *dockerfiles, *scripts]:
        problems.extend(check_installs(path))

    if problems:
        print("\n".join(problems), file=sys.stderr)
        print(
            f"\n{len(problems)} unpinned supply-chain input(s). Bellwether pins every action "
            f"by commit SHA, every image by digest and every installed package by a lock that "
            f"records its bytes; see tools/pin_lint.py.",
            file=sys.stderr,
        )
        return 1

    print(
        f"pin-lint: {len(workflows)} workflow + {len(dockerfiles)} Dockerfile + {len(scripts)} "
        f"script input(s) — every action and image is pinned, every install is locked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
