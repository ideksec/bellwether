"""Executable inventory, interpreter detection, and token estimates (§6.1).

A skill's bundled scripts are the part a human reviewer is least likely to read closely
and the part most able to act, so the inventory is a first-class output rather than a
detail of parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bellwether.skill.digests import FileRecord

__all__ = [
    "Executable",
    "build_inventory",
    "detect_interpreter",
    "estimate_tokens",
]

#: Extension to interpreter, used where there is no shebang. Deliberately conservative:
#: guessing wrongly here would put a misleading interpreter in a security report.
_EXTENSION_INTERPRETERS: dict[str, str] = {
    ".py": "python",
    ".sh": "sh",
    ".bash": "bash",
    ".zsh": "zsh",
    ".fish": "fish",
    ".rb": "ruby",
    ".js": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".ts": "node",
    ".pl": "perl",
    ".php": "php",
    ".ps1": "powershell",
    ".r": "rscript",
    ".lua": "lua",
}

_SHEBANG_RE = re.compile(r"^#!\s*(?P<path>\S+)(?P<rest>.*)$")


@dataclass(frozen=True)
class Executable:
    """One bundled script.

    Attributes:
        path: POSIX path relative to the skill root.
        interpreter: Best-effort interpreter name, or ``None`` where undetermined.
        source: How the interpreter was determined — ``shebang``, ``extension``, or
            ``unknown``. A reviewer reading "python (extension)" knows the file does not
            actually declare an interpreter, which is different information from
            "python (shebang)".
        shebang: The raw first line, where present.
        executable_bit: Whether the owner-execute bit is set.
        in_payload: Whether this file is installed into the container. A script under
            ``evals/`` never executes there.
    """

    path: str
    interpreter: str | None
    source: str
    shebang: str | None
    executable_bit: bool
    in_payload: bool


def detect_interpreter(first_line: str | None, path: str) -> tuple[str | None, str, str | None]:
    """Return ``(interpreter, source, shebang)`` for a file.

    A shebang wins over the extension, and ``/usr/bin/env python3`` resolves to the
    program being run rather than to ``env``.
    """
    if first_line and first_line.startswith("#!"):
        match = _SHEBANG_RE.match(first_line.strip())
        if match:
            program = Path(match.group("path")).name
            rest = match.group("rest").split()
            if program == "env":
                # `env -S node --flag` and `env -i python3` both name the interpreter
                # after their own options, not immediately.
                arguments = [item for item in rest if not item.startswith("-") and "=" not in item]
                if arguments:
                    program = Path(arguments[0]).name
            return _normalise_interpreter(program), "shebang", first_line.strip()

    extension = Path(path).suffix.lower()
    if extension in _EXTENSION_INTERPRETERS:
        return _EXTENSION_INTERPRETERS[extension], "extension", None
    return None, "unknown", None


def _normalise_interpreter(program: str) -> str:
    """Collapse versioned interpreter names: ``python3.12`` and ``python3`` are python."""
    stripped = re.sub(r"[0-9.]+$", "", program)
    return stripped or program


def build_inventory(
    root: Path, records: list[FileRecord], payload_paths: set[str]
) -> list[Executable]:
    """Inventory every file that is executable, or that looks like a script.

    Both conditions matter. A script without the execute bit still runs under
    ``python script.py``, and an executable file with no recognisable interpreter is
    itself worth reporting.
    """
    executables: list[Executable] = []
    for record in records:
        if record.is_symlink:
            continue
        first_line = _first_line(root / record.path)
        interpreter, source, shebang = detect_interpreter(first_line, record.path)
        if not record.is_executable and interpreter is None:
            continue
        executables.append(
            Executable(
                path=record.path,
                interpreter=interpreter,
                source=source,
                shebang=shebang,
                executable_bit=record.is_executable,
                in_payload=record.path in payload_paths,
            )
        )
    return executables


def _first_line(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            raw = handle.readline(512)
    except OSError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def estimate_tokens(text: str) -> int:
    """Estimate a token count without depending on any tokenizer.

    This is an **estimate** and is labelled as one wherever it is shown. Bellwether needs
    a figure for progressive-disclosure budgeting and for flagging an oversized skill
    body; it does not need to agree with a specific vendor's tokenizer, and taking a
    dependency on one would tie the figure to a model family the user may not be running.

    The heuristic is the usual one — roughly four characters per token for English prose —
    with a floor of one token per whitespace-separated word, which keeps it from
    understating text made of many short tokens such as code.
    """
    if not text.strip():
        return 0
    by_characters = (len(text) + 3) // 4
    by_words = len(text.split())
    return max(by_characters, by_words)
