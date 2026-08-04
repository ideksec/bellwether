"""Shipped ``.bellwether/`` templates, used by ``bellwether init`` (§20).

The templates are the documentation most users will actually read, so they carry the
reasoning inline: which settings are enforced and why, which numbers are provisional,
and which fields the user must fill in because Bellwether deliberately ships no model
identifiers of its own.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

__all__ = ["SCAFFOLD_FILES", "template_path", "template_text", "write_scaffold"]

#: Template file name -> destination, relative to the repository root (§5).
SCAFFOLD_FILES: dict[str, str] = {
    "config.yaml": ".bellwether/config.yaml",
    "policy.yaml": ".bellwether/policy.yaml",
    "platform-baseline.yaml": ".bellwether/platform-baseline.yaml",
}

#: Directories created empty by ``bellwether init``, each with a ``.gitkeep``.
SCAFFOLD_DIRS: tuple[str, ...] = (
    ".bellwether/fixtures/empty",
    ".bellwether/baselines",
)


def template_path(name: str) -> Path:
    """Return the on-disk path of a shipped template."""
    path = Path(str(resources.files("bellwether.config.templates").joinpath(name)))
    if not path.is_file():
        available = ", ".join(sorted(SCAFFOLD_FILES))
        raise FileNotFoundError(f"no template named {name!r}; shipped templates: {available}")
    return path


def template_text(name: str) -> str:
    return template_path(name).read_text(encoding="utf-8")


def write_scaffold(root: Path, *, force: bool = False) -> tuple[list[Path], list[Path]]:
    """Write the ``.bellwether/`` scaffold under ``root``.

    Returns ``(written, skipped)``. Existing files are skipped unless ``force`` is set —
    overwriting a repository's policy is not something to do as a side effect of running
    ``init`` a second time.
    """
    written: list[Path] = []
    skipped: list[Path] = []

    for name, destination in SCAFFOLD_FILES.items():
        target = root / destination
        if target.exists() and not force:
            skipped.append(target)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(template_text(name), encoding="utf-8")
        written.append(target)

    for directory in SCAFFOLD_DIRS:
        keep = root / directory / ".gitkeep"
        if keep.exists():
            skipped.append(keep)
            continue
        keep.parent.mkdir(parents=True, exist_ok=True)
        keep.write_text("", encoding="utf-8")
        written.append(keep)

    return written, skipped
