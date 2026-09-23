"""What gets published, pinned (release review, 2026-09).

Three decisions a later edit could quietly undo: the distribution is ``bellwether-skills``
(``bellwether`` on PyPI is an unrelated project); the only console command is ``bellwether``
(``bw`` is the Bitwarden CLI's name); and the copyright line lives in ``NOTICE``, shipped beside
``LICENSE`` — whose ``Copyright [yyyy]`` line is the Apache appendix's template, meant to stay.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PROJECT = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def test_the_distribution_name_is_not_the_taken_one() -> None:
    assert _PROJECT["name"] == "bellwether-skills"


def test_the_only_console_command_is_bellwether() -> None:
    assert _PROJECT["scripts"] == {"bellwether": "bellwether.cli:main"}


def test_the_license_files_that_ship_include_the_copyright_notice() -> None:
    assert _PROJECT["license"] == "Apache-2.0"
    assert set(_PROJECT["license-files"]) == {"LICENSE", "NOTICE"}
    assert "Copyright 2026 ideksec" in (_ROOT / "NOTICE").read_text(encoding="utf-8")
