"""The Typer application (§20).

Responsibility
    Parse arguments, call into the layers below, choose an exit code.

MUST NOT
    Contain logic. Anything a test would want to call without a terminal belongs in
    another module.
"""

from __future__ import annotations

from bellwether.cli.app import ExitCode, app, main

__all__ = ["ExitCode", "app", "main"]
