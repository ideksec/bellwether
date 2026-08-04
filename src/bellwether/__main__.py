"""Allow ``python -m bellwether`` alongside the ``bellwether`` and ``bw`` entry points."""

from __future__ import annotations

from bellwether.cli import main

if __name__ == "__main__":
    main()
