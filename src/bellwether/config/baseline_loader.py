"""Loading ``platform-baseline.yaml`` (§12.6).

Its own module for the same reason policy has one: the baseline is consumed by the
assertion layer and above, and a shared loader module would carry its types everywhere
by transitive import. The boundary stays visible in the file tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bellwether.config.document import (
    PLATFORM_BASELINE_FILE,
    load_yaml_mapping,
    validate_document,
)
from bellwether.config.models.baseline import PlatformBaseline

__all__ = ["load_platform_baseline", "parse_platform_baseline"]


def parse_platform_baseline(
    data: dict[str, Any], source: Path | str = "platform-baseline.yaml"
) -> PlatformBaseline:
    return validate_document(PlatformBaseline, data, source)


def load_platform_baseline(path: Path = PLATFORM_BASELINE_FILE) -> PlatformBaseline:
    return parse_platform_baseline(load_yaml_mapping(path), path)
