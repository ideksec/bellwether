"""Every config setting enforces, refuses, or says it is not built (CLAUDE.md).

"A control the schema accepts must enforce or refuse." `tests/test_control_registry.py` holds
policy gates to that; nothing held `config.yaml` to it, and a runtime probe of which config fields
package code ever reads (spec-notes) found the shipped template full of settings nothing read:
`execution.retry_on_infra_error` and `metrics.bci_weights` (both now wired), `sandbox.backend:
gvisor` (which ran plain Docker — now refused), and two dozen more.

This file fails the build on a config field classified nowhere, and on a registry entry that has
gone stale in either direction — a "not built" setting the code has started to read, or a "read"
setting nothing references.
"""

from __future__ import annotations

import inspect
import re
import typing
from pathlib import Path

import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

from bellwether.cli.app import app
from bellwether.config import load_config, template_path
from bellwether.config.models.config import NOT_BUILT_SETTINGS, Config
from bellwether.errors import ConfigurationError

_SRC = Path(__file__).resolve().parents[1] / "src" / "bellwether"
_CODE = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted(_SRC.rglob("*.py"))
    if "config/models" not in path.as_posix()
)

#: Read by package code on the path a run or `doctor` takes.
READ = {
    "providers.*.type",
    "providers.*.base_url",
    "providers.*.api_key_env",
    "providers.*.models",
    "providers.*.pricing.*.input_usd_per_mtok",
    "providers.*.pricing.*.output_usd_per_mtok",
    "providers.*.pricing.*.cache_read_usd_per_mtok",
    "providers.*.pricing.*.cache_write_usd_per_mtok",
    "harnesses.*.version_pin",
    "sandbox.image",
    "sandbox.memory",
    "sandbox.cpus",
    "sandbox.pids_limit",
    "sandbox.timeout_seconds",
    "sandbox.writable_paths",
    "sandbox.randomize_identifiers",
    "capture.zones.workspace",
    "capture.zones.harness_state",
    "capture.zones.scratch",
    "egress.image",
    "egress.allowlist",
    "egress.per_run_caps.max_requests",
    "egress.per_run_caps.max_request_bytes",
    "dns.image",
    "dns.allowlist",
    "canaries.enabled",
    "metrics.bci_weights.outcome",
    "metrics.bci_weights.trigger",
    "metrics.bci_weights.trajectory",
    "metrics.bci_weights.capability",
    "metrics.bci_weights.output",
    "metrics.trajectory_cluster_threshold",
    "metrics.sensitive_directories",
    "execution.retry_on_infra_error",
    "execution.cache",
    "execution.cache_ttl_days",
    "execution.limits.max_turns",
    "execution.limits.max_tool_calls",
    "execution.limits.max_total_tokens",
}
#: Refused when set to anything but the built behaviour: the §21 enforced settings, the sandbox
#: backend (only Docker is built), and a harness whose declared type is not what would run.
REFUSED_OTHERWISE = {
    "egress.scan_model_api_bodies",
    "egress.deployment",
    "dns.mode",
    "canaries.redact_at_capture",
    "canaries.randomize_markers",
    "sandbox.backend",
    "harnesses.*.type",
}
#: Document headers and single-valued fields: nothing to act on.
FIXED = {"api_version", "kind", "egress.mode"}

#: Access patterns for staleness where ``parent.leaf`` would be ambiguous.
_ACCESS = {
    "harnesses.*.install": r"\.install\b",
    "harnesses.*.tools": r"(?<!bellwether)\.harness\w*\.tools\b|entry\.tools\b",
    "judges": r"\.judges\b",
    "embeddings": r"\.embeddings\b",
    "reporting.html": r"reporting\.html\b",
}


def _model_of(annotation: object) -> tuple[type[BaseModel] | None, bool]:
    """The model a field holds, and whether it sits behind a dict key."""
    if inspect.isclass(annotation) and issubclass(annotation, BaseModel):
        return annotation, False
    args = typing.get_args(annotation)
    if typing.get_origin(annotation) is dict and len(args) == 2:
        sub, _ = _model_of(args[1])
        return (sub, True) if sub is not None else (None, False)
    for arg in args:  # Optional[...], Annotated[...]
        sub, keyed = _model_of(arg)
        if sub is not None:
            return sub, keyed
    return None, False


def _leaves(model: type[BaseModel] = Config, prefix: str = "") -> list[str]:
    paths: list[str] = []
    for name, field in model.model_fields.items():
        path = f"{prefix}.{name}" if prefix else name
        sub, keyed = _model_of(field.annotation)
        if sub is None:
            paths.append(path)
        else:
            paths.extend(_leaves(sub, f"{path}.*" if keyed else path))
    return paths


def _not_built(path: str) -> bool:
    return any(path == key or path.startswith(key + ".") for key in NOT_BUILT_SETTINGS)


def test_every_config_field_is_classified_exactly_once() -> None:
    unclassified, doubled = [], []
    for path in _leaves():
        classes = [
            path in READ,
            path in REFUSED_OTHERWISE,
            path in FIXED,
            _not_built(path),
        ]
        if sum(classes) == 0:
            unclassified.append(path)
        elif sum(classes) > 1:
            doubled.append(path)
    assert not unclassified, (
        f"classify these in READ, REFUSED_OTHERWISE, FIXED or NOT_BUILT: {unclassified}"
    )
    assert not doubled, f"classified twice: {doubled}"
    assert set(_leaves()) >= READ | REFUSED_OTHERWISE | FIXED, "a listed path no longer exists"


def _signature(path: str) -> str:
    if path in _ACCESS:
        return _ACCESS[path]
    parts = [part for part in path.split(".") if part != "*"]
    return r"\b" + r"\.".join(re.escape(part) for part in parts[-2:]) + r"\b"


@pytest.mark.parametrize("path", sorted(NOT_BUILT_SETTINGS))
def test_a_not_built_setting_is_not_read(path: str) -> None:
    """Stale in one direction: someone built it and forgot to take it off the list, so `doctor`
    would tell operators a working setting does nothing."""
    assert not re.search(_signature(path), _CODE), (
        f"{path} is read by package code; remove it from NOT_BUILT_SETTINGS"
    )


@pytest.mark.parametrize("path", sorted(READ))
def test_a_read_setting_is_referenced(path: str) -> None:
    """Stale in the other: a setting classified as read that nothing references any more."""
    leaf = path.rsplit(".", 1)[-1]
    assert re.search(r"\b" + re.escape(leaf) + r"\b", _CODE), f"nothing references {path}"


@pytest.mark.parametrize(
    "config_path",
    [template_path("config.yaml"), *sorted(Path("examples").rglob("config*.yaml"))],
    ids=str,
)
def test_shipped_configs_set_nothing_unbuilt(config_path: Path) -> None:
    """`init` writes the template; the live workflows run the examples. Neither may promise a
    behaviour this build does not have."""
    assert load_config(config_path).not_built_settings() == []


def _write_config(tmp_path: Path, extra: str) -> Path:
    base = template_path("config.yaml").read_text(encoding="utf-8")
    path = tmp_path / "config.yaml"
    path.write_text(base + extra, encoding="utf-8")
    return path


def test_doctor_names_a_not_built_setting_and_why(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    assert CliRunner().invoke(app, ["init", str(root)]).exit_code == 0
    config = root / ".bellwether" / "config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "  retry_on_infra_error:", "  concurrency: 8\n  retry_on_infra_error:"
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["doctor", "--config", str(config), "--json"])
    assert "settings not built in this version" in result.output
    assert "execution.concurrency (runs execute one at a time)" in result.output


def test_a_setting_nested_under_a_not_built_block_is_reported_once(tmp_path: Path) -> None:
    config = load_config(
        _write_config(tmp_path, "\nreporting:\n  sarif: true\n  retention_days: 7\n")
    )
    assert [path for path, _ in config.not_built_settings()] == [
        "reporting.retention_days",
        "reporting.sarif",
    ]


def test_a_non_docker_backend_is_refused(tmp_path: Path) -> None:
    """It used to parse and then run a plain Docker container — the operator asked for gVisor's
    boundary and got runc's, with nothing said."""
    base = template_path("config.yaml").read_text(encoding="utf-8")
    path = tmp_path / "config.yaml"
    path.write_text(base.replace("  backend: docker", "  backend: gvisor"), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not built in this version"):
        load_config(path)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ("  claude-code:\n    type: api-loop\n", "chosen by its name"),
        ("  generic-subprocess:\n    type: generic-subprocess\n", "not built"),
    ],
)
def test_a_harness_type_that_would_not_run_is_refused(
    tmp_path: Path, entry: str, message: str
) -> None:
    base = template_path("config.yaml").read_text(encoding="utf-8")
    start = base.index("harnesses:\n") + len("harnesses:\n")
    end = base.index("\n\n", start)
    path = tmp_path / "config.yaml"
    path.write_text(base[:start] + entry + base[end:], encoding="utf-8")
    with pytest.raises(ConfigurationError, match=message):
        load_config(path)


def test_config_classes_hold_only_what_the_registry_knows() -> None:
    """A registry key must name a real field path, or it silently matches nothing."""
    leaves = set(_leaves())
    for key in NOT_BUILT_SETTINGS:
        assert any(p == key or p.startswith(key + ".") for p in leaves), key
    assert isinstance(Config.model_fields, dict)
