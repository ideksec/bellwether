"""Configuration, policy, manifest and scenario loading (§21, §16.1, §6.2, §7).

Responsibility
    Read and validate the four YAML document types, and render every failure as a
    sentence naming the file, the path within it, and the allowed values.

MUST NOT
    Touch the network. This is the bottom layer of the §8.1 stack; ``.importlinter``
    forbids it importing sockets, HTTP clients, or the Docker SDK.
"""

from __future__ import annotations

from bellwether.config.loader import (
    CONFIG_DIR,
    CONFIG_FILE,
    PLATFORM_BASELINE_FILE,
    POLICY_FILE,
    load_config,
    load_manifest,
    load_policy,
    load_scenarios,
    load_yaml_mapping,
    parse_config,
    parse_manifest,
    parse_policy,
    parse_scenarios,
    resolve_model_id,
)
from bellwether.config.models import (
    API_VERSION,
    AssertionSpec,
    Config,
    Criticality,
    DeclaredScope,
    EnforcedSetting,
    Gates,
    Policy,
    ProfileSpec,
    ProviderConfig,
    Scenario,
    ScenarioSuite,
    Severity,
    SkillManifest,
    Target,
)
from bellwether.config.templates import template_path, write_scaffold

__all__ = [
    "API_VERSION",
    "CONFIG_DIR",
    "CONFIG_FILE",
    "PLATFORM_BASELINE_FILE",
    "POLICY_FILE",
    "AssertionSpec",
    "Config",
    "Criticality",
    "DeclaredScope",
    "EnforcedSetting",
    "Gates",
    "Policy",
    "ProfileSpec",
    "ProviderConfig",
    "Scenario",
    "ScenarioSuite",
    "Severity",
    "SkillManifest",
    "Target",
    "load_config",
    "load_manifest",
    "load_policy",
    "load_scenarios",
    "load_yaml_mapping",
    "parse_config",
    "parse_manifest",
    "parse_policy",
    "parse_scenarios",
    "resolve_model_id",
    "template_path",
    "write_scaffold",
]
