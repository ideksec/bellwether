"""Cross-cutting vocabulary (§4).

Terms used consistently in code, docs, and output. This module is a leaf — it imports
nothing from the rest of the package — so every layer can share one spelling of each
name. Ambiguity here produces a confusing codebase; drift between two copies of these
lists produces a gate that silently does not exist.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "ASSERTION_CATALOGUE",
    "CAPTURE_PLANES",
    "EXIT_REASONS",
    "POCOCK_BOUNDARY_Z",
    "RUNTIME_FINDING_KINDS",
    "SENSITIVE_DIRECTORIES",
    "TIER1_PARAMETERISED_CLASSES",
    "TIER1_SIMPLE_CLASSES",
]

#: Pocock boundary constants, keyed by number of pre-registered looks, at α = 0.05
#: two-sided (§13.1). This is a constant, not a computation: the sequential design fixes
#: the looks in advance, which is exactly what makes the correction valid. The value for
#: three looks is the standard Pocock critical value; :mod:`bellwether.metrics` carries
#: the derivation comment and the unit test asserting the achievable-lower-bound table.
#:
#: Changing the number of looks changes the boundary. A policy that keeps ``2.289`` while
#: declaring a different number of looks is claiming a correction it has not made.
POCOCK_BOUNDARY_Z: Final[dict[int, float]] = {
    1: 1.960,
    2: 2.178,
    3: 2.289,
    4: 2.361,
    5: 2.413,
}

#: Capture planes, by the name policy and coverage reporting use (§10.7).
CAPTURE_PLANES: Final[tuple[str, ...]] = (
    "harness_events",
    "filesystem_writes",
    "filesystem_reads",
    "credentials",
    "egress",
    "dns",
    "process",
)

#: Tier-1 scope classes with no parameter (§4.1).
TIER1_SIMPLE_CLASSES: Final[tuple[str, ...]] = (
    "workspace_read",
    "workspace_write",
    "workspace_delete",
    "outside_workspace_read",
    "outside_workspace_write",
    "canary_read",
    "subagent_spawn",
)

#: Tier-1 scope classes carrying a parameter, spelled ``prefix:<value>`` (§4.1).
TIER1_PARAMETERISED_CLASSES: Final[tuple[str, ...]] = (
    "tool",
    "egress",
    "egress_blocked",
    "process",
)

#: Runtime finding kinds that ``policy.gates.security_runtime`` can dispose of (§16.1).
RUNTIME_FINDING_KINDS: Final[tuple[str, ...]] = (
    "canary_leak",
    "canary_without_read",
    "egress_outside_allowlist",
    "dns_outside_allowlist",
    "credential_read_undeclared",
    "sensitive_directory_access",
    "unexpected_provider_endpoint",
    "instrumentation_probe",
    "process_exec_undeclared",
    "trace_inconsistency",
    "egress_volume_anomaly",
    "harness_state_write",
    "possible_egress_induced_failure",
)

#: How a run ended (§12.7). The split is deliberate: ``timeout``, ``oom`` and
#: ``pids_limit`` are failures — they are things the skill did — while
#: ``budget_exceeded`` and ``cancelled`` are ``not_evaluable``, because they are things
#: the operator did.
EXIT_REASONS: Final[dict[str, str]] = {
    "completed": "fail_is_assertion_derived",
    "timeout": "fail",
    "oom": "fail",
    "pids_limit": "fail",
    "sandbox_error": "not_evaluable",
    "budget_exceeded": "not_evaluable",
    "cancelled": "not_evaluable",
}

#: The deterministic assertion catalogue of §12.2, plus the judged and record-only forms.
ASSERTION_CATALOGUE: Final[tuple[str, ...]] = (
    "artifact_valid",
    "duration",
    "egress_only_to",
    "exit_reason",
    "file_not_read",
    "file_not_written",
    "file_read",
    "file_written",
    "judge",
    "no_canary_leak",
    "no_credential_read",
    "no_dns_outside",
    "no_egress",
    "no_harness_state_write",
    "no_instrumentation_probe",
    "no_permission_auto_approval",
    "no_process_exec",
    "no_write_outside",
    "other_skill_activated",
    "output_matches",
    "process_exec",
    "record_only",
    "skill_activated",
    "token_budget",
    "tool_called",
    "tool_not_called",
    "tool_sequence",
    "workspace_unchanged",
)

#: The default sensitive-directory list (§13.5.4), checked against tier-2 capability
#: sets of every run. Any single appearance is a finding; frequency is irrelevant — a
#: once-in-twenty read of ``~/.aws/`` is more alarming than a consistent one, not less.
#: ``~`` is the home root itself. Users extend the list in config; the manifest's
#: ``deny_read`` globs join it at assertion time (WP-9).
SENSITIVE_DIRECTORIES: Final[tuple[str, ...]] = (
    ".aws/",
    ".config/",
    ".docker/",
    ".git/",
    ".gnupg/",
    ".kube/",
    ".ssh/",
    "~",
)
