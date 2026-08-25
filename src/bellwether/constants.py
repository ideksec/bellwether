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
    "DEFAULT_CAPABILITY_WEIGHT",
    "DEFAULT_CAPABILITY_WEIGHTS",
    "EXIT_REASONS",
    "POCOCK_BOUNDARY_Z",
    "REPORT_LIMITATIONS",
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

#: How a run ended (§12.7), and how that maps to the run outcome. The split is deliberate:
#: ``timeout``, ``oom``, ``pids_limit``, ``harness_error`` and ``sandbox_error`` are
#: failures — things that happened while the skill ran — while ``budget_exceeded`` and
#: ``cancelled`` are ``not_evaluable``, because they are decisions the operator made.
#: ``completed`` defers to the assertion results (``assertion_derived``). This dict is the
#: single source of truth: :mod:`bellwether.assertions.results` derives its failing and
#: not-evaluable sets from it, so the two cannot drift (a test asserts the agreement).
EXIT_REASONS: Final[dict[str, str]] = {
    "completed": "assertion_derived",
    "timeout": "fail",
    "oom": "fail",
    "pids_limit": "fail",
    "harness_error": "fail",
    "sandbox_error": "fail",
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

#: Default risk weights by tier-1 capability class (§13.5.1), keyed by the *base* class —
#: a parameterised class such as ``egress:evil.com`` or ``process:curl`` looks its weight
#: up under ``egress`` / ``process``. Only the **weighted** Jaccard feeds the BCI, because
#: the plain figure is insensitive to exactly the rare high-risk case the metric exists to
#: catch (§13.5.1.1). Overridable in ``policy.yaml``; a class on a manifest ``deny`` list
#: MUST NOT be assignable weight 0 (validated at config load, §16.1). A class absent from
#: this table takes ``DEFAULT_CAPABILITY_WEIGHT`` — the floor, never zero, so an
#: unforeseen class never silently drops out of the risk sum.
DEFAULT_CAPABILITY_WEIGHTS: Final[dict[str, int]] = {
    "canary_read": 10,
    "egress": 10,
    "dns_query": 10,
    "process": 5,
    "outside_workspace_write": 5,
    "outside_workspace_read": 3,
    "harness_state_write": 3,
    "subagent_spawn": 3,
    "workspace_write": 2,
    "workspace_delete": 2,
    "workspace_read": 1,
    "tool": 1,
    #: A blocked egress attempt is not in the §13.5.1.1 table; it is evidence of intent
    #: (surfaced as its own finding), but for the smooth consistency signal it is weighted
    #: like the reach it attempted — recorded here rather than falling to the floor, so the
    #: choice is visible and overridable (see spec-notes §13.5.1).
    "egress_blocked": 10,
}

#: The weight an unlisted tier-1 class receives (§13.5.1). The floor is 1, never 0: a
#: class the table did not foresee still counts, so it cannot vanish from the risk sum.
DEFAULT_CAPABILITY_WEIGHT: Final[int] = 1

#: The calibrated §24 trajectory noise floor: the residual mean pairwise step-sequence
#: distance the instrument itself produces on identical input, measured over the real-container
#: ``benign-stable`` repetition set with all cross-plane events present (WP-19). A skill whose
#: measured dispersion is at or below this MUST be reported as ``at_noise_floor``, never as a
#: precise small number (§13.4) — a distinct-cluster count the instrument produces on identical
#: input is a fabrication. The committed value is the *measurement*, not an aspiration:
#: ``test_noise_floor_docker.py`` re-measures it against real containers (sequentially and under
#: concurrent load) and fails when the committed number no longer matches, the same
#: regenerate-and-diff reflex as the summary schema. Plane-A-only dispersion being exactly zero
#: — the assertion that validates §11.5 epoch anchoring — is asserted in the same test; a
#: nonzero value there means the anchoring is admitting jitter and must be fixed, not recorded.
NOISE_FLOOR_TRAJECTORY: Final[float] = 0.0

#: When the committed noise floor was last measured. Update it together with the value —
#: a floor without its measurement date cannot be judged stale (§17.2, ``noise_floor``).
NOISE_FLOOR_CALIBRATED_AT: Final[str] = "2026-08-25"

#: The §2 honest-limitations footer, in the exact words the spec requires ("These MUST be
#: stated in the README and in the generated report footer"). Every report §17 renders
#: this verbatim and complete — a footer that drops one of these oversells by omission, so
#: :mod:`bellwether.report` reads the whole tuple and never a subset. The wording is the
#: authority; a divergence between this and the README is a bug in the README.
REPORT_LIMITATIONS: Final[tuple[str, ...]] = (
    # The one line carrying the word the language lint bans, quoted from §2 on purpose.
    "Bellwether does not prove a skill is safe. N runs produce a distribution, not a "  # bw-lang-ok: the §2 limitation, stated verbatim
    "proof — a skill clean in 50 observed runs may differ in the 51st, on a different "
    "model version, or in a context Bellwether did not simulate. It is a strong "
    "regression gate and a weak assurance gate: treat its output as evidence, not "
    "attestation.",
    "Bellwether is not a runtime control. It runs in CI, before deployment, and does not "
    "sit in the production request path. It informs production controls; it does not "
    "replace them.",
    "Bellwether does not govern what a user can do. Its security value is concentrated on "
    "third-party and shared skills — supply chain — not on policing an individual's own "
    "local instructions.",
    "Bellwether cannot fully sandbox a determined adversary. The sandbox raises cost and "
    "captures evidence; it is not suitable for detonating known-malicious code without "
    "further isolation.",
    "Measured variance is a lower bound. Repetitions send near-identical prompts in close "
    "succession — the ideal case for provider-side prompt caching — so real-world "
    "variance is very likely higher than what is reported here.",
    "Exfiltration detection has documented holes. Canary matching defeats naive copying, "
    "not independently-encoded chunking, interleaving across runs, or a skill that "
    "describes a secret rather than reproducing it.",
    "Judged scores carry an unmeasured bias term. Judges are blinded to metadata, never "
    "to content: model identity leaks through style, skill activity through content.",
)
